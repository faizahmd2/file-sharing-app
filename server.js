require('dotenv').config();

const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');
const cron = require('node-cron');
const rateLimit = require('express-rate-limit');
const { createPresignedPost } = require('@aws-sdk/s3-presigned-post');
const { S3Client, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");
const { v4: uuidv4 } = require('uuid');
const shortid = require('shortid');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
const server = http.createServer(app);

// S3/R2 Client Configuration
const s3Client = new S3Client({
    region: 'auto',
    endpoint: process.env.R2_ENDPOINT,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY,
        secretAccessKey: process.env.R2_SECRET_KEY
    }
});

// Database Configuration
let db, filesCollection, sessionsCollection;

async function connectDB() {
    const client = new MongoClient(process.env.MONGO_URI);
    await client.connect();
    db = client.db(process.env.DB_NAME || 'fileshare');

    filesCollection = db.collection('files');
    sessionsCollection = db.collection('upload_sessions');
    
    // Create indexes
    await filesCollection.createIndex({ uniqueId: 1 });
    await filesCollection.createIndex({ expire: 1 });
    await filesCollection.createIndex({ uploadedAt: 1 });
    await sessionsCollection.createIndex({ sessionId: 1 });
    await sessionsCollection.createIndex({ createdAt: 1 }, { expireAfterSeconds: 3600 }); // 1 hour expiry
}

// Configuration
const CONFIG = {
    MAX_FILE_SIZE: 100 * 1024 * 1024, // 100MB
    DAILY_UPLOAD_LIMIT: 2 * 1024 * 1024 * 1024, // 2GB per unique ID per day
    MAX_FILES_PER_ID: 50,
    MIN_EXPIRY_MINUTES: 5,
    MAX_EXPIRY_MINUTES: 10080, // 7 days
    BUCKET_NAME: process.env.R2_BUCKET,
    CUSTOM_DOMAIN: process.env.R2_CUSTOM_DOMAIN,
    ALLOWED_EXTENSIONS: [
        'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'ico',
        'mp4', 'avi', 'mov', 'wmv', 'mkv', 'webm', 'm4v', 'flv',
        'mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a', 'wma',
        'pdf', 'doc', 'docx', 'txt', 'rtf', 'odt', 'pages',
        'xls', 'xlsx', 'csv', 'ods', 'numbers',
        'ppt', 'pptx', 'odp', 'key',
        'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
        'js', 'html', 'css', 'json', 'xml', 'py', 'java', 'cpp', 'c', 'php', 'rb', 'go', 'rs', 'swift',
        'psd', 'ai', 'sketch', 'fig', 'epub', 'mobi'
    ]
};

// Middleware
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    methods: ['GET', 'POST', 'DELETE', 'PUT'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Token']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const uploadRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // Reduced from 50
    message: { error: 'Too many upload requests, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});

const downloadRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many download requests, please try again later' },
    standardHeaders: true,
    legacyHeaders: false,
});

// Static files
app.use(express.static('public'));

// Security utilities
function generateSecureToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateFileKey(uniqueId, originalName, sessionId) {
    const timestamp = Date.now();
    const randomString = crypto.randomBytes(8).toString('hex');
    const extension = path.extname(originalName);
    const hash = crypto.createHash('sha256').update(`${uniqueId}${sessionId}${timestamp}`).digest('hex').substring(0, 8);
    return `${uniqueId}/${hash}_${timestamp}_${randomString}${extension}`;
}

function validateFileName(fileName) {
    const dangerousPatterns = [
        /\.\./,  // Parent directory traversal
        /[<>:"|?*]/,  // Invalid characters
        /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i,  // Windows reserved names
        /^\./,  // Hidden files starting with dot
        /\s+$/,  // Trailing whitespace
    ];

    if (dangerousPatterns.some(pattern => pattern.test(fileName))) {
        return false;
    }

    const extension = path.extname(fileName).toLowerCase().substring(1);
    return CONFIG.ALLOWED_EXTENSIONS.includes(extension);
}

async function checkDailyUploadLimit(uniqueId, newFileSize) {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);

        const result = await filesCollection.aggregate([
            {
                $match: {
                    uniqueId: uniqueId,
                    uploadedAt: {
                        $gte: today,
                        $lt: tomorrow
                    },
                    status: 'completed'
                }
            },
            {
                $group: {
                    _id: null,
                    totalSize: { $sum: "$size" },
                    fileCount: { $sum: 1 }
                }
            }
        ]).toArray();

        const currentUsage = result[0] || { totalSize: 0, fileCount: 0 };
        const newTotalSize = currentUsage.totalSize + newFileSize;
        const newFileCount = currentUsage.fileCount + 1;

        return {
            allowed: newTotalSize <= CONFIG.DAILY_UPLOAD_LIMIT && newFileCount <= CONFIG.MAX_FILES_PER_ID,
            currentUsage: currentUsage.totalSize,
            remainingQuota: CONFIG.DAILY_UPLOAD_LIMIT - currentUsage.totalSize,
            fileCount: currentUsage.fileCount
        };
    } catch (error) {
        console.error('Error checking daily upload limit:', error);
        return { allowed: false, error: 'Unable to verify upload limits' };
    }
}

// Middleware to validate session token
async function validateSession(req, res, next) {
    const sessionToken = req.headers['x-session-token'];
    if (!sessionToken) {
        return res.status(401).json({ error: 'Session token required' });
    }

    try {
        const session = await sessionsCollection.findOne({ 
            sessionToken,
            status: 'pending',
            expiresAt: { $gt: new Date() }
        });

        if (!session) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        req.session = session;
        next();
    } catch (error) {
        console.error('Session validation error:', error);
        res.status(500).json({ error: 'Session validation failed' });
    }
}

// Routes
app.get('/dashboard', (req, res) => {
    if (req.query.uniqueId) {
        res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
    } else {
        const editorId = shortid.generate();
        res.redirect(`/dashboard?uniqueId=${editorId}`);
    }
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        config: {
            maxFileSize: CONFIG.MAX_FILE_SIZE,
            dailyLimit: CONFIG.DAILY_UPLOAD_LIMIT,
            maxFiles: CONFIG.MAX_FILES_PER_ID
        }
    });
});

// Initialize upload session - REQUIRED before getting credentials
app.post('/api/init-upload', uploadRateLimit, async (req, res) => {
    try {
        const { uniqueId, fileName, fileSize, expiryMinutes, clientFingerprint } = req.body;

        // Basic validation
        if (!uniqueId || !fileName || !fileSize || !expiryMinutes || !clientFingerprint) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (fileSize > CONFIG.MAX_FILE_SIZE) {
            return res.status(400).json({ 
                error: `File size exceeds maximum allowed size of ${Math.round(CONFIG.MAX_FILE_SIZE / 1024 / 1024)}MB` 
            });
        }

        if (!validateFileName(fileName)) {
            return res.status(400).json({ error: 'Invalid file name or file type not allowed' });
        }

        // Check daily limits
        const limitCheck = await checkDailyUploadLimit(uniqueId, fileSize);
        if (!limitCheck.allowed) {
            return res.status(429).json({ 
                error: limitCheck.error || 'Daily upload limit exceeded',
                quota: {
                    used: limitCheck.currentUsage,
                    remaining: limitCheck.remainingQuota,
                    fileCount: limitCheck.fileCount
                }
            });
        }

        // Create upload session
        const sessionToken = generateSecureToken();
        const sessionId = uuidv4();
        const fileKey = generateFileKey(uniqueId, fileName, sessionId);

        const uploadSession = {
            sessionId,
            sessionToken,
            uniqueId,
            fileKey,
            fileName,
            fileSize,
            expiryMinutes,
            clientFingerprint,
            status: 'pending',
            createdAt: new Date(),
            expiresAt: new Date(Date.now() + 3600000), // 1 hour
            uploadStarted: false,
            uploadCompleted: false
        };

        await sessionsCollection.insertOne(uploadSession);

        res.json({
            sessionToken,
            sessionId,
            fileKey,
            expiresAt: uploadSession.expiresAt
        });

    } catch (error) {
        console.error('Error initializing upload:', error);
        res.status(500).json({ error: 'Failed to initialize upload' });
    }
});

// Get upload credentials - requires valid session
app.post('/api/upload-credentials', validateSession, async (req, res) => {
    try {
        const session = req.session;
        
        // Prevent duplicate credential requests
        if (session.uploadStarted) {
            return res.status(400).json({ error: 'Upload already started for this session' });
        }

        // Generate presigned POST
        const presignedPost = await createPresignedPost(s3Client, {
            Bucket: CONFIG.BUCKET_NAME,
            Key: session.fileKey,
            Fields: {
                'Content-Type': req.body.contentType || 'application/octet-stream',
            },
            Conditions: [
                ['content-length-range', session.fileSize - 1000, session.fileSize + 1000], // Allow small variance
                ['eq', '$Content-Type', req.body.contentType || 'application/octet-stream'],
            ],
            Expires: 1800, // 30 minutes
        });

        // Use custom domain if configured
        if (CONFIG.CUSTOM_DOMAIN) {
            presignedPost.url = CONFIG.CUSTOM_DOMAIN;
        }

        // Mark session as started
        await sessionsCollection.updateOne(
            { sessionId: session.sessionId },
            { 
                $set: {
                    uploadStarted: true,
                    contentType: req.body.contentType || 'application/octet-stream'
                }
            }
        );

        res.json({
            uploadUrl: presignedPost.url,
            fields: presignedPost.fields,
            fileKey: session.fileKey
        });

    } catch (error) {
        console.error('Error generating upload credentials:', error);
        res.status(500).json({ error: 'Failed to generate upload credentials' });
    }
});

// Confirm upload completion - requires valid session
app.post('/api/upload-complete', validateSession, async (req, res) => {
    try {
        const session = req.session;

        if (!session.uploadStarted) {
            return res.status(400).json({ error: 'Upload not started' });
        }

        if (session.uploadCompleted) {
            return res.status(400).json({ error: 'Upload already completed' });
        }

        // Store file metadata
        const fileMetadata = {
            uniqueId: session.uniqueId,
            fileKey: session.fileKey,
            originalName: session.fileName,
            size: session.fileSize,
            contentType: session.contentType,
            expiryMinutes: session.expiryMinutes,
            expire: new Date(Date.now() + session.expiryMinutes * 60 * 1000),
            uploadedAt: new Date(),
            status: 'completed',
            sessionId: session.sessionId
        };

        await filesCollection.insertOne(fileMetadata);

        // Mark session as completed
        await sessionsCollection.updateOne(
            { sessionId: session.sessionId },
            { 
                $set: { 
                    uploadCompleted: true,
                    status: 'completed',
                    completedAt: new Date()
                }
            }
        );

        res.json({ success: true, message: 'Upload confirmed successfully' });

    } catch (error) {
        console.error('Error confirming upload:', error);
        res.status(500).json({ error: 'Failed to confirm upload' });
    }
});

// List files for a unique ID
app.get('/api/files', async (req, res) => {
    try {
        const { uniqueId } = req.query;

        if (!uniqueId) {
            return res.status(400).json({ error: 'uniqueId is required' });
        }

        const files = await filesCollection.find(
            {
                uniqueId,
                expire: { $gt: new Date() },
                status: 'completed'
            },
            {
                projection: {
                    uniqueId: 1,
                    fileKey: 1,
                    expire: 1,
                    originalName: 1,
                    size: 1,
                    uploadedAt: 1
                }
            }
        ).sort({ uploadedAt: -1 }).toArray();
        
        const limitCheck = await checkDailyUploadLimit(uniqueId, 0);

        res.json({
            files,
            disableUpload: !limitCheck.allowed,
            quota: {
                used: limitCheck.currentUsage || 0,
                limit: CONFIG.DAILY_UPLOAD_LIMIT,
                remaining: limitCheck.remainingQuota || CONFIG.DAILY_UPLOAD_LIMIT,
                fileCount: limitCheck.fileCount || 0,
                maxFiles: CONFIG.MAX_FILES_PER_ID
            }
        });

    } catch (error) {
        console.error('Error listing files:', error);
        res.status(500).json({ error: 'Failed to retrieve files' });
    }
});

// Generate download URL
app.get('/api/download/:uniqueId/:fileKey', downloadRateLimit, async (req, res) => {
    try {
        const { uniqueId, fileKey } = req.params;

        const file = await filesCollection.findOne({
            uniqueId,
            fileKey,
            expire: { $gt: new Date() },
            status: 'completed'
        });

        if (!file) {
            return res.status(404).json({ error: 'File not found or expired' });
        }

        const command = new GetObjectCommand({
            Bucket: CONFIG.BUCKET_NAME,
            Key: fileKey,
            ResponseContentDisposition: `attachment; filename="${file.originalName}"`,
        });

        const downloadUrl = await getSignedUrl(s3Client, command, { expiresIn: 3600 });

        res.json({ downloadUrl });

    } catch (error) {
        console.error('Error generating download URL:', error);
        res.status(500).json({ error: 'Failed to generate download URL' });
    }
});

// Delete file
app.delete('/api/files/:uniqueId/:fileKey', async (req, res) => {
    try {
        const { uniqueId, fileKey } = req.params;

        const file = await filesCollection.findOne({
            uniqueId,
            fileKey,
            status: 'completed'
        });

        if (!file) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Delete from R2
        await s3Client.send(new DeleteObjectCommand({ 
            Bucket: CONFIG.BUCKET_NAME, 
            Key: fileKey 
        }));

        // Delete metadata from database
        await filesCollection.deleteOne({ uniqueId, fileKey });

        res.json({ success: true, message: 'File deleted successfully' });

    } catch (error) {
        console.error('Error deleting file:', error);
        res.status(500).json({ error: 'Failed to delete file' });
    }
});

// Get upload statistics
app.get('/api/stats/:uniqueId', async (req, res) => {
    try {
        const { uniqueId } = req.params;
        const limitCheck = await checkDailyUploadLimit(uniqueId, 0);

        res.json({
            quota: {
                used: limitCheck.currentUsage || 0,
                limit: CONFIG.DAILY_UPLOAD_LIMIT,
                remaining: limitCheck.remainingQuota || CONFIG.DAILY_UPLOAD_LIMIT,
                fileCount: limitCheck.fileCount || 0,
                maxFiles: CONFIG.MAX_FILES_PER_ID,
                usagePercentage: Math.round(((limitCheck.currentUsage || 0) / CONFIG.DAILY_UPLOAD_LIMIT) * 100)
            },
            config: {
                maxFileSize: CONFIG.MAX_FILE_SIZE,
                allowedExtensions: CONFIG.ALLOWED_EXTENSIONS,
                minExpiry: CONFIG.MIN_EXPIRY_MINUTES,
                maxExpiry: CONFIG.MAX_EXPIRY_MINUTES
            }
        });

    } catch (error) {
        console.error('Error getting stats:', error);
        res.status(500).json({ error: 'Failed to retrieve statistics' });
    }
});

app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

// Cleanup expired files and sessions
async function cleanupExpiredFiles() {
    try {
        console.log('Starting cleanup...');
        
        // Cleanup expired files
        const expiredFiles = await filesCollection.find({
            expire: { $lt: new Date() }
        }).toArray();
        
        for (const file of expiredFiles) {
            try {
                await s3Client.send(new DeleteObjectCommand({ 
                    Bucket: CONFIG.BUCKET_NAME, 
                    Key: file.fileKey 
                }));
                await filesCollection.deleteOne({ _id: file._id });
                console.log(`Deleted expired file: ${file.fileKey}`);
            } catch (error) {
                console.error(`Error deleting expired file ${file.fileKey}:`, error);
            }
        }

        // Cleanup abandoned sessions (older than 1 hour without completion)
        await sessionsCollection.deleteMany({
            $or: [
                { expiresAt: { $lt: new Date() } },
                { 
                    createdAt: { $lt: new Date(Date.now() - 3600000) },
                    uploadCompleted: { $ne: true }
                }
            ]
        });
        
        console.log(`Cleanup completed. Processed ${expiredFiles.length} expired files.`);
    } catch (error) {
        console.error('Error during cleanup:', error);
    }
}

// Schedule cleanup every hour
cron.schedule('0 * * * *', cleanupExpiredFiles);

// Error handling
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
const PORT = process.env.PORT || 5832;

async function startServer() {
    try {
        await connectDB();
        console.log('Connected to MongoDB');
        
        server.listen(PORT, () => {
            console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`Server running on port ${PORT}`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('Process terminated');
        process.exit(0);
    });
});

process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    server.close(() => {
        console.log('Process terminated');
        process.exit(0);
    });
});

startServer();

module.exports = app;