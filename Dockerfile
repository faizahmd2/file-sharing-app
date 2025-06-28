FROM node:18-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --only=production && npm cache clean --force

COPY --chown=node:node . .

RUN mkdir -p public && chown node:node public

USER node

EXPOSE 5832

CMD ["node", "server.js"]
