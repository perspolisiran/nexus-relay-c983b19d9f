FROM node:22-alpine
WORKDIR /app
COPY package.json .
COPY server.js .
EXPOSE 443
CMD ["npm", "start"]