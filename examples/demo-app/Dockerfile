# demo-app — deliberately vulnerable. See README.md. Never deploy.
FROM node:latest

WORKDIR /app

# ADD of a remote URL — no checksum, fetched at build time.
ADD https://example.com/entrypoint.sh /app/entrypoint.sh

COPY . .
RUN npm install

# No USER directive — the app runs as root.
EXPOSE 3000
CMD ["node", "server.js"]
