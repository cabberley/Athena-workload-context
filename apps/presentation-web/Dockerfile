# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM node:24.7.0-bookworm-slim@sha256:0104d9447ea3ddf7373643be7f9915fc7b7c896e41d0d33229338e457217cd78 AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --fund=false

COPY index.html tsconfig.json tsconfig.app.json tsconfig.node.json vite.config.ts vitest.config.ts ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29.1-alpine3.22-slim@sha256:ba47582e1ad3ad1df0c12a21bf464770c5b995e5f06db4aabead4ab1ae2858c4

COPY --chown=101:101 nginx.conf /etc/nginx/nginx.conf
COPY --from=build --chown=101:101 /app/dist /usr/share/nginx/html
COPY --chown=101:101 json-not-found.json /usr/share/nginx/html/json-not-found.json

USER 101:101
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --output-document=- http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]