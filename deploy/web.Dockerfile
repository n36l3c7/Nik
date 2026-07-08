# CSAP web image — build the static SPA, then serve it with nginx (which also
# reverse-proxies /api to the backend container).
#
# Build context is the REPOSITORY ROOT (see docker-compose.yml), so this file
# can see package.json, src/, index.html, etc.

# ---- Stage 1: build the static bundle ----
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

# ---- Stage 2: serve with nginx ----
FROM nginx:alpine
# Replace the default server block with ours (static + /api reverse proxy).
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
