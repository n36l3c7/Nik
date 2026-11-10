# Nik web image — build the static SPA, then serve it with nginx (which also
# reverse-proxies /api to the backend container).

# ---- Stage 1: build the static bundle ----
FROM docker.io/library/node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build

# ---- Stage 2: serve with nginx ----
FROM docker.io/library/nginx:alpine
# openssl backs the entrypoint hook that self-signs a TLS certificate when the
# operator has not mounted one (see nginx/gen-selfsigned.sh).
RUN apk add --no-cache openssl
# Replace the default server block with ours (static + /api reverse proxy).
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY nginx/gen-selfsigned.sh /docker-entrypoint.d/15-gen-selfsigned.sh
RUN chmod +x /docker-entrypoint.d/15-gen-selfsigned.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
