# Nik web image — build the static SPA, then serve it with nginx (which also
# reverse-proxies /api to the backend container).

# ---- Stage 1: build the static bundle ----
FROM docker.io/library/node:26-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build
# The security headers nginx sends, from the same definition `vite preview` uses.
RUN node security-headers.js /app/nginx-headers

# ---- Stage 2: serve with nginx ----
FROM docker.io/library/nginx:1.31-alpine
# openssl backs the entrypoint hook that self-signs a TLS certificate when the
# operator has not mounted one (see nginx/gen-selfsigned.sh).
RUN apk add --no-cache openssl
# Replace the default server block with ours (static + /api reverse proxy).
COPY nginx/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/nginx-headers/ /etc/nginx/
COPY nginx/https-redirect.sh /docker-entrypoint.d/12-https-redirect.sh
COPY nginx/gen-selfsigned.sh /docker-entrypoint.d/15-gen-selfsigned.sh
RUN chmod +x /docker-entrypoint.d/12-https-redirect.sh /docker-entrypoint.d/15-gen-selfsigned.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80 443
