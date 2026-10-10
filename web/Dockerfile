# UI-008a: the SvelteKit app builds to a static SPA (adapter-static). The
# dev/preview container serves those static assets with Caddy and reverse-proxies
# /api/* to the FastAPI BFF (aptl-web-api). No Node server, no control-plane
# token, no SSR — the shipped delivery contract is `aptl web serve`.
FROM node:26-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1 AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

FROM caddy:2-alpine@sha256:881bbc60f9986d5ab8e7cfd6cf7e4ef3c9c0439fef2429d035d065577882f028
# Apply published Alpine fixes the pinned base predates (zlib 1.3.2-r1 for
# CVE-2026-85091), as operator-access-proxy does.
RUN apk upgrade --no-cache
COPY --from=builder /app/build /srv
COPY Caddyfile /etc/caddy/Caddyfile

# Run unprivileged (issue #1193): Caddy listens on unprivileged port 3000 and
# only needs its own state directories writable.
RUN addgroup -S -g 10001 caddy \
    && adduser -S -D -H -u 10001 -G caddy caddy \
    && chown -R caddy:caddy /data /config
USER 10001:10001

EXPOSE 3000
