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

FROM caddy:2-alpine@sha256:6aeddd44c3078b0f9a35206472a11420648a79c184603ef95957d0a20044cb2b
COPY --from=builder /app/build /srv
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 3000
