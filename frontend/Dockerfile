# Frontend image: static production build served by nginx.
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
# `npm ci` can skip platform-specific optional bindings when the lockfile was
# generated on another OS (npm/cli#4828). `npm install` resolves the binding
# for the build platform from the same lockfile.
RUN npm install --no-audit --no-fund

COPY . .

# The browser talks to nginx on the same origin; nginx proxies /api/ to the
# backend service. This avoids CORS entirely for the bundled deployment.
ARG VITE_API_BASE_URL=/api
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN npm run build

FROM nginx:1.27-alpine

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD wget -q -O - http://127.0.0.1/ >/dev/null 2>&1 || exit 1
