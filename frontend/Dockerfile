# ── CloudGuard Frontend — Dockerfile ──────────────────────────────────────────
# Cloud Computing: multi-stage build — build Node app, serve with Nginx.

# Stage 1: Build the React app
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --silent
COPY . .
# In Docker, all traffic goes through Nginx on port 80 (not directly to backend:5001)
ARG REACT_APP_API_URL=http://localhost
ENV REACT_APP_API_URL=$REACT_APP_API_URL
RUN npm run build

# Stage 2: Serve the static build with Nginx
FROM nginx:alpine

# Copy the React build output
COPY --from=builder /app/build /usr/share/nginx/html

# Nginx config for SPA routing (all paths → index.html)
COPY nginx-spa.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
