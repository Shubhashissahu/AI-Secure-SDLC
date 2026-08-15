# Build stage
FROM node:20-alpine as builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build production bundle
RUN npm run build

# Production stage - serve with nginx
FROM nginx:1.25-alpine

# Copy nginx config
COPY <<EOF /etc/nginx/conf.d/default.conf
server {
  listen 5173;
  root /usr/share/nginx/html;
  index index.html;
  
  location / {
    try_files \$uri /index.html;
  }
  
  location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
  }
}
EOF

# Copy built app from builder
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5173/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
