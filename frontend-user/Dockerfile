FROM node:20-alpine AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ARG VITE_BACKEND_URL
ARG VITE_WS_URL
ENV VITE_BACKEND_URL=${VITE_BACKEND_URL}
ENV VITE_WS_URL=${VITE_WS_URL}

RUN npm run build

# Production stage with nginx
FROM nginx:alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
