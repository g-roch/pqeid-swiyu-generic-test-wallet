FROM node:24-alpine AS build
RUN apk add --no-cache openjdk21-jre-headless
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run generate:apis && npm run build

FROM nginx:alpine
COPY --from=build /app/dist/test-wallet-frontend/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
