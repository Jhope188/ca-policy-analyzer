
# Build Stage
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Optional: eigene Entra App Registration Client ID
ARG NEXT_PUBLIC_MSAL_CLIENT_ID
ENV NEXT_PUBLIC_MSAL_CLIENT_ID=$NEXT_PUBLIC_MSAL_CLIENT_ID

RUN npm run build


# Runtime Stage
FROM nginx:1.30-alpine

COPY --from=builder /app/out /usr/share/nginx/html

COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]