FROM nginx:1.27-alpine

RUN apk add --no-cache openssl \
    && mkdir -p /etc/nginx/certs /usr/share/nginx/app1 /usr/share/nginx/staging \
    && openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
       -keyout /etc/nginx/certs/server.key \
       -out /etc/nginx/certs/server.crt \
       -subj "/CN=app1.lab.local" \
       -addext "subjectAltName=DNS:app1.lab.local,DNS:staging.lab.local"

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY app1.html /usr/share/nginx/app1/index.html
COPY staging.html /usr/share/nginx/staging/index.html

EXPOSE 80 443
