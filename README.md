# Nginx Cheat Sheet

## Installation
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install nginx

# CentOS/RHEL
sudo yum install nginx
# or
sudo dnf install nginx

# From source
wget http://nginx.org/download/nginx-1.24.0.tar.gz
tar -xzf nginx-1.24.0.tar.gz
cd nginx-1.24.0
./configure --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx
make && sudo make install

# Docker
docker run -d -p 80:80 --name nginx nginx:alpine
```

## Basic Configuration
```nginx
# /etc/nginx/nginx.conf
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    gzip on;
    gzip_comp_level 6;
    gzip_min_length 1000;
    gzip_types text/plain text/css application/json application/javascript;
    
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

## Virtual Hosts
```nginx
# /etc/nginx/sites-available/myapp.com
server {
    listen 80;
    server_name myapp.com www.myapp.com;
    root /var/www/myapp;
    index index.html index.htm index.php;
    
    access_log /var/log/nginx/myapp.access.log;
    error_log /var/log/nginx/myapp.error.log;
    
    location / {
        try_files $uri $uri/ =404;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
    
    location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

## SSL/TLS Configuration
```nginx
server {
    listen 80;
    server_name myapp.com www.myapp.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name myapp.com www.myapp.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    location / {
        root /var/www/myapp;
        try_files $uri $uri/ =404;
    }
}
```

## Reverse Proxy
```nginx
upstream backend {
    least_conn;
    server 192.168.1.10:8000 weight=3;
    server 192.168.1.11:8000 weight=2;
    server 192.168.1.12:8000 backup;
}

server {
    listen 80;
    server_name api.myapp.com;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 30s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }
    
    location /api/ {
        proxy_pass http://backend/api/;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
```

## Load Balancing
```nginx
# Round Robin (default)
upstream app_servers {
    server app1.example.com;
    server app2.example.com;
    server app3.example.com;
}

# Least Connections
upstream app_servers {
    least_conn;
    server app1.example.com;
    server app2.example.com;
}

# IP Hash
upstream app_servers {
    ip_hash;
    server app1.example.com;
    server app2.example.com;
}

# Weighted
upstream app_servers {
    server app1.example.com weight=3;
    server app2.example.com weight=2;
    server app3.example.com weight=1;
}

# Health checks (Nginx Plus)
upstream app_servers {
    server app1.example.com max_fails=3 fail_timeout=30s;
    server app2.example.com max_fails=3 fail_timeout=30s;
}
```

## Security Configuration
```nginx
# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "no-referrer-when-downgrade" always;
add_header Content-Security-Policy "default-src 'self'" always;

# Hide server tokens
server_tokens off;

# Rate limiting
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

server {
    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend;
    }
    
    location /login {
        limit_req zone=login burst=5;
        proxy_pass http://backend;
    }
}

# Block bad bots
map $http_user_agent $bad_bot {
    default 0;
    ~*malicious 1;
    ~*bot 1;
    ~*crawler 1;
}

server {
    if ($bad_bot) {
        return 444;
    }
}
```

## Caching
```nginx
# Proxy cache
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=10g 
                 inactive=60m use_temp_path=off;

server {
    location / {
        proxy_cache my_cache;
        proxy_cache_revalidate on;
        proxy_cache_min_uses 3;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_background_update on;
        proxy_cache_lock on;
        
        proxy_pass http://backend;
    }
}

# Static file caching
location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
    access_log off;
}

location ~* \.(html|htm)$ {
    expires 1h;
    add_header Cache-Control "public";
}
```

## Performance Tuning
```nginx
# Worker optimization
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    # Connection optimization
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 15;
    keepalive_requests 100;
    
    # Buffer optimization
    client_max_body_size 64m;
    client_body_buffer_size 128k;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    output_buffers 1 32k;
    postpone_output 1460;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 10240;
    gzip_proxied expired no-cache no-store private must-revalidate max-age=0;
    gzip_types text/plain text/css text/xml text/javascript application/javascript;
}
```

## Commands
```bash
# Start/stop/reload
sudo systemctl start nginx
sudo systemctl stop nginx
sudo systemctl reload nginx
sudo systemctl restart nginx
sudo systemctl enable nginx

# Test configuration
sudo nginx -t
sudo nginx -T  # Test and dump

# Reload gracefully
sudo nginx -s reload

# View processes
ps aux | grep nginx

# Check listening ports
sudo netstat -tulnp | grep nginx

# Check logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Check configuration
nginx -V  # Show compile options
nginx -v  # Show version
```

## Monitoring and Logs
```nginx
# Custom log format
log_format combined_realip '$remote_addr - $remote_user [$time_local] '
                          '"$request" $status $body_bytes_sent '
                          '"$http_referer" "$http_user_agent" '
                          'rt=$request_time uct="$upstream_connect_time" '
                          'uht="$upstream_header_time" urt="$upstream_response_time"';

# Status module (requires compilation)
location /nginx_status {
    stub_status on;
    access_log off;
    allow 127.0.0.1;
    allow 192.168.1.0/24;
    deny all;
}

# Real-time logs
access_log /var/log/nginx/access.log combined_realip;
error_log /var/log/nginx/error.log warn;
```

## Official Links
- [Nginx Documentation](http://nginx.org/en/docs/)
- [Configuration Examples](https://www.nginx.com/resources/wiki/start/)
- [Security Guide](https://nginx.org/en/docs/http/securing_nginx.html)