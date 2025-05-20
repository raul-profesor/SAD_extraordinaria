FROM ubuntu:latest

# Install Nginx
RUN apt-get update && \
    apt-get install -y nginx && \
    rm -rf /var/lib/apt/lists/*

# Copy a sample webpage
COPY index.html /var/www/html/

# Expose port 80
EXPOSE 80
