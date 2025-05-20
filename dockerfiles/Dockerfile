FROM ubuntu:22.04

# Install necessary packages, including iproute2
RUN apt-get update && \
    apt-get install -y iproute2 iputils-ping dnsutils curl wireguard tcpdump openresolv openssh-client && \
    rm -rf /var/lib/apt/lists/*

