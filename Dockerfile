FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Switch to Vietnam mirrors for faster downloads
RUN sed -i 's/archive.ubuntu.com/vn.archive.ubuntu.com/g' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i 's/security.ubuntu.com/vn.archive.ubuntu.com/g' /etc/apt/sources.list.d/ubuntu.sources

RUN apt-get update && apt-get install -y \
    openssh-server \
    git \
    sudo \
    curl \
    init \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    ssh-keygen -A && \
    echo "PermitRootLogin yes" >> /etc/ssh/sshd_config && \
    echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config && \
    echo 'root:bootstrap' | chpasswd

# Create startup script that works in containers
RUN echo '#!/bin/bash\n\
# Start SSH service\n\
service ssh start\n\
\n\
# Keep container running\n\
tail -f /dev/null' > /start.sh && \
    chmod +x /start.sh

RUN mkdir -p /workspace
WORKDIR /workspace

CMD ["/start.sh"]