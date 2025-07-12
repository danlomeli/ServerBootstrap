#!/bin/bash

# Script 3: Install Docker, curl, and make
# Installs essential development tools

set -e

echo "=== Installing Docker, curl, and make ==="
echo "This script will install Docker, curl, and make using apt-get."
echo

# Check if we're running as the correct user (not root)
if [ "$EUID" -eq 0 ]; then
    echo "Error: This script should NOT be run as root."
    echo "Please run this script as your regular sudo user."
    exit 1
fi

# Update package list
echo "Updating package list..."
sudo apt-get update

# Install basic tools first
echo "Installing curl and make..."
sudo apt-get install -y curl make

# Install prerequisites for Docker
echo "Installing Docker prerequisites..."
sudo apt-get install -y \
    ca-certificates \
    gnupg \
    lsb-release \
    git-lfs

# Add Docker's official GPG key
echo "Adding Docker GPG key..."
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo "Adding Docker repository..."
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package list with Docker repository
echo "Updating package list with Docker repository..."
sudo apt-get update

# Install Docker Engine
echo "Installing Docker Engine..."
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add current user to docker group
echo "Adding user $(whoami) to docker group..."
sudo usermod -aG docker $(whoami)

# Start and enable Docker service
echo "Starting Docker service..."
if [ -f /etc/init.d/docker ]; then
    sudo /etc/init.d/docker start
else
    echo "Warning: Could not find Docker init script. Trying alternative methods..."
    sudo service docker start 2>/dev/null || echo "Could not start Docker service automatically"
fi

# Verify installations
echo
echo "=== Installation Verification ==="

echo "Checking curl version:"
curl --version | head -n 1

echo "Checking make version:"
make --version | head -n 1

echo "Checking Docker version:"
docker --version

echo "Checking Docker Compose version:"
docker compose version

echo
echo "=== Installation Complete ==="
echo "The following packages have been installed:"
echo "✓ curl"
echo "✓ make"
echo "✓ Docker Engine"
echo "✓ Docker Compose"
echo
echo "IMPORTANT: You have been added to the docker group."
echo "You need to log out and log back in for the group changes to take effect."
echo "After logging back in, you can run 'docker run hello-world' to test Docker."
echo
echo "To log out and back in via SSH:"
echo "1. Type 'exit' to close this session"
echo "2. SSH back in: ssh $(whoami)@$(hostname -I | awk '{print $1}')"
echo "3. Test Docker: docker run hello-world"
echo
read -p "Press Enter to finish..."