#!/bin/sh
# Run once on a fresh Ubuntu VM:  curl -fsSL <raw url> | sh   (or copy and run)
set -e
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
# small VMs: 2 GB swap so postgres + the build never run out of memory
if [ ! -f /swapfile ]; then
  sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi
echo "Docker installed. Log out and back in, then run deploy/up.sh in the repo."
