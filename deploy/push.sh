#!/bin/sh
# From a dev machine: ship the committed tree to the VM and rebuild. Usage: sh deploy/push.sh user@host [services]
set -e
TARGET="$1"; shift
git archive --format=tar.gz -o /tmp/sewasetu-deploy.tgz HEAD
scp -q -i ~/.ssh/sewasetu_vm /tmp/sewasetu-deploy.tgz "$TARGET":~/deploy.tgz
ssh -i ~/.ssh/sewasetu_vm "$TARGET" "cd sewasetu && tar xzf ~/deploy.tgz && docker compose up -d --build $*"
