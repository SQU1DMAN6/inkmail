#!/usr/bin/env bash

set -euo pipefail

REMOTE_HOST="129.150.63.22"
REMOTE_DIR="/home/inkdrop-machine/inkmail"

echo "==> Deploying InkMail to Daddy: ${REMOTE_HOST}"

ssh "root@${REMOTE_HOST}" 'bash -s' <<EOF
set -euo pipefail

cd "${REMOTE_DIR}"

echo "==> Pulling latest source"
git pull

echo "==> Cleaning previous build"
make clean

echo "==> Building InkMail"
make build

cd build

echo "==> Installing InkMail"
yes n | ./install.sh

echo "==> InkMail deployment complete"
EOF

echo "==> Deployment finished successfully."
