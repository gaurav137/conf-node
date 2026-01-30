#!/bin/bash
set -e

# Teardown script for kubelet-proxy kind cluster
CLUSTER_NAME="${CLUSTER_NAME:-kubelet-proxy-test}"
SIGNING_SERVER_CONTAINER="local-signing-server"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo "Deleting kind cluster: $CLUSTER_NAME"
kind delete cluster --name "$CLUSTER_NAME" 2>/dev/null || true

echo "Stopping local-signing-server container..."
docker stop "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true
docker rm "$SIGNING_SERVER_CONTAINER" 2>/dev/null || true

echo "Cleaning up temporary files..."
rm -rf "$PROJECT_ROOT/tmp"
rm -rf /tmp/kubelet-proxy-logs

echo "Cleanup complete!"
