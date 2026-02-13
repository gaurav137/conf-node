#!/usr/bin/env bash
set -euo pipefail

# Test script for attestation-client on Azure CVM
# Usage: ./scripts/aks/test-attestation-client.sh <user@host> [ssh-key]

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <user@host> [ssh-key]" >&2
    exit 1
fi

VM_HOST="$1"
SSH_KEY="${2:-~/.ssh/id_rsa}"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o ConnectTimeout=10"

BINARY="bin/attestation-client"
REMOTE_BIN="/tmp/attestation-client"
REMOTE_DIR="/tmp"
LOCAL_OUT="tmp/attestation-output"

ARTIFACTS=(tpm_quote.bin hcl_report.bin snp_report.bin aik_cert.der)

echo "=== Attestation Client Test ==="
echo "Target: ${VM_HOST}"
echo ""

# 1. Build
echo "--- Building attestation-client ---"
make attestation-client
echo ""

# 2. Copy binary to CVM
echo "--- Uploading binary ---"
scp ${SSH_OPTS} "${BINARY}" "${VM_HOST}:${REMOTE_BIN}"
echo ""

# 3. Run on CVM
echo "--- Running attestation-client ---"
ssh ${SSH_OPTS} "${VM_HOST}" "sudo ${REMOTE_BIN}"
echo ""

# 4. Copy artifacts back
echo "--- Downloading artifacts ---"
mkdir -p "${LOCAL_OUT}"
for f in "${ARTIFACTS[@]}"; do
    scp ${SSH_OPTS} "${VM_HOST}:${REMOTE_DIR}/${f}" "${LOCAL_OUT}/${f}" 2>/dev/null && \
        echo "  ${f} -> ${LOCAL_OUT}/${f}" || \
        echo "  ${f} (not found, skipping)"
done
echo ""

# 5. Summary
echo "--- Artifacts ---"
ls -lh "${LOCAL_OUT}/"
echo ""
echo "Done."
