#!/bin/bash
#
# Deploy attestation-cli to AKS Flex Node VM
#
# This script builds and copies the attestation-cli binary to the Azure VM
# that was previously set up using deploy-cluster.sh and deploy-flex-node-vm.sh.
# The binary can then be run locally from within the VM.
#
# Usage:
#   ./deploy-attestation-cli.sh [options]
#
# Options:
#   --help, -h     Show this help message
#
# Prerequisites:
#   - deploy-cluster.sh must have been run successfully
#   - deploy-flex-node-vm.sh must have been run successfully
#   - Go must be installed for building the binary
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
GENERATED_DIR="$SCRIPT_DIR/generated"

# Show help
show_help() {
    echo "Usage: ./deploy-attestation-cli.sh [options]"
    echo ""
    echo "Deploy attestation-cli binary to the AKS Flex Node VM."
    echo ""
    echo "Options:"
    echo "  --help, -h     Show this help message"
    echo ""
    echo "Prerequisites:"
    echo "  - deploy-cluster.sh must have been run successfully"
    echo "  - deploy-flex-node-vm.sh must have been run successfully"
    echo "  - Go must be installed for building the binary"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Get resource names from currently logged in user
get_resource_info() {
    log_info "Getting resource information from Azure..."

    # Get the currently logged in user's UPN
    CURRENT_USER_UPN=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null) || {
        log_error "Failed to get current user. Make sure you are logged in with 'az login'"
        exit 1
    }

    # Extract username from UPN
    USERNAME=$(echo "$CURRENT_USER_UPN" | cut -d'@' -f1 | tr '.' '-' | tr '[:upper:]' '[:lower:]')

    # Set resource names
    RESOURCE_GROUP="${USERNAME}-flex-test-rg"
    VM_NAME="${USERNAME}-flex-vm"
    SSH_PRIVATE_KEY_FILE="$GENERATED_DIR/${VM_NAME}-ssh.pem"

    log_info "Resource group: $RESOURCE_GROUP"
    log_info "VM name: $VM_NAME"

    # Verify SSH key exists
    if [[ ! -f "$SSH_PRIVATE_KEY_FILE" ]]; then
        log_error "SSH private key not found at: $SSH_PRIVATE_KEY_FILE"
        log_error "Please run deploy-flex-node-vm.sh first"
        exit 1
    fi

    # Get VM public IP
    VM_PUBLIC_IP=$(az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --show-details --query publicIps -o tsv 2>/dev/null) || {
        log_error "Failed to get VM public IP. Make sure the VM exists."
        exit 1
    }

    if [[ -z "$VM_PUBLIC_IP" ]]; then
        log_error "VM does not have a public IP address"
        exit 1
    }

    log_info "VM public IP: $VM_PUBLIC_IP"
}

# Build attestation-cli binary
build_binary() {
    log_info "Building attestation-cli binary..."
    cd "$PROJECT_ROOT"

    # Build for Linux (Azure VMs run Linux)
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -ldflags "-s -w" \
        -o bin/attestation-cli-linux-amd64 \
        ./cmd/attestation-cli

    log_info "Binary built: bin/attestation-cli-linux-amd64"
}

# Copy attestation-cli binary to the Azure VM
deploy_to_vm() {
    log_info "Deploying attestation-cli to Azure VM: $VM_NAME..."

    local ssh_opts="-i $SSH_PRIVATE_KEY_FILE -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    local remote_path="/usr/local/bin/attestation-cli"

    # Copy the binary to the VM
    log_info "Copying attestation-cli binary to VM..."
    scp $ssh_opts "$PROJECT_ROOT/bin/attestation-cli-linux-amd64" azureuser@$VM_PUBLIC_IP:/tmp/attestation-cli || {
        log_error "Failed to copy attestation-cli binary to VM"
        exit 1
    }

    # Move it into place and make it executable
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "sudo mv /tmp/attestation-cli $remote_path && sudo chmod +x $remote_path" || {
        log_error "Failed to install attestation-cli on VM"
        exit 1
    }

    # Verify binary is in place
    log_info "Verifying attestation-cli on VM..."
    ssh $ssh_opts azureuser@$VM_PUBLIC_IP "$remote_path --help 2>&1 || echo 'attestation-cli binary is installed at $remote_path'" || true

    log_info "attestation-cli deployed to VM at $remote_path"
}

# Main
main() {
    log_info "=== Deploy attestation-cli to AKS Flex Node VM ==="

    get_resource_info
    build_binary
    deploy_to_vm

    echo ""
    log_info "=== Deployment complete ==="
    log_info "You can run the attestation-cli on the VM via SSH:"
    echo "  ssh -i $SSH_PRIVATE_KEY_FILE azureuser@$VM_PUBLIC_IP"
    echo "  sudo attestation-cli"
}

main
