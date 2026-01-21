#!/bin/bash
set -e

# Script to sign pod specs using the signing-server for kubelet-proxy signature verification

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SIGNING_SERVER_URL="${SIGNING_SERVER_URL:-http://localhost:8080}"
SIGNING_SERVER_PORT="${SIGNING_SERVER_PORT:-8080}"

# Legacy key directory (for backward compatibility with verify-spec)
KEY_DIR="${KEY_DIR:-$PROJECT_ROOT/tmp/signing-keys}"

usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  sign-spec <pod.yaml>       Sign a pod's spec and output with signature annotation"
    echo "  verify-spec <pod.yaml>     Verify a pod's signature (requires local cert)"
    echo "  get-cert                   Fetch the signing certificate from signing-server"
    echo ""
    echo "Environment variables:"
    echo "  SIGNING_SERVER_URL         URL to signing-server (default: http://localhost:8080)"
    echo "  KEY_DIR                    Directory for certs (default: $KEY_DIR)"
    echo ""
    echo "Examples:"
    echo "  $0 sign-spec my-pod.yaml > signed-pod.yaml"
    echo "  kubectl apply -f signed-pod.yaml"
    echo "  $0 get-cert > signing-cert.pem"
}

get_signing_server_url() {
    echo "$SIGNING_SERVER_URL"
}

check_signing_server() {
    local url
    url=$(get_signing_server_url)
    
    if ! curl -sf "$url/health" >/dev/null 2>&1; then
        echo "Error: signing-server is not running at $url" >&2
        echo "Start the signing-server with: docker run -d -p 8080:8080 --name signing-server signing-server:local" >&2
        return 1
    fi
    return 0
}

get_cert() {
    check_signing_server || exit 1
    
    local url
    url=$(get_signing_server_url)
    
    curl -sf "$url/signingcert"
    local rc=$?
    
    if [[ $rc -ne 0 ]]; then
        echo "Error: Failed to fetch signing certificate" >&2
        exit 1
    fi
}

sign_spec() {
    local pod_file="$1"
    
    if [[ -z "$pod_file" ]]; then
        echo "Error: pod file required" >&2
        usage
        exit 1
    fi
    
    if [[ ! -f "$pod_file" ]]; then
        echo "Error: file not found: $pod_file" >&2
        exit 1
    fi
    
    check_signing_server || exit 1
    
    local url
    url=$(get_signing_server_url)
    
    # Check if we have yq or python for YAML/JSON processing
    if command -v yq &>/dev/null; then
        YAML_TOOL="yq"
    elif command -v python3 &>/dev/null; then
        YAML_TOOL="python"
    else
        echo "Error: yq or python3 required for YAML processing" >&2
        exit 1
    fi
    
    # Extract the spec as canonical JSON
    local spec_json
    if [[ "$YAML_TOOL" == "yq" ]]; then
        spec_json=$(yq -o=json '.spec' "$pod_file" | jq -cS '.')
    else
        spec_json=$(python3 -c "
import yaml
import json
import sys

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [sort_dict(item) for item in obj]
    return obj

spec = sort_dict(pod.get('spec', {}))
print(json.dumps(spec, separators=(',', ':')))
")
    fi
    
    # Call signing-server to sign the spec
    local response
    response=$(curl -sf -X POST "$url/sign" \
        -H "Content-Type: application/json" \
        -d "{\"payload\": $(echo "$spec_json" | jq -Rs .)}")
    
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to sign pod spec" >&2
        exit 1
    fi
    
    local signature
    signature=$(echo "$response" | jq -r '.signature')
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        echo "Error: No signature returned from signing-server" >&2
        exit 1
    fi
    
    # Output the pod with the signature annotation added
    if [[ "$YAML_TOOL" == "yq" ]]; then
        yq eval ".metadata.annotations.\"kubelet-proxy.io/signature\" = \"$signature\"" "$pod_file"
    else
        python3 -c "
import yaml
import sys

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

if 'metadata' not in pod:
    pod['metadata'] = {}
if 'annotations' not in pod['metadata']:
    pod['metadata']['annotations'] = {}

pod['metadata']['annotations']['kubelet-proxy.io/signature'] = '$signature'

yaml.dump(pod, sys.stdout, default_flow_style=False)
"
    fi
    
    echo "" >&2
    echo "Signature added to pod spec" >&2
    echo "Spec hash (for debugging): $(echo -n "$spec_json" | sha256sum | cut -d' ' -f1)" >&2
}

verify_spec() {
    local pod_file="$1"
    
    if [[ -z "$pod_file" ]]; then
        echo "Error: pod file required" >&2
        usage
        exit 1
    fi
    
    if [[ ! -f "$pod_file" ]]; then
        echo "Error: file not found: $pod_file" >&2
        exit 1
    fi
    
    # Try to find certificate - check KEY_DIR first, then tmp/certs
    local cert_file=""
    if [[ -f "$KEY_DIR/signing.crt" ]]; then
        cert_file="$KEY_DIR/signing.crt"
    elif [[ -f "$KEY_DIR/signing-cert.pem" ]]; then
        cert_file="$KEY_DIR/signing-cert.pem"
    elif [[ -f "$PROJECT_ROOT/tmp/certs/signing-cert.pem" ]]; then
        cert_file="$PROJECT_ROOT/tmp/certs/signing-cert.pem"
    fi
    
    if [[ -z "$cert_file" || ! -f "$cert_file" ]]; then
        echo "Error: signing certificate not found." >&2
        echo "Run '$0 get-cert > \$KEY_DIR/signing-cert.pem' first." >&2
        exit 1
    fi
    
    # Check for yq or python
    if command -v yq &>/dev/null; then
        YAML_TOOL="yq"
    elif command -v python3 &>/dev/null; then
        YAML_TOOL="python"
    else
        echo "Error: yq or python3 required for YAML processing" >&2
        exit 1
    fi
    
    # Extract signature and spec
    local signature spec_json
    if [[ "$YAML_TOOL" == "yq" ]]; then
        signature=$(yq '.metadata.annotations."kubelet-proxy.io/signature"' "$pod_file")
        spec_json=$(yq -o=json '.spec' "$pod_file" | jq -cS '.')
    else
        signature=$(python3 -c "
import yaml
with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)
print(pod.get('metadata', {}).get('annotations', {}).get('kubelet-proxy.io/signature', ''))
")
        spec_json=$(python3 -c "
import yaml
import json

with open('$pod_file', 'r') as f:
    pod = yaml.safe_load(f)

def sort_dict(obj):
    if isinstance(obj, dict):
        return {k: sort_dict(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [sort_dict(item) for item in obj]
    return obj

spec = sort_dict(pod.get('spec', {}))
print(json.dumps(spec, separators=(',', ':')))
")
    fi
    
    if [[ -z "$signature" || "$signature" == "null" ]]; then
        echo "Error: no signature found in pod" >&2
        exit 1
    fi
    
    # Extract public key from certificate
    local pubkey_file
    pubkey_file=$(mktemp)
    openssl x509 -in "$cert_file" -pubkey -noout > "$pubkey_file" 2>/dev/null
    
    # Verify
    echo "Verifying signature..."
    echo "Spec hash: $(echo -n "$spec_json" | sha256sum | cut -d' ' -f1)"
    
    if echo -n "$spec_json" | openssl dgst -sha256 -verify "$pubkey_file" -signature <(echo "$signature" | base64 -d) 2>/dev/null; then
        echo "✓ Signature is VALID"
        rm -f "$pubkey_file"
    else
        echo "✗ Signature is INVALID"
        rm -f "$pubkey_file"
        exit 1
    fi
}

# Main
case "${1:-}" in
    sign-spec)
        sign_spec "$2"
        ;;
    verify-spec)
        verify_spec "$2"
        ;;
    get-cert)
        get_cert
        ;;
    *)
        usage
        exit 1
        ;;
esac
