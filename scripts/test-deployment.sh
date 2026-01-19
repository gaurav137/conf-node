#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "${BLUE}[TEST]${NC} $1"; }

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-kubelet-proxy-test}"
WORKER_NODE_NAME="${CLUSTER_NAME}-worker"

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check cluster exists
    if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
        log_error "Cluster '$CLUSTER_NAME' not found. Run 'make deploy-kind' first."
        exit 1
    fi
    
    # Check kubectl context
    kubectl config use-context "kind-${CLUSTER_NAME}" >/dev/null 2>&1
    
    log_info "Prerequisites OK"
}

check_proxy_status() {
    log_test "Checking kubelet-proxy status on worker node..."
    echo ""
    
    if docker exec "$WORKER_NODE_NAME" systemctl is-active --quiet kubelet-proxy; then
        log_info "kubelet-proxy is RUNNING"
    else
        log_error "kubelet-proxy is NOT running"
        echo "Recent logs:"
        docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 20
        exit 1
    fi
    echo ""
}

check_nodes() {
    log_test "Checking cluster nodes..."
    echo ""
    kubectl get nodes -o wide
    echo ""
}

cleanup_test_resources() {
    log_info "Cleaning up any existing test resources..."
    kubectl delete pod test-allowed --ignore-not-found=true 2>/dev/null || true
    kubectl delete pod test-blocked -n blocked-test --ignore-not-found=true 2>/dev/null || true
    kubectl delete namespace blocked-test --ignore-not-found=true 2>/dev/null || true
    sleep 2
}

test_allowed_pod() {
    log_test "TEST 1: Creating a pod that SHOULD BE ALLOWED..."
    echo ""
    
    # Create pod in default namespace (should be allowed)
    kubectl run test-allowed --image=nginx --restart=Never
    
    log_info "Waiting for pod to be scheduled..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-allowed -o wide
    echo ""
    
    # Check if pod is running or at least not failed
    POD_STATUS=$(kubectl get pod test-allowed -o jsonpath='{.status.phase}')
    if [[ "$POD_STATUS" == "Running" || "$POD_STATUS" == "Pending" || "$POD_STATUS" == "ContainerCreating" ]]; then
        log_info "✓ TEST 1 PASSED: Pod was allowed (status: $POD_STATUS)"
    else
        log_error "✗ TEST 1 FAILED: Pod status is $POD_STATUS"
    fi
    echo ""
}

test_blocked_pod() {
    log_test "TEST 2: Creating a pod in BLOCKED namespace (should be REJECTED)..."
    echo ""
    
    # Create blocked namespace
    kubectl create namespace blocked-test
    
    # Create pod in blocked namespace
    kubectl run test-blocked --image=nginx --restart=Never -n blocked-test
    
    log_info "Waiting for admission decision..."
    sleep 5
    
    echo ""
    echo "Pod status:"
    kubectl get pod test-blocked -n blocked-test -o wide 2>/dev/null || echo "Pod not found"
    echo ""
    
    # Check if pod is in Failed state with correct reason
    POD_STATUS=$(kubectl get pod test-blocked -n blocked-test -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
    POD_REASON=$(kubectl get pod test-blocked -n blocked-test -o jsonpath='{.status.reason}' 2>/dev/null || echo "")
    
    if [[ "$POD_STATUS" == "Failed" && "$POD_REASON" == "NodeAdmissionRejected" ]]; then
        log_info "✓ TEST 2 PASSED: Pod was REJECTED (status: $POD_STATUS, reason: $POD_REASON)"
        echo ""
        echo "Pod details:"
        kubectl describe pod test-blocked -n blocked-test | grep -A5 "Status:"
    elif [[ "$POD_STATUS" == "Failed" ]]; then
        log_warn "? TEST 2 PARTIAL: Pod is Failed but reason is '$POD_REASON' (expected 'NodeAdmissionRejected')"
        echo ""
        echo "Pod details:"
        kubectl describe pod test-blocked -n blocked-test | grep -A5 "Status:"
    elif [[ "$POD_STATUS" == "NotFound" ]]; then
        log_warn "? TEST 2 INCONCLUSIVE: Pod not found (may have been filtered)"
    else
        log_error "✗ TEST 2 FAILED: Pod was NOT rejected (status: $POD_STATUS, reason: $POD_REASON)"
        echo ""
        echo "Pod details:"
        kubectl describe pod test-blocked -n blocked-test
    fi
    echo ""
}

show_proxy_logs() {
    log_test "Recent kubelet-proxy logs..."
    echo ""
    docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy --no-pager -n 30 | tail -30
    echo ""
}

run_tests() {
    echo ""
    echo "========================================"
    echo "  Kubelet-Proxy Deployment Tests"
    echo "========================================"
    echo ""
    
    check_prerequisites
    check_nodes
    check_proxy_status
    cleanup_test_resources
    test_allowed_pod
    test_blocked_pod
    show_proxy_logs
    
    echo ""
    echo "========================================"
    echo "  Test Summary"
    echo "========================================"
    echo ""
    echo "To watch proxy logs in real-time:"
    echo "  docker exec $WORKER_NODE_NAME journalctl -u kubelet-proxy -f"
    echo ""
    echo "To clean up test resources:"
    echo "  kubectl delete pod test-allowed"
    echo "  kubectl delete namespace blocked-test"
    echo ""
    echo "To tear down the cluster:"
    echo "  make teardown-kind"
    echo ""
}

# Parse arguments
case "${1:-}" in
    --logs)
        docker exec "$WORKER_NODE_NAME" journalctl -u kubelet-proxy -f
        ;;
    --status)
        check_proxy_status
        check_nodes
        kubectl get pods -A -o wide
        ;;
    --cleanup)
        cleanup_test_resources
        log_info "Test resources cleaned up"
        ;;
    *)
        run_tests
        ;;
esac
