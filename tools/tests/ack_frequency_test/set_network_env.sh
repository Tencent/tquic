#!/bin/bash

# ============================================================================
# Network Environment Simulation Setup Script
# ============================================================================
#
# Purpose:
#   Configures Linux network namespaces to simulate various realistic network
#   environments. This script sets up asymmetric bandwidth, latency, jitter,
#   and packet loss to test the performance and robustness of network
#   applications like QUIC libraries.
#
# Supported Network Types:
#   - mobile: Simulates a typical 4G/5G mobile network connection.
#   - home:   Simulates a standard home broadband (Fiber/Cable) connection.
#
# Requirements:
#   - Linux kernel with network namespace support.
#   - iproute2 package (for `ip` and `tc` commands).
#   - iperf3 (optional, for bandwidth verification).
#   - Root or sudo privileges.
#
# Usage:
#   sudo ./setup_network_env.sh [network_type]
#
# Examples:
#   sudo ./setup_network_env.sh mobile
#   sudo ./setup_network_env.sh         # Defaults to 'home'
#
# ============================================================================

# ============================================================================
# Configuration Section
# ============================================================================

# Set the network type from the first argument, defaulting to 'home'
NETWORK_TYPE="${1:-home}"

# Define network profiles with realistic characteristics.
# Data here is sourced from public reports https://www.speedtest.net/global-index/china?city=Shanghai
case "$NETWORK_TYPE" in
  mobile)
    # Mobile Network Profile (e.g., 4G/5G)
    DOWNLINK_RATE="284mbit"     # Download bandwidth
    UPLINK_RATE="36mbit"        # Upload bandwidth
    DOWNLINK_DELAY="8ms"        # Base download latency
    UPLINK_DELAY="9ms"          # Base upload latency
    JITTER="0ms"              # Latency variation (jitter)
    PACKET_LOSS="0%"          # Packet loss rate
    ;;

  home)
    # Home Broadband Profile (e.g., Fiber/Cable)
    DOWNLINK_RATE="290mbit"     # Download bandwidth
    UPLINK_RATE="64mbit"        # Upload bandwidth
    DOWNLINK_DELAY="3ms"        # Base download latency
    UPLINK_DELAY="4ms"          # Base upload latency
    JITTER="0ms"              # Latency variation (jitter)
    PACKET_LOSS="0%"          # Packet loss rate
    ;;
  *)
    echo "ERROR: Unknown network type: $NETWORK_TYPE" >&2
    echo "Supported types: mobile, home" >&2
    exit 1
    ;;
esac

# Define network namespace and virtual interface parameters
CLIENT_NS="client_ns"           # Name for the client namespace
SERVER_NS="server_ns"           # Name for the server namespace
VETH_CLIENT="veth_client"       # Name of the veth interface in the client namespace
VETH_SERVER="veth_server"       # Name of the veth interface in the server namespace
CLIENT_IP="10.0.0.1/24"         # IP address for the client
SERVER_IP="10.0.0.2/24"         # IP address for the server
SERVER_IP_ADDR="10.0.0.2"       # Server IP address without subnet mask for ping/iperf

# ============================================================================
# Script Execution
# ============================================================================

# Exit immediately if any command fails
set -e

# Helper function for printing formatted section headers
print_info() {
  echo -e "\n\e[1;34m--- $1 ---\e[0m"
}

# --- Display selected configuration ---
print_info "Network Simulation Type: $NETWORK_TYPE"
echo "Configuration Parameters:"
echo "  - Downlink Bandwidth: $DOWNLINK_RATE"
echo "  - Uplink Bandwidth:   $UPLINK_RATE"
echo "  - Downlink Delay:     $DOWNLINK_DELAY +/- $JITTER"
echo "  - Uplink Delay:       $UPLINK_DELAY +/- $JITTER"
echo "  - Packet Loss Rate:   $PACKET_LOSS"

# --- Phase 1: Environment Cleanup ---
print_info "Phase 1: Cleaning up any previous environment"
sudo ip netns del "$CLIENT_NS" &>/dev/null || true
sudo ip netns del "$SERVER_NS" &>/dev/null || true
sudo ip link del "$VETH_CLIENT" &>/dev/null || true
echo "Cleanup complete."

# --- Phase 2: Create Network Infrastructure ---
print_info "Phase 2: Creating network namespaces and veth pair"
sudo ip netns add "$CLIENT_NS"
sudo ip netns add "$SERVER_NS"
sudo ip link add "$VETH_CLIENT" type veth peer name "$VETH_SERVER"
echo "Namespaces and veth pair created successfully."

# --- Phase 3: Configure Network Interfaces ---
print_info "Phase 3: Assigning interfaces and IP addresses"
sudo ip link set "$VETH_CLIENT" netns "$CLIENT_NS"
sudo ip link set "$VETH_SERVER" netns "$SERVER_NS"

# Configure client namespace network stack
echo "Configuring client namespace..."
sudo ip netns exec "$CLIENT_NS" ip link set lo up
sudo ip netns exec "$CLIENT_NS" ip link set dev "$VETH_CLIENT" up
sudo ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP" dev "$VETH_CLIENT"

# Configure server namespace network stack
echo "Configuring server namespace..."
sudo ip netns exec "$SERVER_NS" ip link set lo up
sudo ip netns exec "$SERVER_NS" ip link set dev "$VETH_SERVER" up
sudo ip netns exec "$SERVER_NS" ip addr add "$SERVER_IP" dev "$VETH_SERVER"
echo "Network interfaces and IP addresses configured."

# --- Phase 4: Apply Traffic Control Rules ---
print_info "Phase 4: Applying asymmetric traffic control rules"

# Configure uplink (Client -> Server) traffic shaping
echo "Configuring Uplink (Client -> Server)..."
sudo ip netns exec "$CLIENT_NS" tc qdisc add dev "$VETH_CLIENT" root handle 1: htb default 10
sudo ip netns exec "$CLIENT_NS" tc class add dev "$VETH_CLIENT" parent 1: classid 1:10 htb rate "$UPLINK_RATE"
sudo ip netns exec "$CLIENT_NS" tc qdisc add dev "$VETH_CLIENT" parent 1:10 handle 10: netem delay "$UPLINK_DELAY" "$JITTER" loss "$PACKET_LOSS"

# Configure downlink (Server -> Client) traffic shaping
echo "Configuring Downlink (Server -> Client)..."
sudo ip netns exec "$SERVER_NS" tc qdisc add dev "$VETH_SERVER" root handle 1: htb default 10
sudo ip netns exec "$SERVER_NS" tc class add dev "$VETH_SERVER" parent 1: classid 1:10 htb rate "$DOWNLINK_RATE"
sudo ip netns exec "$SERVER_NS" tc qdisc add dev "$VETH_SERVER" parent 1:10 handle 10: netem delay "$DOWNLINK_DELAY" "$JITTER" loss "$PACKET_LOSS"
echo "Traffic control rules applied successfully."

# --- Phase 5: Environment Verification ---
print_info "Phase 5: Verifying the network environment"

# Test connectivity and latency with ping
echo ""
echo "Testing connectivity and latency (10 ping packets)..."
EXPECTED_RTT=$((${DOWNLINK_DELAY%ms} + ${UPLINK_DELAY%ms}))
echo "Expected average RTT: ~${EXPECTED_RTT}ms (plus jitter)"
sudo ip netns exec "$CLIENT_NS" ping -c 10 "$SERVER_IP_ADDR"

# Test bandwidth with iperf3 if available
echo ""
echo "Testing bandwidth with iperf3..."

if ! command -v iperf3 &> /dev/null; then
  echo "WARNING: iperf3 not found. Bandwidth verification skipped."
  echo "You can install it with: sudo apt install iperf3"
  echo ""
  print_info "Network Environment Setup Complete (without bandwidth verification)"
  exit 0
fi

# Start iperf3 server in the background
echo "Starting iperf3 server in server namespace..."
sudo ip netns exec "$SERVER_NS" iperf3 -s &>/dev/null &
IPERF_SERVER_PID=$!
sleep 2 # Give the server a moment to start

# Test downlink bandwidth (server to client)
print_info "Testing Downlink Bandwidth (Server -> Client)"
echo "Expected: ~$DOWNLINK_RATE"
sudo ip netns exec "$CLIENT_NS" iperf3 -c "$SERVER_IP_ADDR" -t 10 -R

# Test uplink bandwidth (client to server)
print_info "Testing Uplink Bandwidth (Client -> Server)"
echo "Expected: ~$UPLINK_RATE"
sudo ip netns exec "$CLIENT_NS" iperf3 -c "$SERVER_IP_ADDR" -t 10

# Clean up iperf3 server process
echo ""
echo "Stopping iperf3 server..."
sudo kill "$IPERF_SERVER_PID" 2>/dev/null || true
wait "$IPERF_SERVER_PID" 2>/dev/null || true

# ============================================================================
# Completion
# ============================================================================

print_info "Network Environment Setup Complete"
echo ""
echo "Summary:"
echo "  - Network Type: $NETWORK_TYPE"
echo "  - Client Namespace: $CLIENT_NS (IP: ${CLIENT_IP%/*})"
echo "  - Server Namespace: $SERVER_NS (IP: ${SERVER_IP%/*})"
echo "  - Configuration verified with ping and iperf3."
echo ""
echo "To run commands within the namespaces:"
echo "  Client side: sudo ip netns exec $CLIENT_NS <your_command>"
echo "  Server side: sudo ip netns exec $SERVER_NS <your_command>"
echo ""
echo "The environment is ready for your network library testing."