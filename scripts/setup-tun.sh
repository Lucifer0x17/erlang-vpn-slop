#!/bin/bash
set -euo pipefail

# ErlVPN TUN Device Setup Script
# Creates and configures the TUN device for ErlVPN

DEVICE_NAME="${1:-erlvpn0}"
TUNNEL_IP="${2:-10.8.0.1}"
TUNNEL_CIDR="${3:-16}"
MTU="${4:-1280}"

log() { echo "[erlvpn-tun] $*"; }
err() { echo "[erlvpn-tun] ERROR: $*" >&2; exit 1; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo)"
fi

OS="$(uname -s)"
log "Detected OS: $OS"
log "Setting up TUN device: $DEVICE_NAME ($TUNNEL_IP/$TUNNEL_CIDR, MTU=$MTU)"

case "$OS" in
    Linux)
        # Ensure TUN module is loaded
        if [ ! -e /dev/net/tun ]; then
            log "Loading tun kernel module..."
            modprobe tun || err "Failed to load tun module"
        fi

        # Create TUN device if it doesn't exist
        if ! ip link show "$DEVICE_NAME" &>/dev/null; then
            log "Creating TUN device $DEVICE_NAME..."
            ip tuntap add dev "$DEVICE_NAME" mode tun
        else
            log "TUN device $DEVICE_NAME already exists"
        fi

        # Configure IP address
        log "Assigning IP $TUNNEL_IP/$TUNNEL_CIDR to $DEVICE_NAME..."
        ip addr flush dev "$DEVICE_NAME" 2>/dev/null || true
        ip addr add "$TUNNEL_IP/$TUNNEL_CIDR" dev "$DEVICE_NAME"

        # Set MTU
        log "Setting MTU to $MTU..."
        ip link set dev "$DEVICE_NAME" mtu "$MTU"

        # Bring interface up
        log "Bringing $DEVICE_NAME up..."
        ip link set dev "$DEVICE_NAME" up

        # Enable IP forwarding
        log "Enabling IPv4 forwarding..."
        sysctl -w net.ipv4.ip_forward=1 > /dev/null
        sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1 || true

        log "TUN device $DEVICE_NAME is up and ready"
        ip addr show dev "$DEVICE_NAME"
        ;;

    Darwin)
        # macOS uses utun devices (kernel-managed)
        # The actual utun device will be created by tunctl at runtime
        # This script just enables forwarding

        log "Enabling IPv4 forwarding..."
        sysctl -w net.inet.ip.forwarding=1 > /dev/null

        log "Enabling IPv6 forwarding..."
        sysctl -w net.inet6.ip6.forwarding=1 > /dev/null 2>&1 || true

        log "Note: On macOS, the utun device is created dynamically by the application."
        log "IP forwarding has been enabled."
        ;;

    *)
        err "Unsupported OS: $OS"
        ;;
esac

log "TUN setup complete."
