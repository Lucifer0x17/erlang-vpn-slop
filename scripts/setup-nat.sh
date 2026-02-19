#!/bin/bash
set -euo pipefail

# ErlVPN NAT/Masquerade Setup Script
# Configures NAT for VPN traffic to reach the internet

DEVICE_NAME="${1:-erlvpn0}"
TUNNEL_SUBNET="${2:-10.8.0.0/16}"

log() { echo "[erlvpn-nat] $*"; }
err() { echo "[erlvpn-nat] ERROR: $*" >&2; exit 1; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (or with sudo)"
fi

OS="$(uname -s)"
log "Detected OS: $OS"

# Detect default outgoing interface
detect_default_iface() {
    case "$OS" in
        Linux)
            ip route show default | awk '/default/ {print $5; exit}'
            ;;
        Darwin)
            route -n get default 2>/dev/null | awk '/interface:/ {print $2; exit}'
            ;;
    esac
}

DEFAULT_IFACE="$(detect_default_iface)"
if [ -z "$DEFAULT_IFACE" ]; then
    err "Could not detect default network interface"
fi
log "Default interface: $DEFAULT_IFACE"
log "VPN tunnel device: $DEVICE_NAME"
log "Tunnel subnet: $TUNNEL_SUBNET"

case "$OS" in
    Linux)
        # Check for nftables first, fall back to iptables
        if command -v nft &>/dev/null; then
            log "Using nftables..."

            # Create nftables rules
            nft add table ip erlvpn 2>/dev/null || true
            nft flush table ip erlvpn 2>/dev/null || true

            nft add chain ip erlvpn postrouting '{ type nat hook postrouting priority 100; policy accept; }'
            nft add rule ip erlvpn postrouting oifname "$DEFAULT_IFACE" ip saddr "$TUNNEL_SUBNET" masquerade

            nft add chain ip erlvpn forward '{ type filter hook forward priority 0; policy accept; }'
            nft add rule ip erlvpn forward iifname "$DEVICE_NAME" oifname "$DEFAULT_IFACE" accept
            nft add rule ip erlvpn forward iifname "$DEFAULT_IFACE" oifname "$DEVICE_NAME" ct state established,related accept

            log "nftables NAT rules applied"
            nft list table ip erlvpn

        elif command -v iptables &>/dev/null; then
            log "Using iptables..."

            # NAT/Masquerade
            iptables -t nat -C POSTROUTING -s "$TUNNEL_SUBNET" -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
                iptables -t nat -A POSTROUTING -s "$TUNNEL_SUBNET" -o "$DEFAULT_IFACE" -j MASQUERADE

            # Forward rules
            iptables -C FORWARD -i "$DEVICE_NAME" -o "$DEFAULT_IFACE" -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i "$DEVICE_NAME" -o "$DEFAULT_IFACE" -j ACCEPT

            iptables -C FORWARD -i "$DEFAULT_IFACE" -o "$DEVICE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
                iptables -A FORWARD -i "$DEFAULT_IFACE" -o "$DEVICE_NAME" -m state --state ESTABLISHED,RELATED -j ACCEPT

            log "iptables NAT rules applied"
            iptables -t nat -L POSTROUTING -n -v | head -10
        else
            err "Neither nftables nor iptables found"
        fi
        ;;

    Darwin)
        log "Using pf (Packet Filter) on macOS..."

        PF_ANCHOR="erlvpn"
        PF_RULES="/tmp/erlvpn-pf.conf"

        # Write pf rules
        cat > "$PF_RULES" <<EOF
# ErlVPN NAT rules
nat on $DEFAULT_IFACE from $TUNNEL_SUBNET to any -> ($DEFAULT_IFACE)
pass in on utun+ proto {tcp, udp, icmp} from $TUNNEL_SUBNET to any
pass out on $DEFAULT_IFACE proto {tcp, udp, icmp} from $TUNNEL_SUBNET to any
EOF

        # Load anchor
        echo "nat-anchor \"$PF_ANCHOR\"" | pfctl -f - 2>/dev/null || true
        echo "rdr-anchor \"$PF_ANCHOR\"" | pfctl -f - 2>/dev/null || true

        # Load rules into anchor
        pfctl -a "$PF_ANCHOR" -f "$PF_RULES" 2>/dev/null || \
            pfctl -f "$PF_RULES" 2>/dev/null || true

        # Enable pf if not already enabled
        pfctl -e 2>/dev/null || true

        log "pf NAT rules applied"
        pfctl -a "$PF_ANCHOR" -s nat 2>/dev/null || pfctl -s nat 2>/dev/null || true

        rm -f "$PF_RULES"
        ;;

    *)
        err "Unsupported OS: $OS"
        ;;
esac

log "NAT setup complete. VPN clients can now reach the internet."
