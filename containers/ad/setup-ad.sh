#!/bin/bash
set -e

DOMAIN="${SAMBA_DOMAIN:-TECHVAULT}"
REALM="${SAMBA_REALM:-TECHVAULT.LOCAL}"
ADMIN_PASS="${SAMBA_ADMIN_PASSWORD:-Admin123!}"
DNS_FORWARDER="${DNS_FORWARDER:-8.8.8.8}"

REALM_LOWER=$(echo "$REALM" | tr '[:upper:]' '[:lower:]')
PROVISIONED_MARKER="/var/lib/samba/private/.provisioned"

if [ ! -f "$PROVISIONED_MARKER" ]; then
    echo "=== Provisioning Samba AD DC ==="
    echo "Domain: $DOMAIN"
    echo "Realm: $REALM"

    # Remove default smb.conf
    rm -f /etc/samba/smb.conf

    # Provision the domain
    samba-tool domain provision \
        --server-role=dc \
        --use-rfc2307 \
        --dns-backend=SAMBA_INTERNAL \
        --realm="$REALM" \
        --domain="$DOMAIN" \
        --adminpass="$ADMIN_PASS" \
        --option="dns forwarder = $DNS_FORWARDER"

    # Copy Kerberos config
    cp /var/lib/samba/private/krb5.conf /etc/krb5.conf

    # Configure rsyslog forwarding if SIEM_IP is set
    if [ -n "$SIEM_IP" ]; then
        cat > /etc/rsyslog.d/90-forward.conf <<EOF
*.* @${SIEM_IP}:514
EOF
    fi

    # Provision users and groups
    /opt/provision-users.sh

    # Save smb.conf to volume so it survives container rebuilds
    cp /etc/samba/smb.conf /var/lib/samba/smb.conf.provisioned

    touch "$PROVISIONED_MARKER"
    echo "=== Samba AD DC provisioned ==="
else
    echo "=== Samba AD DC already provisioned, starting ==="
    # Restore provisioned smb.conf if the container was rebuilt
    if [ -f /var/lib/samba/smb.conf.provisioned ]; then
        cp /var/lib/samba/smb.conf.provisioned /etc/samba/smb.conf
        echo "Restored AD DC smb.conf from volume"
    fi
    # Restore Kerberos config
    if [ -f /var/lib/samba/private/krb5.conf ]; then
        cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
    fi
fi

# Configure rsyslog forwarding (always, in case container was rebuilt)
if [ -n "$SIEM_IP" ]; then
    cat > /etc/rsyslog.d/90-forward.conf <<EOF
*.* @${SIEM_IP}:514
EOF
fi

# Start services via supervisord
exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
