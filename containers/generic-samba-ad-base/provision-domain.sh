#!/bin/sh
set -eu

domain=${1:-}
realm=${2:-}
for value in "$domain" "$realm"; do
    case "$value" in
        "" | *[!A-Za-z0-9.-]*)
            exit 2
            ;;
    esac
done

private_root=/var/lib/samba/private
provisioned_marker="$private_root/.provisioned"
saved_config=/var/lib/samba/smb.conf.provisioned

if [ ! -f "$provisioned_marker" ]; then
    rm -f /etc/samba/smb.conf
    admin_password="A1!$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
    samba-tool domain provision \
        --server-role=dc \
        --use-rfc2307 \
        --dns-backend=SAMBA_INTERNAL \
        --realm="$realm" \
        --domain="$domain" \
        --adminpass="$admin_password"
    cp "$private_root/krb5.conf" /etc/krb5.conf
    cp /etc/samba/smb.conf "$saved_config"
    touch "$provisioned_marker"
else
    if [ -f "$saved_config" ]; then
        cp "$saved_config" /etc/samba/smb.conf
    fi
    if [ -f "$private_root/krb5.conf" ]; then
        cp "$private_root/krb5.conf" /etc/krb5.conf
    fi
fi

touch /run/aptl-samba-provider.ready
