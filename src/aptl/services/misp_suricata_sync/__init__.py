"""MISP-to-Suricata IOC sync service.

Polls MISP for indicators tagged for enforcement, translates them into
Suricata-compatible alert rules, writes a dedicated rules file, and
triggers a Suricata rule reload.

Per ADR-019 Suricata stays IDS-only: this service emits ``alert`` rules
only, never ``drop``. Packet-level prevention is handled by Wazuh
active-response, not Suricata.
"""
