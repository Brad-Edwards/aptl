### Fixed

Pinned the `shuffle-orborus` container to a static `aptl-security` address
(`172.20.0.7`). It was previously the only SOC datastore left on a DHCP
address, so its IP drifted between ACES inventory capture runs and left the
committed evidence bundle internally inconsistent. The orborus capture script
also had a `docker logs … 2>&1 > file` redirection that discarded the
container's stderr log stream; it now captures both streams.
