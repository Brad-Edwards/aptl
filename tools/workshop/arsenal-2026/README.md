# Historical Arsenal provisioning sources

Exact source snapshots from `b97746a50442289615c20d00ce5785847fcb34be`
on `889-cortex-adr088-envpack`. The `.txt` suffix is deliberate: these are
non-executable references, not installed or supported provisioning commands.

The files preserve the AMI boot service, fleet launcher, desktop setup, and
temporary SOAR/Suricata/Kali repairs used by the August range. They assume a
specific baked AMI and cloud account. They include broad Docker cleanup,
hardcoded host paths, insecure/default credential handling, ignored failures,
and a capture-admission bypass. Do not run them on the shared host or use them
as a substitute for `aptl seat start`.

Useful repairs must be implemented in current canonical owners after checking
whether later code already incorporates them. See
[the audit](../../../docs/architecture/issue-1022-historical-branch-audit.md)
and [the event QA record](../../../docs/workshop/arsenal-2026/qa.md).
