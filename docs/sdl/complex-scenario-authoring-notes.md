# Complex Scenario Authoring Notes

This file is a persistent issue log for the large SDL example scenarios
added in this branch. It exists specifically so scenario-authoring
friction does not disappear into chat context.

## Notes

- Initial design goal: author scenarios from explicit design briefs first,
  then encode them into SDL examples and tests.
- Resolved: leaf enum-backed property fields can now take full `${var}`
  placeholders. The complex examples use this for
  `accounts.*.password_strength`, while discriminant `type` fields remain
  concrete.
- Resolved: named service bindings and named ACL rules are now first-class
  target refs via `nodes.<node>.services.<service_name>` and
  `infrastructure.<infra>.acls.<acl_name>`. The hospital and port
  examples use these directly in objectives.
- Resolved: release and recovery flows no longer need to be flattened only
  into `stories` / `scripts` / `events` plus `depends_on`. The SDL now
  has first-class `workflows` for branching and parallel objective
  composition, and the satcom/port examples exercise them.
- Resolved: workflows now support `switch` routing, reusable `call`
  subflows, and explicit cancel/timeout lifecycle semantics at the
  control-plane boundary.
- Still out of scope: workflows are DAGs only. General loops, exception
  hierarchies, and compensation/rollback semantics remain future work.
