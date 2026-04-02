# Dependency Ordering

## Graph Model

- nodes are compiled runtime resources
- edges point from a resource to the resources it depends on for ordering
- only same-snapshot resources participate in ordering normalization

## Required Properties

- ordering dependencies are evaluated on a normalized graph containing only known nodes
- create/start order is a stable topological order
- delete/teardown order is the reverse of create/start order
- ordering cycles are reported fail-closed and keep the plan invalid

## Rollout Notes

This first implementation wave focuses on shared graph primitives. Broader propagation semantics, update semantics, and provenance-aware reconciliation are follow-on work in the same domain.
