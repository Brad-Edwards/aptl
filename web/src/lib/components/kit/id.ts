/**
 * Deterministic, collision-free id generator for kit primitives.
 *
 * Components that wire ARIA relationships (`Field` → control, `Dialog` title /
 * description, `Menu` trigger → menu) need stable ids without depending on
 * `Math.random()`. A module-level counter is monotonic within a page load and
 * keeps test output deterministic per render order.
 */
let counter = 0;

export function nextId(prefix = 'aptl'): string {
	return `${prefix}-${++counter}`;
}
