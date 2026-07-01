import { error } from '@sveltejs/kit';
import { ApiError, getScenario } from '$lib/api';
import type { ScenarioDetail } from '$lib/types';

/**
 * Load the scenario-detail workbench projection for `/scenarios/[id]`.
 *
 * Routes through `getScenario()` (not a raw `fetch`) so the call carries the
 * port-scoped `X-APTL-Session` header via the shared API boundary, and threads
 * the load-provided `event.fetch` in so the request resolves in every load
 * context. An unknown scenario surfaces as a route-level 404 (short message +
 * Lab link from the error page); any other failure (malformed catalog/ACES
 * projection, transport error) becomes a redacted page-level unavailable state.
 */
export async function load({
	params,
	fetch
}): Promise<{ scenario: ScenarioDetail }> {
	try {
		return { scenario: await getScenario(params.id, fetch) };
	} catch (err) {
		if (err instanceof ApiError && err.status === 404) {
			error(404, 'Scenario not found');
		}
		error(502, 'Scenario is currently unavailable');
	}
}
