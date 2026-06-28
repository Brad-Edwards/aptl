// SPA mode: disable SSR and prerendering for all routes.
// adapter-static generates a single index.html fallback; client-side JS
// handles all routing.  No server-side load runs, so no API token is ever
// rendered into the page HTML.
import { browser } from '$app/environment';
import { captureSessionFromHash } from '$lib/session';

export const ssr = false;
export const prerender = false;

// Runs (client-side) before any component mounts, so the session header token
// from the login-redirect fragment is in sessionStorage before the first
// /api/* call. See $lib/session for why the token travels in the URL fragment.
export const load = () => {
	if (browser) captureSessionFromHash();
};
