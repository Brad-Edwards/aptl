import { createRawSnippet } from 'svelte';

/** A snippet that renders plain text (wrapped in a span) for kit children props. */
export function textSnippet(text: string) {
	return createRawSnippet(() => ({
		render: () => `<span>${text}</span>`
	}));
}

/** A snippet that renders a focusable button, for overlay focus tests. */
export function buttonSnippet(label: string, testid = 'snippet-button') {
	return createRawSnippet(() => ({
		render: () => `<button data-testid="${testid}">${label}</button>`
	}));
}
