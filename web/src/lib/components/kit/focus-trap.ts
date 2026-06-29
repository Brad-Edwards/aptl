/**
 * Minimal focus-management utilities for the kit's overlay primitives
 * (`Dialog`, `Menu`). Owning this behaviour — rather than pulling a headless
 * component library — keeps the kit small, avoids a new runtime dependency
 * under the strict `script-src 'self'` CSP, and lets the focus contract be
 * tested directly.
 */

const FOCUSABLE_SELECTOR = [
	'a[href]',
	'button:not([disabled])',
	'input:not([disabled])',
	'select:not([disabled])',
	'textarea:not([disabled])',
	'[tabindex]:not([tabindex="-1"])'
].join(',');

/**
 * Focusable descendants of `container`, in DOM order. Elements explicitly
 * hidden via the `hidden` attribute or `aria-hidden` are excluded. Layout-based
 * visibility is intentionally not consulted (jsdom has no layout, and the kit's
 * overlays mount their content unconditionally while open).
 */
export function getFocusable(container: HTMLElement): HTMLElement[] {
	return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
		(el) => !el.hasAttribute('hidden') && el.getAttribute('aria-hidden') !== 'true'
	);
}

export interface FocusTrap {
	activate(): void;
	deactivate(): void;
}

/**
 * Confine Tab / Shift+Tab focus cycling to `container`. The container itself is
 * treated as a valid focus position (it carries `tabindex="-1"` so the overlay
 * can receive initial focus); Tab from the last element wraps to the first, and
 * Shift+Tab from the first (or the container) wraps to the last.
 */
export function createFocusTrap(container: HTMLElement): FocusTrap {
	function onKeydown(event: KeyboardEvent): void {
		if (event.key !== 'Tab') return;
		const focusable = getFocusable(container);
		if (focusable.length === 0) {
			event.preventDefault();
			container.focus();
			return;
		}
		const first = focusable[0];
		const last = focusable[focusable.length - 1];
		const active = document.activeElement;
		if (event.shiftKey && (active === first || active === container)) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && active === last) {
			event.preventDefault();
			first.focus();
		}
	}

	return {
		activate() {
			container.addEventListener('keydown', onKeydown);
		},
		deactivate() {
			container.removeEventListener('keydown', onKeydown);
		}
	};
}
