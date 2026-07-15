/**
 * App-shell UI state and the first-run local-use gate (UI-008f).
 *
 * The Settings drawer, Privacy panel, and local-use notice are mounted once in
 * the app shell (`+layout.svelte`) and opened from anywhere (NavBar, footer, a
 * guarded action) through this shared store, so their open state has a single
 * owner.
 *
 * `guardControlledAction` is the acknowledgement gate: the design requires the
 * "Authorized local lab use" notice *before the first mutating lab action,
 * terminal launch, or SIEM query* — not on every page load. This is a UI
 * precondition only; it never replaces the server's auth/CSRF/terminal gates
 * (UI-008f preflight guardrail).
 */
import { get, writable } from 'svelte/store';
import { acknowledgeNotice, isNoticeAcknowledged, preferences } from './preferences';

export const settingsOpen = writable(false);
export const privacyOpen = writable(false);
export const noticeOpen = writable(false);

/** The controlled action deferred until the notice is acknowledged, if any. */
let pendingAction: (() => void) | null = null;

export function openSettings(): void {
	settingsOpen.set(true);
}

export function openPrivacy(): void {
	privacyOpen.set(true);
}

/**
 * Run a controlled action, gating it behind the first-run acknowledgement.
 * Runs immediately when the current notice version is already acknowledged;
 * otherwise defers the action and opens the notice.
 */
export function guardControlledAction(run: () => void): void {
	if (isNoticeAcknowledged(get(preferences))) {
		run();
		return;
	}
	pendingAction = run;
	noticeOpen.set(true);
}

/** Acknowledge the notice, close it, and run any deferred controlled action. */
export function acknowledgeAndRun(): void {
	acknowledgeNotice();
	noticeOpen.set(false);
	const action = pendingAction;
	pendingAction = null;
	action?.();
}

/** Dismiss the notice without acknowledging; the deferred action is cancelled. */
export function dismissNotice(): void {
	pendingAction = null;
	noticeOpen.set(false);
}
