/**
 * Local operator preferences (UI-008f).
 *
 * A single schema-versioned, browser-local store — the one extensibility seam
 * for non-secret UI preferences (per the design spec's "Settings and
 * Persistence" table and the UI-008f preflight guardrails). It is deliberately
 * NOT an API DTO, `aptl.json`, a cookie, or server-side state: preferences never
 * leave the browser in v1.
 *
 * Invariants:
 * - **Never persist secrets** — no API tokens, bearer headers, service
 *   credentials, terminal I/O, or raw SIEM query bodies. Only the non-secret
 *   fields below.
 * - **Schema-versioned** — stored under `aptl.web.preferences.v1` with an inner
 *   `v` guard. A version mismatch or corrupt JSON resets to defaults; unknown
 *   keys are ignored; out-of-range values fall back per field.
 * - **Reset** — `resetPreferences()` returns every field to its default.
 *
 * Reading/writing storage and applying document effects are guarded on
 * `globalThis` (mirroring `$lib/session`) so the module is import-safe under SSR
 * and in tests.
 */
import { get, writable } from 'svelte/store';

export const PREFERENCES_VERSION = 1;
export const PREFERENCES_KEY = 'aptl.web.preferences.v1';

/** Bumped whenever the local-use/privacy notice text materially changes, so a
 *  prior acknowledgement no longer counts (the notice re-appears). */
export const NOTICE_VERSION = '1';

export type ColorMode = 'system' | 'dark' | 'light' | 'high-contrast';
export type Density = 'comfortable' | 'compact';
export type Motion = 'system' | 'reduced';
export type TimeDisplay = 'local' | 'utc';
export type SiemTimeRange = '15m' | '1h' | '24h';

/** Stored acknowledgement of the local-use/privacy notice — version + when. */
export interface NoticeAck {
	version: string;
	timestamp: string;
}

export interface Preferences {
	colorMode: ColorMode;
	density: Density;
	motion: Motion;
	/** `'system'` (browser default) or a BCP-47 language tag. */
	locale: string;
	timeDisplay: TimeDisplay;
	siemTimeRange: SiemTimeRange;
	siemRowLimit: number;
	terminalFontSize: number;
	terminalScrollback: number;
	noticeAck: NoticeAck | null;
}

export const TERMINAL_FONT_SIZE_MIN = 10;
export const TERMINAL_FONT_SIZE_MAX = 20;

export const SIEM_ROW_LIMITS = [50, 100, 250, 500] as const;
export const TERMINAL_SCROLLBACKS = [500, 1000, 5000, 10000] as const;

export const DEFAULT_PREFERENCES: Preferences = {
	colorMode: 'system',
	density: 'comfortable',
	motion: 'system',
	locale: 'system',
	timeDisplay: 'local',
	siemTimeRange: '1h',
	siemRowLimit: 100,
	terminalFontSize: 14,
	terminalScrollback: 1000,
	noticeAck: null
};

/** Labelled option lists — the single source shared by the dialog and tests. */
export const COLOR_MODE_OPTIONS: { value: ColorMode; label: string }[] = [
	{ value: 'system', label: 'System' },
	{ value: 'dark', label: 'Dark' },
	{ value: 'light', label: 'Light' },
	{ value: 'high-contrast', label: 'High contrast' }
];
export const DENSITY_OPTIONS: { value: Density; label: string }[] = [
	{ value: 'comfortable', label: 'Comfortable' },
	{ value: 'compact', label: 'Compact' }
];
export const MOTION_OPTIONS: { value: Motion; label: string }[] = [
	{ value: 'system', label: 'System' },
	{ value: 'reduced', label: 'Reduced' }
];
export const LOCALE_OPTIONS: { value: string; label: string }[] = [
	{ value: 'system', label: 'Browser default' },
	{ value: 'en', label: 'English' },
	{ value: 'en-GB', label: 'English (UK)' },
	{ value: 'de', label: 'Deutsch' },
	{ value: 'es', label: 'Español' },
	{ value: 'fr', label: 'Français' },
	{ value: 'ja', label: '日本語' }
];
export const TIME_DISPLAY_OPTIONS: { value: TimeDisplay; label: string }[] = [
	{ value: 'local', label: 'Browser local time' },
	{ value: 'utc', label: 'UTC' }
];
export const SIEM_TIME_RANGE_OPTIONS: { value: SiemTimeRange; label: string }[] = [
	{ value: '15m', label: 'Last 15 minutes' },
	{ value: '1h', label: 'Last hour' },
	{ value: '24h', label: 'Last 24 hours' }
];

function oneOf<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
	return typeof value === 'string' && (allowed as readonly string[]).includes(value)
		? (value as T)
		: fallback;
}

function boundedInt(
	value: unknown,
	min: number,
	max: number,
	fallback: number
): number {
	return typeof value === 'number' && Number.isInteger(value) && value >= min && value <= max
		? value
		: fallback;
}

function memberOf(value: unknown, allowed: readonly number[], fallback: number): number {
	return typeof value === 'number' && allowed.includes(value) ? value : fallback;
}

function sanitizeLocale(value: unknown): string {
	if (value === 'system') return 'system';
	// Accept a plausible BCP-47 tag (e.g. `en`, `en-GB`, `zh-Hant`); anything
	// else falls back to the browser default rather than persisting garbage.
	if (typeof value === 'string' && /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(value)) {
		return value;
	}
	return DEFAULT_PREFERENCES.locale;
}

function sanitizeNoticeAck(value: unknown): NoticeAck | null {
	if (
		value &&
		typeof value === 'object' &&
		typeof (value as NoticeAck).version === 'string' &&
		typeof (value as NoticeAck).timestamp === 'string'
	) {
		return { version: (value as NoticeAck).version, timestamp: (value as NoticeAck).timestamp };
	}
	return null;
}

/** Coerce arbitrary parsed input into a valid `Preferences`, field by field. */
export function sanitizePreferences(raw: unknown): Preferences {
	const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
	return {
		colorMode: oneOf(r.colorMode, ['system', 'dark', 'light', 'high-contrast'], DEFAULT_PREFERENCES.colorMode),
		density: oneOf(r.density, ['comfortable', 'compact'], DEFAULT_PREFERENCES.density),
		motion: oneOf(r.motion, ['system', 'reduced'], DEFAULT_PREFERENCES.motion),
		locale: sanitizeLocale(r.locale),
		timeDisplay: oneOf(r.timeDisplay, ['local', 'utc'], DEFAULT_PREFERENCES.timeDisplay),
		siemTimeRange: oneOf(r.siemTimeRange, ['15m', '1h', '24h'], DEFAULT_PREFERENCES.siemTimeRange),
		siemRowLimit: memberOf(r.siemRowLimit, SIEM_ROW_LIMITS, DEFAULT_PREFERENCES.siemRowLimit),
		terminalFontSize: boundedInt(
			r.terminalFontSize,
			TERMINAL_FONT_SIZE_MIN,
			TERMINAL_FONT_SIZE_MAX,
			DEFAULT_PREFERENCES.terminalFontSize
		),
		terminalScrollback: memberOf(
			r.terminalScrollback,
			TERMINAL_SCROLLBACKS,
			DEFAULT_PREFERENCES.terminalScrollback
		),
		noticeAck: sanitizeNoticeAck(r.noticeAck)
	};
}

/** Load and validate preferences from local storage, defaulting on any fault. */
export function loadPreferences(): Preferences {
	try {
		const raw = globalThis.localStorage?.getItem(PREFERENCES_KEY);
		if (!raw) return { ...DEFAULT_PREFERENCES };
		const parsed = JSON.parse(raw) as { v?: unknown };
		if (!parsed || typeof parsed !== 'object' || parsed.v !== PREFERENCES_VERSION) {
			// Unknown/absent schema version — ignore the stored blob and reset.
			return { ...DEFAULT_PREFERENCES };
		}
		return sanitizePreferences(parsed);
	} catch {
		return { ...DEFAULT_PREFERENCES };
	}
}

function persist(prefs: Preferences): void {
	try {
		globalThis.localStorage?.setItem(
			PREFERENCES_KEY,
			JSON.stringify({ v: PREFERENCES_VERSION, ...prefs })
		);
	} catch {
		// Storage unavailable (private-mode edge cases) — preferences stay
		// in-memory for the session; nothing else to do.
	}
}

/**
 * Apply the preferences that drive global presentation to `<html>` as data
 * attributes. `app.css` keys its light/high-contrast palettes off
 * `data-color-mode`, its forced-reduced-motion block off `data-motion`, and the
 * component kit reads `data-density`. No-op when there is no document (SSR/tests
 * without jsdom).
 */
export function applyPreferenceEffects(prefs: Preferences): void {
	const el = globalThis.document?.documentElement;
	if (!el) return;
	el.setAttribute('data-color-mode', prefs.colorMode);
	el.setAttribute('data-density', prefs.density);
	el.setAttribute('data-motion', prefs.motion);
}

/** The live preferences store. Loaded from storage; persisted + applied on change. */
export const preferences = writable<Preferences>(loadPreferences());

preferences.subscribe((prefs) => {
	persist(prefs);
	applyPreferenceEffects(prefs);
});

/** Update a single preference field. */
export function setPreference<K extends keyof Preferences>(key: K, value: Preferences[K]): void {
	preferences.update((prefs) => ({ ...prefs, [key]: value }));
}

/** Clamp + set the terminal font size within its bounded range. */
export function setTerminalFontSize(size: number): void {
	const clamped = Math.max(
		TERMINAL_FONT_SIZE_MIN,
		Math.min(TERMINAL_FONT_SIZE_MAX, Math.round(size))
	);
	setPreference('terminalFontSize', clamped);
}

/** Return every preference to its default (the visible "Reset preferences"). */
export function resetPreferences(): void {
	preferences.set({ ...DEFAULT_PREFERENCES });
}

/** Whether the current notice version has been acknowledged. */
export function isNoticeAcknowledged(prefs: Preferences = get(preferences)): boolean {
	return prefs.noticeAck?.version === NOTICE_VERSION;
}

/** Record acknowledgement of the current notice version with a timestamp. */
export function acknowledgeNotice(): void {
	setPreference('noticeAck', { version: NOTICE_VERSION, timestamp: new Date().toISOString() });
}
