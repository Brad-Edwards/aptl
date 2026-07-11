import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import {
	preferences,
	DEFAULT_PREFERENCES,
	PREFERENCES_KEY,
	PREFERENCES_VERSION,
	NOTICE_VERSION,
	TERMINAL_FONT_SIZE_MIN,
	TERMINAL_FONT_SIZE_MAX,
	sanitizePreferences,
	loadPreferences,
	setPreference,
	setTerminalFontSize,
	resetPreferences,
	isNoticeAcknowledged,
	acknowledgeNotice,
	applyPreferenceEffects
} from '../../src/lib/stores/preferences';

beforeEach(() => {
	localStorage.clear();
	resetPreferences();
});

describe('sanitizePreferences', () => {
	it('passes a fully valid object through unchanged', () => {
		const valid = {
			...DEFAULT_PREFERENCES,
			colorMode: 'light' as const,
			density: 'compact' as const,
			terminalFontSize: 16
		};
		expect(sanitizePreferences(valid)).toEqual(valid);
	});

	it('falls back per field on invalid values', () => {
		const r = sanitizePreferences({
			colorMode: 'neon',
			density: 5,
			motion: 'x',
			siemRowLimit: 999,
			terminalFontSize: 99,
			terminalScrollback: 3
		});
		expect(r.colorMode).toBe(DEFAULT_PREFERENCES.colorMode);
		expect(r.density).toBe(DEFAULT_PREFERENCES.density);
		expect(r.motion).toBe(DEFAULT_PREFERENCES.motion);
		expect(r.siemRowLimit).toBe(DEFAULT_PREFERENCES.siemRowLimit);
		expect(r.terminalFontSize).toBe(DEFAULT_PREFERENCES.terminalFontSize);
		expect(r.terminalScrollback).toBe(DEFAULT_PREFERENCES.terminalScrollback);
	});

	it('ignores unknown keys and non-object input', () => {
		expect(sanitizePreferences({ bogus: 1 })).toEqual(DEFAULT_PREFERENCES);
		expect(sanitizePreferences(null)).toEqual(DEFAULT_PREFERENCES);
		expect(sanitizePreferences('nope')).toEqual(DEFAULT_PREFERENCES);
	});

	it('accepts a plausible BCP-47 locale and rejects garbage', () => {
		expect(sanitizePreferences({ locale: 'en-GB' }).locale).toBe('en-GB');
		expect(sanitizePreferences({ locale: 'system' }).locale).toBe('system');
		expect(sanitizePreferences({ locale: '!!' }).locale).toBe(DEFAULT_PREFERENCES.locale);
	});

	it('keeps a well-formed noticeAck and drops a malformed one', () => {
		expect(sanitizePreferences({ noticeAck: { version: '1', timestamp: 't' } }).noticeAck).toEqual({
			version: '1',
			timestamp: 't'
		});
		expect(sanitizePreferences({ noticeAck: { version: 1 } }).noticeAck).toBeNull();
	});
});

describe('loadPreferences', () => {
	it('returns defaults when nothing is stored', () => {
		localStorage.clear();
		expect(loadPreferences()).toEqual(DEFAULT_PREFERENCES);
	});

	it('resets on a schema-version mismatch', () => {
		localStorage.setItem(PREFERENCES_KEY, JSON.stringify({ v: 999, colorMode: 'light' }));
		expect(loadPreferences()).toEqual(DEFAULT_PREFERENCES);
	});

	it('loads and sanitizes a valid stored blob', () => {
		localStorage.setItem(
			PREFERENCES_KEY,
			JSON.stringify({ v: PREFERENCES_VERSION, colorMode: 'light', density: 'compact' })
		);
		const p = loadPreferences();
		expect(p.colorMode).toBe('light');
		expect(p.density).toBe('compact');
	});

	it('resets on corrupt JSON', () => {
		localStorage.setItem(PREFERENCES_KEY, '{not json');
		expect(loadPreferences()).toEqual(DEFAULT_PREFERENCES);
	});
});

describe('preferences store', () => {
	it('setPreference updates the store and persists with the version tag', () => {
		setPreference('colorMode', 'high-contrast');
		expect(get(preferences).colorMode).toBe('high-contrast');
		const stored = JSON.parse(localStorage.getItem(PREFERENCES_KEY)!);
		expect(stored.v).toBe(PREFERENCES_VERSION);
		expect(stored.colorMode).toBe('high-contrast');
	});

	it('setTerminalFontSize clamps to the bounded range', () => {
		setTerminalFontSize(999);
		expect(get(preferences).terminalFontSize).toBe(TERMINAL_FONT_SIZE_MAX);
		setTerminalFontSize(1);
		expect(get(preferences).terminalFontSize).toBe(TERMINAL_FONT_SIZE_MIN);
	});

	it('resetPreferences returns every field to default', () => {
		setPreference('colorMode', 'light');
		setPreference('density', 'compact');
		resetPreferences();
		expect(get(preferences)).toEqual(DEFAULT_PREFERENCES);
	});
});

describe('notice acknowledgement', () => {
	it('is unacknowledged by default', () => {
		expect(isNoticeAcknowledged(get(preferences))).toBe(false);
	});

	it('acknowledgeNotice records the current version and a timestamp', () => {
		acknowledgeNotice();
		const ack = get(preferences).noticeAck!;
		expect(ack.version).toBe(NOTICE_VERSION);
		expect(typeof ack.timestamp).toBe('string');
		expect(isNoticeAcknowledged(get(preferences))).toBe(true);
	});

	it('treats a stale notice version as unacknowledged', () => {
		setPreference('noticeAck', { version: 'stale', timestamp: 't' });
		expect(isNoticeAcknowledged(get(preferences))).toBe(false);
	});
});

describe('applyPreferenceEffects', () => {
	it('writes the presentation preferences as data attributes on <html>', () => {
		applyPreferenceEffects({
			...DEFAULT_PREFERENCES,
			colorMode: 'light',
			density: 'compact',
			motion: 'reduced'
		});
		const el = document.documentElement;
		expect(el.getAttribute('data-color-mode')).toBe('light');
		expect(el.getAttribute('data-density')).toBe('compact');
		expect(el.getAttribute('data-motion')).toBe('reduced');
	});
});
