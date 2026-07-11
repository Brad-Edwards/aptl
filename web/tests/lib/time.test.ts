import { describe, it, expect } from 'vitest';
import { formatTimestamp, resolveLocale } from '../../src/lib/time';

describe('resolveLocale', () => {
	it('maps system/empty to undefined and passes tags through', () => {
		expect(resolveLocale('system')).toBeUndefined();
		expect(resolveLocale('')).toBeUndefined();
		expect(resolveLocale('en-GB')).toBe('en-GB');
	});
});

describe('formatTimestamp', () => {
	const iso = '2026-01-02T03:04:05Z';

	it('formats a UTC instant with a trailing UTC marker', () => {
		const out = formatTimestamp(iso, { timeDisplay: 'utc', locale: 'en' });
		expect(out).toContain('2026');
		expect(out.endsWith('UTC')).toBe(true);
	});

	it('formats local time without a UTC marker', () => {
		const out = formatTimestamp(iso, { timeDisplay: 'local', locale: 'en' });
		expect(out).toContain('2026');
		expect(out.endsWith('UTC')).toBe(false);
	});

	it('returns an empty string for an unparseable instant', () => {
		expect(formatTimestamp('not-a-date', { timeDisplay: 'local', locale: 'system' })).toBe('');
	});
});
