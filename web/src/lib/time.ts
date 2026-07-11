/**
 * Shared timestamp formatting (UI-008f, localization groundwork).
 *
 * The design spec requires dates/times to be formatted through shared helpers
 * that honour the operator's time-display and locale preferences, rather than
 * scattering `toLocaleString` calls (or hard-coded formats) through routes. This
 * is the single formatter; surfaces that render timestamps (SIEM alerts, run
 * status, diagnostics, the privacy panel's acknowledgement line) route through
 * it so a preference change applies everywhere at once.
 */
import type { TimeDisplay } from './stores/preferences';

/** Map a stored locale preference to an `Intl` locale (or `undefined` = default). */
export function resolveLocale(locale: string): string | undefined {
	return locale && locale !== 'system' ? locale : undefined;
}

/**
 * Format an ISO-8601 instant per the operator's preferences.
 *
 * `timeDisplay: 'utc'` renders the instant in UTC with a trailing `UTC` marker;
 * `'local'` uses the browser time zone. `locale` is a BCP-47 tag or `'system'`.
 * Returns `''` for an unparseable input so callers can render an empty cell
 * rather than `Invalid Date`.
 */
export function formatTimestamp(
	iso: string,
	opts: { timeDisplay: TimeDisplay; locale: string }
): string {
	const date = new Date(iso);
	if (Number.isNaN(date.getTime())) return '';
	const utc = opts.timeDisplay === 'utc';
	try {
		const formatted = new Intl.DateTimeFormat(resolveLocale(opts.locale), {
			dateStyle: 'medium',
			timeStyle: 'medium',
			timeZone: utc ? 'UTC' : undefined
		}).format(date);
		return utc ? `${formatted} UTC` : formatted;
	} catch {
		// Invalid locale/timeZone combination — fall back to the ISO string.
		return date.toISOString();
	}
}
