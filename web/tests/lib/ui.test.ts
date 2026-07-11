import { describe, it, expect, beforeEach, vi } from 'vitest';
import { get } from 'svelte/store';
import {
	settingsOpen,
	privacyOpen,
	noticeOpen,
	openSettings,
	openPrivacy,
	guardControlledAction,
	acknowledgeAndRun,
	dismissNotice
} from '../../src/lib/stores/ui';
import {
	preferences,
	resetPreferences,
	isNoticeAcknowledged,
	NOTICE_VERSION
} from '../../src/lib/stores/preferences';

beforeEach(() => {
	localStorage.clear();
	resetPreferences();
	settingsOpen.set(false);
	privacyOpen.set(false);
	noticeOpen.set(false);
});

describe('openSettings / openPrivacy', () => {
	it('open the respective app-shell dialogs', () => {
		openSettings();
		expect(get(settingsOpen)).toBe(true);
		openPrivacy();
		expect(get(privacyOpen)).toBe(true);
	});
});

describe('guardControlledAction', () => {
	it('runs immediately when the notice is already acknowledged', () => {
		preferences.update((p) => ({
			...p,
			noticeAck: { version: NOTICE_VERSION, timestamp: 't' }
		}));
		const run = vi.fn();
		guardControlledAction(run);
		expect(run).toHaveBeenCalledOnce();
		expect(get(noticeOpen)).toBe(false);
	});

	it('defers the action and opens the notice when not acknowledged', () => {
		const run = vi.fn();
		guardControlledAction(run);
		expect(run).not.toHaveBeenCalled();
		expect(get(noticeOpen)).toBe(true);
	});
});

describe('acknowledgeAndRun', () => {
	it('acknowledges, runs the deferred action, and closes the notice', () => {
		const run = vi.fn();
		guardControlledAction(run);
		acknowledgeAndRun();
		expect(run).toHaveBeenCalledOnce();
		expect(get(noticeOpen)).toBe(false);
		expect(isNoticeAcknowledged(get(preferences))).toBe(true);
	});

	it('is a no-op action-wise when nothing was deferred', () => {
		acknowledgeAndRun();
		expect(get(noticeOpen)).toBe(false);
		expect(isNoticeAcknowledged(get(preferences))).toBe(true);
	});
});

describe('dismissNotice', () => {
	it('drops the deferred action and closes the notice', () => {
		const run = vi.fn();
		guardControlledAction(run);
		dismissNotice();
		// A later acknowledgement must not resurrect the discarded action.
		acknowledgeAndRun();
		expect(run).not.toHaveBeenCalled();
		expect(get(noticeOpen)).toBe(false);
	});
});
