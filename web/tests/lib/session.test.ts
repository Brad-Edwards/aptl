import { describe, it, expect, beforeEach } from 'vitest';
import { captureSessionFromHash, getSessionToken, sessionHeaders } from '../../src/lib/session';

describe('session', () => {
	beforeEach(() => {
		sessionStorage.clear();
		history.replaceState(null, '', '/');
	});

	describe('captureSessionFromHash', () => {
		it('stores the token from the fragment and scrubs it from the URL', () => {
			history.replaceState(null, '', '/#aptl_session=tok-abc');

			captureSessionFromHash();

			expect(getSessionToken()).toBe('tok-abc');
			expect(window.location.hash).toBe('');
		});

		it('is a no-op when the fragment has no token', () => {
			history.replaceState(null, '', '/#something=else');

			captureSessionFromHash();

			expect(getSessionToken()).toBeNull();
			// Unrelated fragment params are preserved.
			expect(window.location.hash).toContain('something=else');
		});

		it('preserves other fragment params while removing the token', () => {
			history.replaceState(null, '', '/#aptl_session=tok&keep=1');

			captureSessionFromHash();

			expect(getSessionToken()).toBe('tok');
			expect(window.location.hash).toContain('keep=1');
			expect(window.location.hash).not.toContain('aptl_session');
		});

		it('does nothing when there is no fragment', () => {
			history.replaceState(null, '', '/');

			captureSessionFromHash();

			expect(getSessionToken()).toBeNull();
		});
	});

	describe('getSessionToken', () => {
		it('returns null when no token is stored', () => {
			expect(getSessionToken()).toBeNull();
		});

		it('returns the stored token', () => {
			sessionStorage.setItem('aptl_session', 'stored-tok');
			expect(getSessionToken()).toBe('stored-tok');
		});
	});

	describe('sessionHeaders', () => {
		it('adds the X-APTL-Session header when a token is stored', () => {
			sessionStorage.setItem('aptl_session', 'tok-1');
			const headers = sessionHeaders();
			expect(headers.get('X-APTL-Session')).toBe('tok-1');
		});

		it('omits the header when no token is stored', () => {
			const headers = sessionHeaders();
			expect(headers.has('X-APTL-Session')).toBe(false);
		});

		it('merges onto provided init headers', () => {
			sessionStorage.setItem('aptl_session', 'tok-2');
			const headers = sessionHeaders({ Accept: 'text/event-stream' });
			expect(headers.get('Accept')).toBe('text/event-stream');
			expect(headers.get('X-APTL-Session')).toBe('tok-2');
		});
	});
});
