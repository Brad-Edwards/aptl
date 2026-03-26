import { describe, it, expect } from 'vitest';
import { stateColor } from '../../src/lib/container-state';

describe('stateColor', () => {
	it('returns green for running state', () => {
		expect(stateColor('running')).toBe('bg-aptl-green');
	});

	it('returns red for exited state', () => {
		expect(stateColor('exited')).toBe('bg-aptl-red');
	});

	it('returns red for dead state', () => {
		expect(stateColor('dead')).toBe('bg-aptl-red');
	});

	it('returns amber for unknown/other states', () => {
		expect(stateColor('created')).toBe('bg-aptl-amber');
		expect(stateColor('paused')).toBe('bg-aptl-amber');
		expect(stateColor('restarting')).toBe('bg-aptl-amber');
		expect(stateColor('unknown')).toBe('bg-aptl-amber');
	});
});
