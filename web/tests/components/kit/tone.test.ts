import { describe, it, expect } from 'vitest';
import {
	toneSoft,
	toneDot,
	buttonVariant,
	buttonSize,
	focusRing,
	type Tone,
	type ButtonVariant,
	type ButtonSize
} from '../../../src/lib/components/kit/tone';

const TONES: Tone[] = ['neutral', 'info', 'success', 'warning', 'danger', 'accent'];

describe('tone recipes', () => {
	it('defines a soft and dot recipe for every tone, built on aptl tokens', () => {
		for (const tone of TONES) {
			expect(toneSoft[tone]).toBeTruthy();
			expect(toneDot[tone]).toBeTruthy();
			expect(toneSoft[tone]).toMatch(/aptl-/);
			expect(toneDot[tone]).toMatch(/^bg-aptl-/);
		}
	});

	it('maps semantic status to the expected palette tokens', () => {
		expect(toneSoft.success).toContain('aptl-green');
		expect(toneSoft.danger).toContain('aptl-red');
		expect(toneSoft.warning).toContain('aptl-amber');
		expect(toneSoft.info).toContain('aptl-indigo');
		expect(toneSoft.accent).toContain('aptl-violet');
		expect(toneDot.success).toBe('bg-aptl-green');
	});

	it('defines every button variant and size, with danger on the red token', () => {
		const variants: ButtonVariant[] = ['primary', 'secondary', 'ghost', 'danger'];
		const sizes: ButtonSize[] = ['sm', 'md'];
		for (const variant of variants) expect(buttonVariant[variant]).toBeTruthy();
		for (const size of sizes) expect(buttonSize[size]).toBeTruthy();
		expect(buttonVariant.danger).toContain('aptl-red');
		expect(buttonVariant.primary).toContain('aptl-indigo');
	});

	it('focus ring is keyboard-only and uses the named focus token', () => {
		expect(focusRing).toContain('focus-visible:');
		expect(focusRing).toContain('ring-aptl-focus');
		expect(focusRing).not.toContain('focus:ring'); // not on mouse focus
	});
});
