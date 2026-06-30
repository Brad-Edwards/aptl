import { describe, it, expect, beforeEach } from 'vitest';
import { getFocusable, createFocusTrap } from '../../../src/lib/components/kit/focus-trap';

function mount(html: string): HTMLElement {
	const container = document.createElement('div');
	container.tabIndex = -1;
	container.innerHTML = html;
	document.body.appendChild(container);
	return container;
}

describe('getFocusable', () => {
	beforeEach(() => {
		document.body.innerHTML = '';
	});

	it('returns focusable elements in DOM order, skipping disabled and tabindex=-1', () => {
		const container = mount(
			`<button>a</button><button disabled>b</button><a href="#">c</a><div tabindex="-1">d</div><input />`
		);
		expect(getFocusable(container).map((el) => el.tagName)).toEqual(['BUTTON', 'A', 'INPUT']);
	});

	it('skips hidden and aria-hidden elements', () => {
		const container = mount(
			`<button hidden>a</button><button aria-hidden="true">b</button><button>c</button>`
		);
		const focusable = getFocusable(container);
		expect(focusable).toHaveLength(1);
		expect(focusable[0].textContent).toBe('c');
	});
});

describe('createFocusTrap', () => {
	beforeEach(() => {
		document.body.innerHTML = '';
	});

	it('wraps Tab from the last element to the first', () => {
		const container = mount(
			`<button id="first">f</button><button id="mid">m</button><button id="last">l</button>`
		);
		const trap = createFocusTrap(container);
		trap.activate();

		container.querySelector<HTMLElement>('#last')!.focus();
		container.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
		expect(document.activeElement).toBe(container.querySelector('#first'));
		trap.deactivate();
	});

	it('wraps Shift+Tab from the first element to the last', () => {
		const container = mount(
			`<button id="first">f</button><button id="last">l</button>`
		);
		const trap = createFocusTrap(container);
		trap.activate();

		container.querySelector<HTMLElement>('#first')!.focus();
		container.dispatchEvent(
			new KeyboardEvent('keydown', { key: 'Tab', shiftKey: true, bubbles: true })
		);
		expect(document.activeElement).toBe(container.querySelector('#last'));
		trap.deactivate();
	});

	it('deactivate removes the keydown handler', () => {
		const container = mount(`<button id="first">f</button><button id="last">l</button>`);
		const trap = createFocusTrap(container);
		trap.activate();
		trap.deactivate();

		const last = container.querySelector<HTMLElement>('#last')!;
		last.focus();
		container.dispatchEvent(new KeyboardEvent('keydown', { key: 'Tab', bubbles: true }));
		expect(document.activeElement).toBe(last);
	});
});
