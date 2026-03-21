import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import HintToggle from '../../src/lib/components/workbench/HintToggle.svelte';

describe('HintToggle', () => {
	const hints = [
		{ level: 1, text: 'First hint', point_penalty: 0 },
		{ level: 2, text: 'Second hint', point_penalty: 10 },
		{ level: 3, text: 'Third hint', point_penalty: 25 }
	];

	it('shows a reveal button when hints exist', () => {
		render(HintToggle, { props: { hints, objectiveId: 'obj-1' } });
		expect(screen.getByRole('button', { name: /reveal hint 1/i })).toBeTruthy();
	});

	it('does not show hints initially', () => {
		render(HintToggle, { props: { hints, objectiveId: 'obj-1' } });
		expect(screen.queryByText('First hint')).toBeNull();
	});

	it('reveals first hint on click', async () => {
		render(HintToggle, { props: { hints, objectiveId: 'obj-1' } });
		await fireEvent.click(screen.getByRole('button', { name: /reveal hint 1/i }));
		expect(screen.getByText('First hint')).toBeTruthy();
	});

	it('progressively reveals hints in level order', async () => {
		render(HintToggle, { props: { hints, objectiveId: 'obj-1' } });

		// Reveal hint 1
		await fireEvent.click(screen.getByRole('button', { name: /reveal hint 1/i }));
		expect(screen.getByText('First hint')).toBeTruthy();
		expect(screen.queryByText('Second hint')).toBeNull();

		// Reveal hint 2
		await fireEvent.click(screen.getByRole('button', { name: /reveal hint 2/i }));
		expect(screen.getByText('Second hint')).toBeTruthy();
		expect(screen.queryByText('Third hint')).toBeNull();

		// Reveal hint 3
		await fireEvent.click(screen.getByRole('button', { name: /reveal hint 3/i }));
		expect(screen.getByText('Third hint')).toBeTruthy();
	});

	it('displays point penalty for penalized hints', async () => {
		render(HintToggle, { props: { hints, objectiveId: 'obj-1' } });

		// Button for hint 1 (0 penalty) should not show penalty
		const btn1 = screen.getByRole('button', { name: /reveal hint 1/i });
		expect(btn1.textContent).not.toContain('pts');

		// Reveal hint 1, then hint 2 button should show penalty
		await fireEvent.click(btn1);
		const btn2 = screen.getByRole('button', { name: /reveal hint 2/i });
		expect(btn2.textContent).toContain('-10 pts');
	});

	it('hides button after all hints revealed', async () => {
		render(HintToggle, {
			props: {
				hints: [{ level: 1, text: 'Only hint', point_penalty: 0 }],
				objectiveId: 'obj-1'
			}
		});

		await fireEvent.click(screen.getByRole('button', { name: /reveal hint 1/i }));
		expect(screen.queryByRole('button')).toBeNull();
	});

	it('renders nothing for empty hints', () => {
		const { container } = render(HintToggle, {
			props: { hints: [], objectiveId: 'obj-1' }
		});
		expect(container.textContent?.trim()).toBe('');
	});
});
