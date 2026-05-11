import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import LabStartNotice from '../../src/lib/components/LabStartNotice.svelte';
import type { LabActionResponse } from '../../src/lib/types';

const READY: LabActionResponse = {
	success: true,
	message: 'Lab started successfully',
	error: null,
	outcome: 'ready',
	diagnostics: []
};

const DEGRADED_USABLE: LabActionResponse = {
	success: true,
	message: 'Lab started with outcome=degraded_usable',
	error: null,
	outcome: 'degraded_usable',
	diagnostics: [
		{
			step: 'wait_for_services',
			component: 'wazuh_indexer',
			impact: 'telemetry',
			severity: 'warning',
			message: 'Indexer did not become ready within 300s',
			operator_action: 'Check indexer container logs'
		}
	]
};

const DEGRADED_UNUSABLE: LabActionResponse = {
	success: true,
	message: 'Lab started with outcome=degraded_unusable',
	error: null,
	outcome: 'degraded_unusable',
	diagnostics: [
		{
			step: 'test_ssh',
			component: 'ssh:kali',
			impact: 'readiness',
			severity: 'warning',
			message: 'SSH to kali not ready after 60s'
		},
		{
			step: 'build_mcps',
			impact: 'capability',
			severity: 'warning',
			message: 'MCP build returned non-zero exit; see lab logs'
		}
	]
};

const FAILED: LabActionResponse = {
	success: false,
	message: '',
	error: 'vm.max_map_count too low',
	outcome: 'failed',
	diagnostics: []
};

describe('LabStartNotice', () => {
	it('renders nothing when result is null', () => {
		const { container } = render(LabStartNotice, { props: { result: null } });
		expect(container.textContent?.trim()).toBe('');
	});

	it('renders nothing for a clean ready run with no diagnostics', () => {
		const { container } = render(LabStartNotice, { props: { result: READY } });
		expect(container.textContent?.trim()).toBe('');
	});

	it('renders a headline + telemetry row for degraded_usable', () => {
		render(LabStartNotice, { props: { result: DEGRADED_USABLE } });

		expect(screen.getByRole('status').getAttribute('aria-label')).toContain(
			'degraded_usable'
		);
		expect(screen.getByText(/degraded_usable/i)).toBeTruthy();
		expect(screen.getByText(/wait_for_services\/wazuh_indexer/)).toBeTruthy();
		expect(screen.getByText(/\[telemetry\|warning\]/)).toBeTruthy();
		expect(screen.getByText(/Check indexer container logs/)).toBeTruthy();
	});

	it('renders both readiness + capability rows for degraded_unusable', () => {
		render(LabStartNotice, { props: { result: DEGRADED_UNUSABLE } });

		expect(screen.getByText(/degraded_unusable/i)).toBeTruthy();
		// Both impact buckets are visible.
		expect(screen.getByText(/\[readiness\|warning\]/)).toBeTruthy();
		expect(screen.getByText(/\[capability\|warning\]/)).toBeTruthy();
		// Step names appear, including the component slash-suffix for ssh.
		expect(screen.getByText(/test_ssh\/ssh:kali/)).toBeTruthy();
		expect(screen.getByText(/build_mcps/)).toBeTruthy();
	});

	it('renders failure with error string for failed outcome', () => {
		render(LabStartNotice, { props: { result: FAILED } });

		expect(screen.getByText(/Lab start failed/)).toBeTruthy();
		expect(screen.getByText(/vm\.max_map_count too low/)).toBeTruthy();
	});

	it('renders legacy success=false shape even when outcome+diagnostics are absent', () => {
		// Older /api/lab/start builds (and the timeout branch on the
		// current build, which intentionally omits a terminal outcome
		// because the worker thread cannot be cancelled) return
		// `{success: false, error: "..."}` with no ADR-030 fields. The
		// notice must still surface the failure or the UI silently
		// swallows it (codex review #202 cycle 4).
		const legacyFailure: LabActionResponse = {
			success: false,
			message: '',
			error: 'Lab start timed out after 1800s'
			// outcome and diagnostics omitted
		};

		render(LabStartNotice, { props: { result: legacyFailure } });

		expect(screen.getByText(/Lab start failed/)).toBeTruthy();
		expect(screen.getByText(/timed out after 1800s/)).toBeTruthy();
	});

	it('still renders when outcome is ready but diagnostics non-empty', () => {
		// Unusual but possible — a future step might emit a `cosmetic info`
		// without affecting outcome. Diagnostics still surface.
		const result: LabActionResponse = {
			success: true,
			message: 'Lab started successfully',
			error: null,
			outcome: 'ready',
			diagnostics: [
				{
					step: 'pull_images',
					impact: 'cosmetic',
					severity: 'info',
					message: 'Pre-pull failed for 1 image(s); compose will pull on demand'
				}
			]
		};

		render(LabStartNotice, { props: { result } });

		// Notice is interesting because diagnostics non-empty.
		expect(screen.getByText(/\[cosmetic\|info\]/)).toBeTruthy();
		expect(screen.getByText(/pull_images/)).toBeTruthy();
	});
});
