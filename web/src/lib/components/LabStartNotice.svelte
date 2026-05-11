<script lang="ts">
	import type { LabActionResponse, StartupDiagnostic } from '../types';

	interface Props {
		/** The most recent /api/lab/start response, or null when nothing has run. */
		result: LabActionResponse | null;
	}

	let { result }: Props = $props();

	/** ADR-030 headline phrasing — keep in sync with `src/aptl/cli/lab.py::_OUTCOME_HEADLINES`. */
	const OUTCOME_HEADLINE: Record<string, string> = {
		ready: 'Lab is ready.',
		degraded_usable:
			'Lab is degraded_usable — telemetry/cosmetic warnings, scenarios should still run.',
		degraded_unusable:
			'Lab is degraded_unusable — some capabilities or SSH targets are not reachable.',
		failed: 'Lab start failed.'
	};

	/** Hide the notice for clean ready runs with no diagnostics.
	 *
	 *  Renders for any of:
	 *    - explicit non-`ready` outcome,
	 *    - non-empty diagnostics list,
	 *    - legacy `success === false` shape (older API builds, the
	 *      `/api/lab/start` timeout branch, or any path that returns a
	 *      failure envelope without the optional ADR-030 fields). The
	 *      legacy shape must surface visibly — silently swallowing it
	 *      would regress the pre-ADR-030 UI (codex review #202 cycle 4).
	 */
	function isInteresting(r: LabActionResponse | null): boolean {
		if (!r) return false;
		if (r.success === false) return true;
		if (r.diagnostics && r.diagnostics.length > 0) return true;
		return Boolean(r.outcome) && r.outcome !== 'ready';
	}

	/** Group by impact in the same severity order the CLI uses. */
	function groupDiagnostics(
		diagnostics: StartupDiagnostic[] | undefined
	): Array<[string, StartupDiagnostic[]]> {
		const order = ['readiness', 'capability', 'telemetry', 'cosmetic'];
		const buckets: Record<string, StartupDiagnostic[]> = {};
		for (const d of diagnostics ?? []) {
			(buckets[d.impact] ??= []).push(d);
		}
		return order
			.filter((impact) => buckets[impact]?.length)
			.map((impact) => [impact, buckets[impact]] as [string, StartupDiagnostic[]]);
	}

	let visible = $derived(isInteresting(result));
	/** Pick the rendering key: explicit ``outcome`` when present;
	 *  otherwise ``'failed'`` for the legacy ``success=false`` fallback;
	 *  otherwise the empty string (notice hidden). */
	let outcomeKey = $derived(
		result?.outcome ?? (result?.success === false ? 'failed' : '')
	);
	let headline = $derived(OUTCOME_HEADLINE[outcomeKey] ?? '');
	let grouped = $derived(groupDiagnostics(result?.diagnostics));

	/** Border/background palette per outcome — `failed` is the
	 *  hardest signal; `degraded_unusable` is amber; `degraded_usable`
	 *  is amber-lite; `ready` (with diagnostics? unusual) stays neutral. */
	function classesFor(outcome: string): string {
		switch (outcome) {
			case 'failed':
				return 'border-aptl-red/30 bg-aptl-red/5 text-aptl-red';
			case 'degraded_unusable':
				return 'border-aptl-amber/30 bg-aptl-amber/10 text-aptl-amber';
			case 'degraded_usable':
				return 'border-aptl-amber/20 bg-aptl-amber/5 text-aptl-amber';
			default:
				return 'border-aptl-border bg-aptl-bg text-aptl-text';
		}
	}
</script>

{#if visible && result}
	<div
		role="status"
		aria-label="Lab start result: {outcomeKey}"
		class="mb-4 rounded-lg border p-3 text-sm {classesFor(outcomeKey)}"
	>
		<p class="font-medium">{headline}</p>
		{#if outcomeKey === 'failed' && result.error}
			<p class="mt-1 text-xs opacity-80">error: {result.error}</p>
		{/if}
		{#if result.diagnostics && result.diagnostics.length > 0}
			<p class="mt-2 text-xs font-medium">
				diagnostics ({result.diagnostics.length}):
			</p>
			<ul class="mt-1 space-y-1 text-xs">
				{#each grouped as [impact, items] (impact)}
					{#each items as diag (diag.step + (diag.component ?? ''))}
						<li>
							<span class="font-mono">[{diag.impact}|{diag.severity}]</span>
							{diag.step}{diag.component ? `/${diag.component}` : ''} — {diag.message}
							{#if diag.operator_action}
								<div class="ml-4 text-xs opacity-70">
									action: {diag.operator_action}
								</div>
							{/if}
						</li>
					{/each}
				{/each}
			</ul>
		{/if}
	</div>
{/if}
