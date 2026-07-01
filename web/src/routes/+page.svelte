<script lang="ts">
	import { labStatus, labLoading, refreshLabStatus } from '$lib/stores/lab';
	import { startLab, stopLab, killLab } from '$lib/api';
	import Button from '$lib/components/kit/Button.svelte';
	import StatusBadge from '$lib/components/kit/StatusBadge.svelte';
	import type { Tone } from '$lib/components/kit/tone';
	import ContainerGrid from '$lib/components/ContainerGrid.svelte';
	import LabStartNotice from '$lib/components/LabStartNotice.svelte';
	import KillConfirmDialog from '$lib/components/KillConfirmDialog.svelte';
	import ScenarioCard from '$lib/components/ScenarioCard.svelte';
	import type { LabActionResponse, KillActionResponse, ScenarioSummary } from '$lib/types';

	let { data }: { data: { scenarios: ScenarioSummary[]; scenariosError: boolean } } = $props();

	/** Which lifecycle action is in flight, if any. Lifecycle controls are
	 *  single-flight: while one action is pending, start/stop/kill are disabled. */
	let pendingAction = $state<null | 'start' | 'stop' | 'kill'>(null);
	let actionPending = $derived(pendingAction !== null);
	let actionError = $state('');
	/** Last /api/lab/start response — populated for both success and failure so
	 *  the UI can render ADR-030 partial-readiness data (outcome + diagnostics)
	 *  via `LabStartNotice`, not only the legacy success boolean. */
	let startResult = $state<LabActionResponse | null>(null);
	/** Last /api/lab/kill response — its own envelope (processes killed, whether
	 *  containers were also stopped), distinct from the start/stop response. */
	let killResult = $state<KillActionResponse | null>(null);
	let killDialogOpen = $state(false);

	/** Readiness headline: leads with whether the lab is usable and what to do
	 *  next. Derived from the running flag plus the in-session start outcome —
	 *  never inferred from container health, colours, or backend message text
	 *  (ADR-030 outcome lives only on the start response, by design). */
	let readiness = $derived.by((): { tone: Tone; label: string; next: string } => {
		if (pendingAction === 'start') {
			return { tone: 'info', label: 'Starting…', next: 'Bringing the lab up — this can take a few minutes.' };
		}
		if (pendingAction === 'stop') {
			return { tone: 'info', label: 'Stopping…', next: 'Shutting the lab down.' };
		}
		if (pendingAction === 'kill') {
			return { tone: 'danger', label: 'Killing…', next: 'Terminating MCP processes and clearing session state.' };
		}
		const outcome = startResult?.outcome;
		if (outcome === 'failed' || startResult?.success === false) {
			return { tone: 'danger', label: 'Start failed', next: 'Review the diagnostics below, then try again.' };
		}
		if (outcome === 'degraded_unusable') {
			return { tone: 'warning', label: 'Degraded — unusable', next: 'Some capabilities or SSH targets are unreachable; see diagnostics.' };
		}
		if (outcome === 'degraded_usable') {
			return { tone: 'warning', label: 'Degraded — usable', next: 'Scenarios should still run; see diagnostics below.' };
		}
		if ($labStatus.running) {
			return {
				tone: 'success',
				label: outcome === 'ready' ? 'Lab ready' : 'Lab running',
				next: 'Pick a scenario below to begin.'
			};
		}
		return { tone: 'neutral', label: 'Lab stopped', next: 'Start the lab to begin.' };
	});

	async function runAction(
		action: 'start' | 'stop' | 'kill',
		fn: () => Promise<void>
	): Promise<void> {
		if (actionPending) return;
		pendingAction = action;
		actionError = '';
		try {
			await fn();
		} catch (err) {
			actionError = String(err);
		} finally {
			pendingAction = null;
			// Reconcile against the authoritative status after every action.
			await refreshLabStatus();
		}
	}

	function handleStart(): Promise<void> {
		startResult = null;
		killResult = null;
		return runAction('start', async () => {
			// `LabStartNotice` owns the structured rendering for every non-trivial
			// start outcome; `actionError` is reserved for fetch/transport failures.
			startResult = await startLab();
		});
	}

	function handleStop(): Promise<void> {
		startResult = null;
		killResult = null;
		return runAction('stop', async () => {
			const result = await stopLab();
			if (!result.success) {
				actionError = result.error || 'Lab stop failed';
			}
		});
	}

	function handleKillConfirm(containers: boolean): Promise<void> {
		killDialogOpen = false;
		startResult = null;
		killResult = null;
		return runAction('kill', async () => {
			killResult = await killLab(containers);
		});
	}

	let killSummary = $derived.by((): string => {
		if (!killResult) return '';
		const parts = [`${killResult.mcp_processes_killed} MCP process(es) terminated`];
		parts.push(killResult.containers_stopped ? 'containers stopped' : 'containers left running');
		if (killResult.session_cleared) parts.push('session cleared');
		return parts.join(' · ');
	});
</script>

<div class="mx-auto max-w-7xl space-y-8 px-6 py-8">
	<!-- Lab Status Section -->
	<section>
		<div class="mb-4 flex flex-wrap items-start justify-between gap-3">
			<div>
				<h1 class="text-xl font-semibold text-aptl-text">Lab Home</h1>
				<div class="mt-2 flex flex-wrap items-center gap-3">
					<StatusBadge tone={readiness.tone} label={readiness.label} pulse={pendingAction !== null} />
					<p class="text-sm text-aptl-text-muted">{readiness.next}</p>
				</div>
			</div>
			<div class="flex items-center gap-2">
				{#if $labStatus.running}
					<Button variant="secondary" disabled={actionPending} onclick={handleStop}>
						{pendingAction === 'stop' ? 'Stopping…' : 'Stop'}
					</Button>
				{:else}
					<Button variant="primary" disabled={actionPending} onclick={handleStart}>
						{pendingAction === 'start' ? 'Starting…' : 'Start'}
					</Button>
				{/if}
				<Button
					variant="danger"
					disabled={actionPending}
					onclick={() => (killDialogOpen = true)}
				>
					Kill
				</Button>
			</div>
		</div>

		{#if actionError}
			<div
				class="mb-4 rounded-lg border border-aptl-red/20 bg-aptl-red/5 p-3 text-sm text-aptl-red"
				role="alert"
			>
				{actionError}
			</div>
		{/if}

		{#if killResult}
			<div
				role="status"
				aria-label="Kill result"
				class="mb-4 rounded-lg border p-3 text-sm {killResult.success && killResult.errors.length === 0
					? 'border-aptl-border bg-aptl-bg text-aptl-text'
					: 'border-aptl-red/30 bg-aptl-red/5 text-aptl-red'}"
			>
				<p class="font-medium">Kill complete — {killSummary}</p>
				{#if killResult.errors.length > 0}
					<ul class="mt-1 space-y-0.5 text-xs">
						{#each killResult.errors as err (err)}
							<li>{err}</li>
						{/each}
					</ul>
				{/if}
			</div>
		{/if}

		<LabStartNotice result={startResult} />

		{#if $labStatus.error != null && !actionError}
			<div
				class="mb-4 rounded-lg border border-aptl-amber/20 bg-aptl-amber/5 p-3 text-sm text-aptl-amber"
				role="status"
			>
				{$labStatus.error}
			</div>
		{/if}

		<h2 class="mb-3 text-lg font-semibold text-aptl-text">Containers</h2>
		{#if $labLoading}
			<div class="flex items-center justify-center py-12" role="status" aria-label="Loading lab status">
				<div
					class="h-8 w-8 animate-spin rounded-full border-2 border-aptl-indigo border-t-transparent"
				></div>
				<span class="sr-only">Loading lab status</span>
			</div>
		{:else}
			<ContainerGrid containers={$labStatus.containers} />
		{/if}
	</section>

	<!-- Scenarios Section -->
	<section>
		<div class="mb-4">
			<h2 class="text-lg font-semibold text-aptl-text">Scenarios</h2>
			<p class="mt-1 text-sm text-aptl-text-muted">Available attack and defense scenarios</p>
		</div>

		{#if data.scenariosError}
			<div
				class="rounded-lg border border-aptl-amber/20 bg-aptl-amber/5 p-8 text-center text-sm text-aptl-amber"
				role="status"
			>
				Scenario catalog is currently unavailable.
			</div>
		{:else if data.scenarios.length === 0}
			<div class="rounded-lg border border-dashed border-aptl-border p-8 text-center">
				<p class="text-sm text-aptl-text-muted">No scenarios found</p>
			</div>
		{:else}
			<div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
				{#each data.scenarios as scenario (scenario.id)}
					<ScenarioCard {scenario} />
				{/each}
			</div>
		{/if}
	</section>
</div>

<KillConfirmDialog
	bind:open={killDialogOpen}
	pending={pendingAction === 'kill'}
	onConfirm={handleKillConfirm}
	onCancel={() => (killDialogOpen = false)}
/>
