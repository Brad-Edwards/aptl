<script lang="ts">
	import type { AttackStep } from '$lib/types';
	import TerminalBlock from './TerminalBlock.svelte';

	interface Props {
		step: AttackStep;
		stepIndex: number;
	}

	let { step, stepIndex }: Props = $props();

	let copiedIdx = $state<number | null>(null);

	async function copyCommand(cmd: string, idx: number) {
		try {
			await navigator.clipboard.writeText(cmd);
			copiedIdx = idx;
			setTimeout(() => {
				copiedIdx = null;
			}, 2000);
		} catch {
			// Clipboard API may not be available
		}
	}
</script>

<div class="rounded-lg border border-aptl-border bg-aptl-surface p-5">
	<!-- Header -->
	<div class="mb-3 flex flex-wrap items-start gap-3">
		<span
			class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-aptl-indigo text-xs font-bold text-white"
		>
			{step.step_number}
		</span>
		<div class="flex-1">
			<h3 class="text-sm font-semibold text-aptl-text">{step.technique_name}</h3>
			<div class="mt-0.5 flex flex-wrap gap-2 text-xs text-aptl-text-muted">
				<span class="font-mono">{step.technique_id}</span>
				<span>&middot;</span>
				<span>{step.tactic}</span>
				{#if step.vulnerability}
					<span>&middot;</span>
					<span class="text-aptl-red">{step.vulnerability}</span>
				{/if}
			</div>
		</div>
	</div>

	<!-- Description -->
	<p class="mb-4 text-sm text-aptl-text-muted">{step.description}</p>

	<!-- Commands -->
	{#if step.commands.length > 0}
		<div class="mb-4 space-y-2">
			<span class="text-xs font-medium text-aptl-text-muted">Commands</span>
			{#each step.commands as cmd, i}
				<div class="group relative">
					<pre
						class="overflow-x-auto rounded bg-aptl-bg px-3 py-2 font-mono text-xs text-aptl-text">{cmd}</pre>
					<button
						onclick={() => copyCommand(cmd, i)}
						class="absolute right-2 top-1.5 rounded bg-aptl-surface-hover px-1.5 py-0.5 text-xs text-aptl-text-muted opacity-0 transition-opacity group-hover:opacity-100"
						aria-label="Copy command"
					>
						{copiedIdx === i ? 'Copied' : 'Copy'}
					</button>
				</div>
			{/each}
		</div>
	{/if}

	<!-- Expected Detections -->
	{#if step.expected_detections.length > 0}
		<div class="mb-4">
			<span class="text-xs font-medium text-aptl-text-muted">Expected Detections</span>
			<div class="mt-1 space-y-1">
				{#each step.expected_detections as det}
					<div
						class="flex items-center gap-2 rounded bg-aptl-bg px-3 py-1.5 text-xs"
					>
						<span
							class="rounded bg-aptl-teal/10 px-1.5 py-0.5 font-medium text-aptl-teal"
						>
							{det.product_name}
						</span>
						<span class="text-aptl-text-muted">{det.description}</span>
						{#if det.analytic_uid}
							<span class="ml-auto font-mono text-aptl-text-muted">
								{det.analytic_uid}
							</span>
						{/if}
					</div>
				{/each}
			</div>
		</div>
	{/if}

	<!-- Investigation hints -->
	{#if step.investigation_hints.length > 0}
		<div class="mb-4">
			<span class="text-xs font-medium text-aptl-text-muted">Investigation Hints</span>
			<ul class="mt-1 list-inside list-disc space-y-0.5 text-xs text-aptl-text-muted">
				{#each step.investigation_hints as hint}
					<li>{hint}</li>
				{/each}
			</ul>
		</div>
	{/if}

	<!-- Remediation -->
	{#if step.remediation.length > 0}
		<div class="mb-4">
			<span class="text-xs font-medium text-aptl-text-muted">Remediation</span>
			<ul class="mt-1 list-inside list-disc space-y-0.5 text-xs text-aptl-text-muted">
				{#each step.remediation as item}
					<li>{item}</li>
				{/each}
			</ul>
		</div>
	{/if}

	<!-- Embedded terminal for target container -->
	{#if step.target}
		<TerminalBlock container={step.target} label="Terminal: {step.target}" />
	{/if}
</div>
