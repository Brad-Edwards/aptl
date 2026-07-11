<script lang="ts">
	import type { AppConfig } from '$lib/types';
	import { preferences } from '$lib/stores/preferences';

	interface Props {
		config: AppConfig;
	}

	let { config }: Props = $props();

	const enabledFamilies = $derived(
		Object.entries(config.containers)
			.filter(([, on]) => on)
			.map(([name]) => name)
	);

	// Density honoured on this shipped surface: compact tightens the row rhythm.
	const rowPad = $derived($preferences.density === 'compact' ? 'py-1' : 'py-2');

	const publicOrigin = $derived(config.web.public_origin ?? 'default (loopback)');
	const allowedHosts = $derived(
		config.web.allowed_hosts.length > 0 ? config.web.allowed_hosts.join(', ') : '—'
	);
	const enabledFamiliesLabel = $derived(
		enabledFamilies.length > 0 ? enabledFamilies.join(', ') : 'none'
	);
</script>

<div class="space-y-8">
	<section>
		<h2 class="mb-2 text-sm font-semibold text-aptl-text">Lab profile</h2>
		<dl class="divide-y divide-aptl-border border-y border-aptl-border text-sm">
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Name</dt>
				<dd class="text-right font-medium text-aptl-text">{config.lab_name}</dd>
			</div>
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Network subnet</dt>
				<dd class="text-right font-mono text-aptl-text">{config.network_subnet}</dd>
			</div>
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Run storage</dt>
				<dd class="text-right text-aptl-text">{config.run_storage_backend}</dd>
			</div>
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Enabled families</dt>
				<dd class="text-right text-aptl-text">{enabledFamiliesLabel}</dd>
			</div>
		</dl>
	</section>

	<section>
		<h2 class="mb-2 text-sm font-semibold text-aptl-text">Web serve</h2>
		<dl class="divide-y divide-aptl-border border-y border-aptl-border text-sm">
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Build version</dt>
				<dd class="text-right font-mono text-aptl-text">{config.web.build_version}</dd>
			</div>
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Allowed hosts</dt>
				<dd class="text-right font-mono text-aptl-text">{allowedHosts}</dd>
			</div>
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Public origin</dt>
				<dd class="text-right font-mono text-aptl-text">{publicOrigin}</dd>
			</div>
			<div class="flex justify-between gap-6 {rowPad}">
				<dt class="text-aptl-text-muted">Deployment provider</dt>
				<dd class="text-right text-aptl-text">{config.web.deployment_provider}</dd>
			</div>
		</dl>
	</section>

	<section>
		<h2 class="mb-2 text-sm font-semibold text-aptl-text">Secrets</h2>
		<p
			class="rounded-lg border border-aptl-border bg-aptl-bg p-3 text-sm text-aptl-text-muted"
			role="note"
		>
			Tokens, private keys, generated secrets, and service credentials are intentionally hidden.
			This page is read-only.
		</p>
	</section>
</div>
