<script lang="ts">
	import type { ContainerInfo } from '../types';

	interface Props {
		container: ContainerInfo;
	}

	let { container }: Props = $props();

	const stateColor = $derived.by(() => {
		if (container.state === 'running') {
			if (container.health === 'healthy') return 'text-aptl-green';
			if (container.health === 'unhealthy') return 'text-aptl-red';
			return 'text-aptl-amber';
		}
		return 'text-aptl-text-muted';
	});

	const dotColor = $derived.by(() => {
		if (container.state === 'running') {
			if (container.health === 'healthy') return 'bg-aptl-green';
			if (container.health === 'unhealthy') return 'bg-aptl-red';
			return 'bg-aptl-amber';
		}
		return 'bg-aptl-text-muted';
	});

	const statusLabel = $derived.by(() => {
		if (container.state === 'running') {
			if (container.health === 'healthy') return 'healthy';
			if (container.health === 'unhealthy') return 'unhealthy';
			return 'running';
		}
		return 'stopped';
	});

	const SSH_CONTAINERS = new Set(['victim', 'kali', 'reverse', 'workstation']);

	const displayName = $derived(
		container.name.replace(/^aptl-/, '').replace(/-\d+$/, '')
	);

	const showTerminal = $derived(
		container.state === 'running' && SSH_CONTAINERS.has(displayName)
	);
</script>

<div
	class="rounded-lg border border-aptl-border bg-aptl-surface p-4 transition-colors hover:bg-aptl-surface-hover"
>
	<div class="flex items-start justify-between">
		<div class="min-w-0 flex-1">
			<div class="flex items-center gap-2">
				<span class="h-2 w-2 rounded-full {dotColor}" role="img" aria-label="Status: {statusLabel}"></span>
				<h3 class="truncate text-sm font-medium text-aptl-text">
					{displayName}
				</h3>
			</div>
			<p class="mt-1 text-xs {stateColor}">
				{container.state}
				{#if container.health && container.health !== 'N/A'}
					&middot; {container.health}
				{/if}
			</p>
		</div>
	</div>
	<p class="mt-2 truncate font-mono text-xs text-aptl-text-muted">
		{container.image}
	</p>
	{#if container.ports.length > 0}
		<div class="mt-2 flex flex-wrap gap-1">
			{#each container.ports.slice(0, 3) as port}
				<span
					class="rounded bg-aptl-indigo/10 px-1.5 py-0.5 font-mono text-xs text-aptl-indigo"
				>
					{port}
				</span>
			{/each}
			{#if container.ports.length > 3}
				<span class="text-xs text-aptl-text-muted">
					+{container.ports.length - 3} more
				</span>
			{/if}
		</div>
	{/if}
	{#if showTerminal}
		<div class="mt-2">
			<a
				href="/terminal/{displayName}"
				class="text-xs font-medium text-aptl-indigo transition-colors hover:text-aptl-indigo-hover"
			>
				Terminal
			</a>
		</div>
	{/if}
</div>
