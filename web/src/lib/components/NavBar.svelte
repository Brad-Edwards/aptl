<script lang="ts">
	import { labStatus } from '../stores/lab';
	import LabStatusBadge from './LabStatusBadge.svelte';
	import Menu from './kit/Menu.svelte';
	import { focusRing } from './kit/tone';
	import { openSettings, openPrivacy } from '../stores/ui';

	const navLink = 'text-sm text-aptl-text-muted transition-colors hover:text-aptl-text';
</script>

<nav class="border-b border-aptl-border bg-aptl-surface">
	<div class="mx-auto flex h-14 max-w-7xl items-center justify-between px-6">
		<div class="flex items-center gap-6">
			<a href="/" class="text-lg font-semibold tracking-tight text-aptl-text"> APTL </a>
			<div class="hidden items-center gap-4 sm:flex">
				<a href="/" class={navLink}>Lab Home</a>
				<a href="/config" class={navLink}>Config</a>
			</div>
		</div>
		<div class="flex items-center gap-3">
			<LabStatusBadge running={$labStatus.running} />
			<button
				type="button"
				onclick={openSettings}
				class="rounded-md border border-aptl-border bg-aptl-surface px-3 py-1.5 text-sm text-aptl-text hover:bg-aptl-surface-hover {focusRing}"
			>
				Settings
			</button>
			<Menu label="Help" align="right" items={[{ label: 'Privacy', onSelect: openPrivacy }]} />
		</div>
	</div>
</nav>
