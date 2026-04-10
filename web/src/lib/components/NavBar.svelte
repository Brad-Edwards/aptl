<script lang="ts">
	import { labStatus } from '../stores/lab';
	import LabStatusBadge from './LabStatusBadge.svelte';
</script>

<nav class="border-b border-aptl-border bg-aptl-surface">
	<div class="mx-auto flex h-14 max-w-7xl items-center justify-between px-6">
		<div class="flex items-center gap-6">
			<a href="/" class="text-lg font-semibold tracking-tight text-aptl-text">
				APTL
			</a>
			<div class="hidden items-center gap-4 sm:flex">
				<a
					href="/"
					class="text-sm text-aptl-text-muted transition-colors hover:text-aptl-text"
				>
					Lab Home
				</a>
			</div>
		</div>
		<div class="flex items-center gap-4">
			<LabStatusBadge running={$labStatus.running} />
		</div>
	</div>
</nav>
