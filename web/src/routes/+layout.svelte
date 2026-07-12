<script lang="ts">
	import '../app.css';
	import NavBar from '$lib/components/NavBar.svelte';
	import SettingsDialog from '$lib/components/SettingsDialog.svelte';
	import PrivacyDetailsPanel from '$lib/components/PrivacyDetailsPanel.svelte';
	import LocalUseNoticeDialog from '$lib/components/LocalUseNoticeDialog.svelte';
	import { initLabStore, destroyLabStore } from '$lib/stores/lab';
	import {
		settingsOpen,
		privacyOpen,
		noticeOpen,
		openPrivacy,
		acknowledgeAndRun,
		dismissNotice
	} from '$lib/stores/ui';
	import { onMount } from 'svelte';
	import type { Snippet } from 'svelte';

	let { children }: { children: Snippet } = $props();

	onMount(() => {
		initLabStore();
		return () => destroyLabStore();
	});
</script>

<div class="flex min-h-screen flex-col">
	<NavBar />
	<main class="flex-1">
		{@render children()}
	</main>
	<footer class="border-t border-aptl-border bg-aptl-surface">
		<div class="mx-auto flex max-w-7xl items-center justify-end px-6 py-3">
			<button
				type="button"
				class="text-xs text-aptl-text-muted underline-offset-2 hover:text-aptl-text hover:underline"
				onclick={openPrivacy}
			>
				Privacy
			</button>
		</div>
	</footer>
</div>

<!-- App-shell dialogs, mounted once and driven by the shared ui store. -->
<SettingsDialog bind:open={$settingsOpen} />
<PrivacyDetailsPanel bind:open={$privacyOpen} />
<LocalUseNoticeDialog
	bind:open={$noticeOpen}
	onAcknowledge={acknowledgeAndRun}
	onCancel={dismissNotice}
	onPrivacyDetails={openPrivacy}
/>
