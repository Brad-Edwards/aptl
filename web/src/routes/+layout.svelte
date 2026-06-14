<script lang="ts">
	import '../app.css';
	import NavBar from '$lib/components/NavBar.svelte';
	import { initLabStore, destroyLabStore } from '$lib/stores/lab';
	import { onMount, setContext } from 'svelte';
	import type { Snippet } from 'svelte';
	import type { LayoutData } from './$types';

	let { children, data }: { children: Snippet; data: LayoutData } = $props();

	setContext('apiCtx', { apiHost: data.apiHost, wsToken: data.wsToken });

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
</div>
