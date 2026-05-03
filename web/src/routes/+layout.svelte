<script lang="ts">
	import '../app.css';
	import NavBar from '$lib/components/NavBar.svelte';
	import { initLabStore, destroyLabStore } from '$lib/stores/lab';
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
</div>
