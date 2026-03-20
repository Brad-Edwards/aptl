<script lang="ts">
	import { page } from '$app/stores';
</script>

<div class="flex min-h-screen items-center justify-center bg-aptl-bg px-6">
	<div class="text-center">
		<h1 class="text-6xl font-bold text-aptl-text-muted">{$page.status}</h1>
		<p class="mt-4 text-lg text-aptl-text">{$page.error?.message || 'Something went wrong'}</p>
		<a
			href="/"
			class="mt-6 inline-block rounded-lg bg-aptl-indigo px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-aptl-indigo-hover"
		>
			Back to Lab Home
		</a>
	</div>
</div>
