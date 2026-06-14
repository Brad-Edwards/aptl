<script lang="ts">
	import type { Role } from '$lib/console/types';
	import { ROLE_LABELS } from '$lib/console/types';
	import { ROLE_STYLES } from '$lib/console/roles';

	let { role }: { role: Role } = $props();
</script>

<span class="rounded-full px-2 py-0.5 text-xs font-medium {ROLE_STYLES[role].chip}">
	{ROLE_LABELS[role]}
</span>
