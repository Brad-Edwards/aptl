<script lang="ts">
	import type { Role, Session } from '$lib/console/types';
	import { ROLE_LABELS } from '$lib/console/types';
	import { ROLE_STYLES, ROLES_ORDER } from '$lib/console/roles';

	interface Props {
		sessions: Session[];
		selectedId: string | null;
		onSelect: (id: string) => void;
		onCreate: (role: Role) => void;
		onDelete: (id: string) => void;
	}

	let { sessions, selectedId, onSelect, onCreate, onDelete }: Props = $props();

	const grouped = $derived.by(() => {
		const map: Record<Role, Session[]> = { red: [], blue: [], purple: [], neutral: [] };
		for (const s of sessions) map[s.role].push(s);
		return map;
	});
</script>

<aside class="flex w-64 shrink-0 flex-col border-r border-aptl-border bg-aptl-surface">
	<div class="border-b border-aptl-border px-4 py-3">
		<h2 class="text-sm font-semibold text-aptl-text">Sessions</h2>
		<p class="mt-0.5 text-xs text-aptl-text-muted">Red and blue chats stay separate</p>
	</div>

	<div class="flex-1 overflow-y-auto px-2 py-2">
		{#each ROLES_ORDER as role (role)}
			<div class="mb-3">
				<div class="flex items-center justify-between px-2 py-1">
					<span class="flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide {ROLE_STYLES[role].accent}">
						<span class="h-2 w-2 rounded-full {ROLE_STYLES[role].dot}"></span>
						{ROLE_LABELS[role]}
					</span>
					<button
						onclick={() => onCreate(role)}
						aria-label={`New ${role} session`}
						title={`New ${role} session`}
						class="rounded px-1.5 text-sm text-aptl-text-muted transition-colors hover:bg-aptl-surface-hover hover:text-aptl-text"
					>
						+
					</button>
				</div>

				{#each grouped[role] as session (session.id)}
					<div
						class="group mb-1 flex items-center rounded-md border-l-2 {session.id === selectedId
							? `${ROLE_STYLES[role].border} bg-aptl-surface-hover`
							: 'border-transparent'}"
					>
						<button
							onclick={() => onSelect(session.id)}
							class="flex-1 truncate px-2 py-1.5 text-left text-sm text-aptl-text"
						>
							{session.title}
							<span class="ml-1 text-xs text-aptl-text-muted">
								· {session.mcp_servers.length} MCP
							</span>
						</button>
						<button
							onclick={() => onDelete(session.id)}
							aria-label="Delete session"
							title="Delete session"
							class="px-2 text-xs text-aptl-text-muted opacity-0 transition-opacity hover:text-aptl-red group-hover:opacity-100"
						>
							✕
						</button>
					</div>
				{/each}

				{#if grouped[role].length === 0}
					<p class="px-2 py-1 text-xs text-aptl-text-muted">No {role} sessions</p>
				{/if}
			</div>
		{/each}
	</div>
</aside>
