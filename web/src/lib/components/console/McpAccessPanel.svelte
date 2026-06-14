<script lang="ts">
	import type { McpServerSpec, Role, Session } from '$lib/console/types';
	import { ROLE_LABELS } from '$lib/console/types';
	import { ROLE_STYLES, ROLES_ORDER } from '$lib/console/roles';

	interface Props {
		servers: McpServerSpec[];
		session: Session;
		onToggle: (serverName: string, enabled: boolean) => void;
	}

	let { servers, session, onToggle }: Props = $props();

	const order: Role[] = [...ROLES_ORDER, 'neutral'];
	const grouped = $derived.by(() => {
		const map: Record<Role, McpServerSpec[]> = { red: [], blue: [], purple: [], neutral: [] };
		for (const s of servers) map[s.role].push(s);
		return map;
	});

	function enabled(name: string): boolean {
		return session.mcp_servers.includes(name);
	}
</script>

<div class="border-b border-aptl-border px-4 py-3">
	<h3 class="text-sm font-semibold text-aptl-text">MCP access</h3>
	<p class="mt-0.5 text-xs text-aptl-text-muted">
		Controls exactly which lab tools this session can reach.
	</p>
</div>

<div class="px-4 py-3">
	{#if servers.length === 0}
		<p class="text-xs text-aptl-text-muted">
			No MCP servers found. Add a <code class="font-mono">.mcp.json</code> and build the
			servers (<code class="font-mono">./mcp/build-all-mcps.sh</code>).
		</p>
	{/if}

	{#each order as role (role)}
		{#if grouped[role].length > 0}
			<div class="mb-3">
				<div class="mb-1 flex items-center gap-1.5 text-xs font-medium uppercase tracking-wide {ROLE_STYLES[role].accent}">
					<span class="h-2 w-2 rounded-full {ROLE_STYLES[role].dot}"></span>
					{ROLE_LABELS[role]}
				</div>
				{#each grouped[role] as server (server.name)}
					<label
						class="flex items-start gap-2 rounded-md px-2 py-1.5 transition-colors hover:bg-aptl-surface-hover"
						title={server.description}
					>
						<input
							type="checkbox"
							checked={enabled(server.name)}
							onchange={(e) => onToggle(server.name, e.currentTarget.checked)}
							class="mt-0.5 accent-aptl-indigo"
						/>
						<span class="min-w-0 flex-1">
							<span class="flex items-center gap-1.5">
								<span class="truncate font-mono text-xs text-aptl-text">{server.name}</span>
								{#if !server.available}
									<span
										class="rounded bg-aptl-amber/10 px-1 text-[10px] text-aptl-amber"
										title={server.unavailable_reason}
									>
										offline
									</span>
								{/if}
							</span>
							<span class="block truncate text-[11px] text-aptl-text-muted">{server.description}</span>
						</span>
					</label>
				{/each}
			</div>
		{/if}
	{/each}
</div>
