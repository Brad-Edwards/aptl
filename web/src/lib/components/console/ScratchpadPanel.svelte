<script lang="ts">
	import type { Scratchpad, Session } from '$lib/console/types';

	interface Props {
		scratchpads: Scratchpad[];
		session: Session;
		onCreate: (name: string) => void;
		onToggleAttach: (padId: string, attached: boolean) => void;
		onSave: (padId: string, content: string) => void;
		onDelete: (padId: string) => void;
	}

	let { scratchpads, session, onCreate, onToggleAttach, onSave, onDelete }: Props = $props();

	let newName = $state('');
	let editingId = $state<string | null>(null);
	let draft = $state('');

	function attached(id: string): boolean {
		return session.scratchpads.includes(id);
	}

	function startEdit(pad: Scratchpad) {
		editingId = pad.id;
		draft = pad.content;
	}

	function save() {
		if (editingId) onSave(editingId, draft);
		editingId = null;
	}

	function create() {
		const name = newName.trim();
		if (name) {
			onCreate(name);
			newName = '';
		}
	}
</script>

<div class="border-b border-aptl-border px-4 py-3">
	<h3 class="text-sm font-semibold text-aptl-text">Shared scratchpads</h3>
	<p class="mt-0.5 text-xs text-aptl-text-muted">
		Shared memory across sessions. Attach a pad to expose read/write tools to this chat.
	</p>
</div>

<div class="px-4 py-3">
	<div class="mb-3 flex gap-2">
		<input
			type="text"
			bind:value={newName}
			placeholder="New scratchpad name"
			onkeydown={(e) => e.key === 'Enter' && create()}
			class="min-w-0 flex-1 rounded-md border border-aptl-border bg-aptl-bg px-2 py-1 text-xs text-aptl-text placeholder:text-aptl-text-muted focus:border-aptl-indigo focus:outline-none"
		/>
		<button
			onclick={create}
			class="rounded-md bg-aptl-indigo px-2 py-1 text-xs font-medium text-white transition-colors hover:bg-aptl-indigo-hover"
		>
			Add
		</button>
	</div>

	{#if scratchpads.length === 0}
		<p class="text-xs text-aptl-text-muted">No scratchpads yet.</p>
	{/if}

	{#each scratchpads as pad (pad.id)}
		<div class="mb-2 rounded-md border border-aptl-border bg-aptl-bg/40">
			<div class="flex items-center gap-2 px-2 py-1.5">
				<input
					type="checkbox"
					checked={attached(pad.id)}
					onchange={(e) => onToggleAttach(pad.id, e.currentTarget.checked)}
					title="Attach to this session"
					class="accent-aptl-indigo"
				/>
				<span class="min-w-0 flex-1 truncate text-xs font-medium text-aptl-text">{pad.name}</span>
				<button
					onclick={() => (editingId === pad.id ? (editingId = null) : startEdit(pad))}
					class="text-xs text-aptl-text-muted hover:text-aptl-text"
				>
					{editingId === pad.id ? 'close' : 'edit'}
				</button>
				<button
					onclick={() => onDelete(pad.id)}
					aria-label="Delete scratchpad"
					class="text-xs text-aptl-text-muted hover:text-aptl-red"
				>
					✕
				</button>
			</div>

			{#if editingId === pad.id}
				<div class="border-t border-aptl-border p-2">
					<textarea
						bind:value={draft}
						rows="6"
						class="w-full resize-y rounded border border-aptl-border bg-aptl-bg px-2 py-1 font-mono text-xs text-aptl-text focus:border-aptl-indigo focus:outline-none"
					></textarea>
					<div class="mt-1 flex justify-end">
						<button
							onclick={save}
							class="rounded bg-aptl-indigo px-2 py-1 text-xs font-medium text-white hover:bg-aptl-indigo-hover"
						>
							Save
						</button>
					</div>
				</div>
			{:else if pad.content}
				<p class="border-t border-aptl-border px-2 py-1 font-mono text-[11px] text-aptl-text-muted line-clamp-2">
					{pad.content}
				</p>
			{/if}
		</div>
	{/each}
</div>
