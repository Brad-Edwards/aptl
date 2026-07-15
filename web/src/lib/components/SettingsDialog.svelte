<script lang="ts">
	import Dialog from '$lib/components/kit/Dialog.svelte';
	import Button from '$lib/components/kit/Button.svelte';
	import Field from '$lib/components/kit/Field.svelte';
	import Select from '$lib/components/kit/Select.svelte';
	import {
		preferences,
		setPreference,
		setTerminalFontSize,
		resetPreferences,
		COLOR_MODE_OPTIONS,
		DENSITY_OPTIONS,
		MOTION_OPTIONS,
		LOCALE_OPTIONS,
		TIME_DISPLAY_OPTIONS,
		SIEM_TIME_RANGE_OPTIONS,
		SIEM_ROW_LIMITS,
		TERMINAL_SCROLLBACKS,
		TERMINAL_FONT_SIZE_MIN,
		TERMINAL_FONT_SIZE_MAX,
		type ColorMode,
		type Density,
		type Motion,
		type TimeDisplay,
		type SiemTimeRange
	} from '$lib/stores/preferences';

	interface Props {
		/** Open state. Bindable so the parent (app shell) can also close it. */
		open?: boolean;
		onClose?: () => void;
	}

	let { open = $bindable(false), onClose }: Props = $props();

	const rowLimitOptions = SIEM_ROW_LIMITS.map((n) => ({ value: String(n), label: String(n) }));
	const scrollbackOptions = TERMINAL_SCROLLBACKS.map((n) => ({
		value: String(n),
		label: `${n} lines`
	}));

	const legend = 'text-xs font-semibold uppercase tracking-wide text-aptl-text-muted';
</script>

<Dialog
	bind:open
	title="Settings"
	description="Local workbench preferences. These change how the UI looks and behaves in this browser only — they never change the lab."
	placement="right"
	{onClose}
>
	{#snippet body()}
		<div class="space-y-6">
			<fieldset class="space-y-3">
				<legend class={legend}>Appearance</legend>
				<Field label="Color mode">
					<Select
						options={COLOR_MODE_OPTIONS}
						bind:value={
							() => $preferences.colorMode, (v) => setPreference('colorMode', v as ColorMode)
						}
					/>
				</Field>
				<Field label="Density">
					<Select
						options={DENSITY_OPTIONS}
						bind:value={() => $preferences.density, (v) => setPreference('density', v as Density)}
					/>
				</Field>
				<Field
					label="Motion"
					description="Reduced also honours your system reduced-motion setting."
				>
					<Select
						options={MOTION_OPTIONS}
						bind:value={() => $preferences.motion, (v) => setPreference('motion', v as Motion)}
					/>
				</Field>
			</fieldset>

			<fieldset class="space-y-3">
				<legend class={legend}>Locale and time</legend>
				<Field label="Language">
					<Select
						options={LOCALE_OPTIONS}
						bind:value={() => $preferences.locale, (v) => setPreference('locale', v)}
					/>
				</Field>
				<Field label="Time display">
					<Select
						options={TIME_DISPLAY_OPTIONS}
						bind:value={
							() => $preferences.timeDisplay, (v) => setPreference('timeDisplay', v as TimeDisplay)
						}
					/>
				</Field>
			</fieldset>

			<fieldset class="space-y-3">
				<legend class={legend}>SIEM defaults</legend>
				<p class="text-xs text-aptl-text-muted">
					Saved for the SIEM explorer, which is not available yet. The backend will still
					enforce time-range and row maximums when it ships.
				</p>
				<Field label="Default time range">
					<Select
						options={SIEM_TIME_RANGE_OPTIONS}
						bind:value={
							() => $preferences.siemTimeRange,
							(v) => setPreference('siemTimeRange', v as SiemTimeRange)
						}
					/>
				</Field>
				<Field label="Row limit">
					<Select
						options={rowLimitOptions}
						bind:value={
							() => String($preferences.siemRowLimit),
							(v) => setPreference('siemRowLimit', Number(v))
						}
					/>
				</Field>
			</fieldset>

			<fieldset class="space-y-3">
				<legend class={legend}>Terminal</legend>
				<div role="group" aria-label="Terminal font size" class="flex flex-col gap-1">
					<span class="text-sm font-medium text-aptl-text">Font size</span>
					<div class="flex items-center gap-3">
						<Button
							size="sm"
							variant="secondary"
							label="Decrease terminal font size"
							disabled={$preferences.terminalFontSize <= TERMINAL_FONT_SIZE_MIN}
							onclick={() => setTerminalFontSize($preferences.terminalFontSize - 1)}
						>
							&minus;
						</Button>
						<span class="min-w-[3ch] text-center tabular-nums text-sm" aria-live="polite">
							{$preferences.terminalFontSize}
						</span>
						<Button
							size="sm"
							variant="secondary"
							label="Increase terminal font size"
							disabled={$preferences.terminalFontSize >= TERMINAL_FONT_SIZE_MAX}
							onclick={() => setTerminalFontSize($preferences.terminalFontSize + 1)}
						>
							+
						</Button>
					</div>
				</div>
				<Field label="Scrollback">
					<Select
						options={scrollbackOptions}
						bind:value={
							() => String($preferences.terminalScrollback),
							(v) => setPreference('terminalScrollback', Number(v))
						}
					/>
				</Field>
			</fieldset>
		</div>
	{/snippet}
	{#snippet footer()}
		<Button variant="secondary" onclick={resetPreferences}>Reset preferences</Button>
		<Button variant="primary" onclick={() => (open = false)}>Done</Button>
	{/snippet}
</Dialog>
