/**
 * APTL web component kit — barrel export.
 *
 * Small, presentation/interaction-only primitives built on the Tailwind v4
 * tokens in `web/src/app.css`. See `docs/specs/web-component-kit.md`.
 */
export { default as Badge } from './Badge.svelte';
export { default as StatusBadge } from './StatusBadge.svelte';
export { default as Button } from './Button.svelte';
export { default as Field } from './Field.svelte';
export { default as TextInput } from './TextInput.svelte';
export { default as Select } from './Select.svelte';
export { default as Table } from './Table.svelte';
export { default as Dialog } from './Dialog.svelte';
export { default as Menu } from './Menu.svelte';

export {
	toneSoft,
	toneDot,
	buttonVariant,
	buttonSize,
	focusRing,
	type Tone,
	type ButtonVariant,
	type ButtonSize,
	type Density
} from './tone';
export { FIELD_CONTEXT_KEY, type FieldContext } from './field-context';
