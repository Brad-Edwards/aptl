/**
 * Shared semantic class recipes for the APTL component kit.
 *
 * This module is the single place semantic intent (a status, a button role, a
 * table density) maps to Tailwind utility classes built on the tokens defined
 * in `web/src/app.css`. Components consume these recipes through semantic props
 * instead of accepting arbitrary colour-class strings, which keeps status
 * colours from drifting into per-component `switch` statements.
 *
 * It deliberately mirrors *class recipes*, never token hex values — `app.css`
 * stays the canonical token source (no JS token mirror, no Tailwind config
 * fork).
 */

/** Semantic tone shared by badges, status pills, and form validation states. */
export type Tone = 'neutral' | 'info' | 'success' | 'warning' | 'danger' | 'accent';

/** Soft pill treatment: tinted background plus a readable foreground colour. */
export const toneSoft: Record<Tone, string> = {
	neutral: 'bg-aptl-text-muted/10 text-aptl-text-muted',
	info: 'bg-aptl-indigo/10 text-aptl-indigo',
	success: 'bg-aptl-green/10 text-aptl-green',
	warning: 'bg-aptl-amber/10 text-aptl-amber',
	danger: 'bg-aptl-red/10 text-aptl-red',
	accent: 'bg-aptl-violet/10 text-aptl-violet'
};

/** Solid status-dot colour per tone. */
export const toneDot: Record<Tone, string> = {
	neutral: 'bg-aptl-text-muted',
	info: 'bg-aptl-indigo',
	success: 'bg-aptl-green',
	warning: 'bg-aptl-amber',
	danger: 'bg-aptl-red',
	accent: 'bg-aptl-violet'
};

/** Button visual role. `danger` is reserved for destructive actions. */
export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';

export const buttonVariant: Record<ButtonVariant, string> = {
	primary: 'bg-aptl-indigo text-white hover:bg-aptl-indigo-hover',
	secondary: 'border border-aptl-border bg-aptl-surface text-aptl-text hover:bg-aptl-surface-hover',
	ghost: 'text-aptl-text-muted hover:bg-aptl-surface-hover hover:text-aptl-text',
	danger: 'bg-aptl-red text-white hover:bg-aptl-red/90'
};

export type ButtonSize = 'sm' | 'md';

export const buttonSize: Record<ButtonSize, string> = {
	sm: 'h-8 px-3 text-xs',
	md: 'h-10 px-4 text-sm'
};

/**
 * Shared focus-ring recipe. Uses the named `--color-aptl-focus` token so focus
 * treatment is consistent and visible (WCAG 2.2 focus-visible) across every
 * interactive primitive.
 */
export const focusRing =
	'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-aptl-focus focus-visible:ring-offset-2 focus-visible:ring-offset-aptl-bg';

/** Table / list / card density. Consumed via component props, not persisted here. */
export type Density = 'comfortable' | 'compact';
