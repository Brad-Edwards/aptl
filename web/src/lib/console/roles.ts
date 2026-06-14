import type { Role } from './types';

/** Tailwind utility classes for each role, used to colour the UI consistently. */
export const ROLE_STYLES: Record<
	Role,
	{ chip: string; accent: string; dot: string; border: string }
> = {
	red: {
		chip: 'bg-aptl-red/10 text-aptl-red',
		accent: 'text-aptl-red',
		dot: 'bg-aptl-red',
		border: 'border-aptl-red/40'
	},
	blue: {
		chip: 'bg-aptl-teal/10 text-aptl-teal',
		accent: 'text-aptl-teal',
		dot: 'bg-aptl-teal',
		border: 'border-aptl-teal/40'
	},
	purple: {
		chip: 'bg-aptl-indigo/10 text-aptl-indigo',
		accent: 'text-aptl-indigo',
		dot: 'bg-aptl-indigo',
		border: 'border-aptl-indigo/40'
	},
	neutral: {
		chip: 'bg-aptl-text-muted/10 text-aptl-text-muted',
		accent: 'text-aptl-text-muted',
		dot: 'bg-aptl-text-muted',
		border: 'border-aptl-border'
	}
};

export const ROLES_ORDER: Role[] = ['red', 'blue', 'purple'];
