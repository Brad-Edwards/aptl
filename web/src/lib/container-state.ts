/** Map a Docker container state string to a Tailwind background color class. */
export function stateColor(state: string): string {
	if (state === 'running') return 'bg-aptl-green';
	if (state === 'exited' || state === 'dead') return 'bg-aptl-red';
	return 'bg-aptl-amber';
}
