<script lang="ts">
	import Field from '../../../../src/lib/components/kit/Field.svelte';
	import TextInput from '../../../../src/lib/components/kit/TextInput.svelte';

	interface Props {
		label: string;
		description?: string;
		error?: string;
		required?: boolean;
	}

	let { label, description, error, required = false }: Props = $props();
</script>

<Field {label} {description} {error} {required}>
	<TextInput />
</Field>
