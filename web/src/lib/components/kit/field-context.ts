/**
 * Context contract shared between `Field` and the form controls it wraps
 * (`TextInput`, `Select`). `Field` owns id generation and validation/described-by
 * wiring; controls read it from context so a consumer writes
 * `<Field label="…"><TextInput /></Field>` without threading ids by hand.
 *
 * Controls fall back to their own props when rendered outside a `Field`.
 */
export const FIELD_CONTEXT_KEY = Symbol('aptl-field');

export interface FieldContext {
	readonly id: string;
	readonly describedById: string | undefined;
	readonly invalid: boolean;
	readonly required: boolean;
}
