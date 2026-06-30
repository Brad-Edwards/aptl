# APTL web component kit

The component kit is a small set of presentation and interaction primitives for
the APTL web GUI. It formalizes the Tailwind v4 tokens already shipped in
[`web/src/app.css`](https://github.com/Brad-Edwards/aptl/blob/main/web/src/app.css)
into a documented design system and provides reusable Svelte components that the
v1 routes assemble from, rather than ad-hoc markup or a wholesale admin
template.

This document implements issue UI-008b under the
[Web GUI Design Specification](web-gui-design.md). It covers the token set and
the kit primitives only. Page-level routes consume the kit in separate child
issues.

## Design tokens

`web/src/app.css` is the single source for the design tokens. The `@theme`
block defines custom properties that Tailwind v4 turns into `*-aptl-*`
utilities, so a token named `--color-aptl-surface` produces utilities such as
`bg-aptl-surface` and `border-aptl-surface`. The kit maps semantic intent to
those utilities through shared recipes in
[`web/src/lib/components/kit/tone.ts`](https://github.com/Brad-Edwards/aptl/blob/main/web/src/lib/components/kit/tone.ts).
No token value is duplicated in JavaScript and the Tailwind configuration is not
forked.

### Token groups

| Group | Tokens | Role |
| --- | --- | --- |
| Surface | `aptl-bg`, `aptl-surface`, `aptl-surface-hover`, `aptl-border` | Page background through raised surfaces and dividers. |
| Text | `aptl-text`, `aptl-text-muted` | Primary copy and muted secondary copy. |
| Accent and status | `aptl-indigo`, `aptl-indigo-hover`, `aptl-violet`, `aptl-teal`, `aptl-red`, `aptl-green`, `aptl-amber` | Purple stays an accent. Status meaning is carried by the semantic tones below, never by colour alone. |
| Focus | `aptl-focus` | Named token for the shared focus-ring recipe, aliasing indigo so focus treatment is overridable in one place. |
| Typography | `font-sans`, `font-mono` | Sans for interface copy with a system-font fallback, mono for terminal and command text. |

### Reduced motion

`app.css` honours the `prefers-reduced-motion` media query globally. Animations
and transitions collapse to an instant change when the user asks for reduced
motion, so an affordance such as the `StatusBadge` pulse never animates against
that preference.

### Density

Density is a presentation choice exposed through component props, such as the
`density` prop on `Table`. The kit does not persist a density preference. The
browser-local preferences store that records operator settings is a separate
concern under the settings dialog child issue.

## Primitives

The kit lives in
[`web/src/lib/components/kit/`](https://github.com/Brad-Edwards/aptl/blob/main/web/src/lib/components/kit)
and is re-exported from `index.ts`. Every component takes semantic props instead
of arbitrary colour-class strings, and every interactive component carries the
shared focus ring and an accessible name.

| Component | Purpose | Key props |
| --- | --- | --- |
| `Badge` | Semantic pill for tags and labels. | `tone`, `dot`, `pulse`, `label` |
| `StatusBadge` | Status pill with a dot and a visible text label. | `tone`, `label`, `pulse` |
| `Button` | Action control; renders a link when `href` is set. | `variant`, `size`, `href`, `disabled`, `label` |
| `Field` | Label, description, and error wrapper for a form control. | `label`, `description`, `error`, `required` |
| `TextInput` | Text input that reads its wiring from a parent `Field`. | `value`, `type`, `invalid`, `ariaLabel` |
| `Select` | Option select that reads its wiring from a parent `Field`. | `value`, `options`, `invalid`, `ariaLabel` |
| `Table` | Captioned data table with a density option. | `caption`, `captionVisible`, `density` |
| `Dialog` | Accessible modal dialog or side drawer. | `open`, `title`, `description`, `placement` |
| `Menu` | Accessible dropdown menu with keyboard navigation. | `label`, `items`, `align` |

### Semantic tones

`Badge`, `StatusBadge`, and the form validation states share one `Tone` scale:
`neutral`, `info`, `success`, `warning`, `danger`, and `accent`. The tone maps to
the palette through `tone.ts`, which keeps status colours from drifting into a
separate colour decision in each component.

### Forms

`Field` owns identifier generation and the relationship wiring. It associates
its label with the control, exposes a description through `aria-describedby`,
and announces a validation message through `role="alert"`. A control placed
inside a `Field` reads that wiring from context, so a caller writes a field
without threading identifiers by hand:

```svelte
<Field label="Row limit" description="The backend remains authoritative.">
  <TextInput />
</Field>
```

`TextInput` and `Select` fall back to their own props when used outside a
`Field`, with `ariaLabel` providing the accessible name.

### Overlays and accessibility

`Dialog` and `Menu` manage keyboard focus directly rather than depending on a
headless component library. Owning the behaviour keeps the kit small, avoids a
new runtime dependency under the strict content-security policy, and lets the
focus contract be tested.

- `Dialog` exposes `role="dialog"` with `aria-modal`, a programmatic title and
  description, a focus trap, Escape-to-close, a backdrop close, and focus return
  to the control that opened it. The `placement` prop selects a centred modal or
  a right-side drawer.
- `Menu` exposes `role="menu"` with a trigger that reports its expanded state.
  The arrow keys, Home, and End move focus across enabled items, Escape closes
  the menu and returns focus to the trigger, and a click outside closes it.

## Testing

Every primitive has a Vitest suite in
[`web/tests/components/kit/`](https://github.com/Brad-Edwards/aptl/blob/main/web/tests/components/kit)
that asserts behaviour and accessibility rather than rendered snapshots: tone
recipe mapping, focus-trap wrapping, label and description wiring, dialog focus
return, and menu keyboard navigation. Run the suite with `npm test` in the `web`
directory.
