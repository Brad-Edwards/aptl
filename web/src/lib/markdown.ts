import { marked } from 'marked';
import DOMPurify from 'dompurify';

/**
 * Render a markdown string to sanitized HTML.
 * Returns empty string for falsy input.
 */
export function renderMarkdown(input: string | null | undefined): string {
	if (!input) return '';
	const raw = marked.parse(input, { async: false }) as string;
	return DOMPurify.sanitize(raw);
}
