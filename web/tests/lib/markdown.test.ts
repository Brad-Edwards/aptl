import { describe, it, expect } from 'vitest';
import { renderMarkdown } from '../../src/lib/markdown';

describe('renderMarkdown', () => {
	it('renders basic markdown to HTML', () => {
		const result = renderMarkdown('**bold** and *italic*');
		expect(result).toContain('<strong>bold</strong>');
		expect(result).toContain('<em>italic</em>');
	});

	it('renders headings', () => {
		const result = renderMarkdown('# Title');
		expect(result).toContain('<h1>Title</h1>');
	});

	it('renders code blocks', () => {
		const result = renderMarkdown('`code`');
		expect(result).toContain('<code>code</code>');
	});

	it('sanitizes XSS: script tags', () => {
		const result = renderMarkdown('<script>alert("xss")</script>');
		expect(result).not.toContain('<script>');
		expect(result).not.toContain('alert');
	});

	it('sanitizes XSS: event handlers', () => {
		const result = renderMarkdown('<img src=x onerror="alert(1)">');
		expect(result).not.toContain('onerror');
	});

	it('sanitizes XSS: javascript URLs', () => {
		const result = renderMarkdown('<a href="javascript:alert(1)">click</a>');
		expect(result).not.toContain('javascript:');
	});

	it('returns empty string for null input', () => {
		expect(renderMarkdown(null)).toBe('');
	});

	it('returns empty string for undefined input', () => {
		expect(renderMarkdown(undefined)).toBe('');
	});

	it('returns empty string for empty string input', () => {
		expect(renderMarkdown('')).toBe('');
	});
});
