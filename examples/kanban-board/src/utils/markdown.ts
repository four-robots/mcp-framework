import { marked } from 'marked';

// Configure marked for security and consistency
marked.setOptions({
  breaks: true, // Enable line breaks
  gfm: true, // Enable GitHub Flavored Markdown
});

// Custom renderer to make links safe
const renderer = new marked.Renderer();
renderer.link = function({ href, title, tokens }) {
  const text = this.parser.parseInline(tokens);
  // Only allow safe URL protocols
  const safeHref = /^(https?:\/\/|mailto:|#)/.test(href || '') ? href : '#';
  return `<a href="${safeHref}" title="${title || ''}" target="_blank" rel="noopener noreferrer">${text}</a>`;
};

marked.use({ renderer });

/**
 * Convert markdown text to HTML
 * @param markdown The markdown text to convert
 * @returns HTML string
 */
export function markdownToHtml(markdown: string): string {
  if (!markdown || typeof markdown !== 'string') {
    return '';
  }
  
  try {
    return marked(markdown) as string;
  } catch (error) {
    console.error('Error parsing markdown:', error);
    // Return escaped text if markdown parsing fails to prevent XSS
    return escapeHtml(markdown);
  }
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Convert markdown to plain text (strip HTML tags)
 * @param markdown The markdown text to convert
 * @returns Plain text string
 */
export function markdownToText(markdown: string): string {
  if (!markdown || typeof markdown !== 'string') {
    return '';
  }
  
  try {
    const html = marked(markdown) as string;
    // Simple HTML tag stripping (for basic use cases)
    return html.replace(/<[^>]*>/g, '').trim();
  } catch (error) {
    console.error('Error parsing markdown to text:', error);
    return markdown;
  }
}

/**
 * Sanitize markdown by limiting allowed elements
 * This is a basic implementation - for production use, consider using a library like DOMPurify
 */
export function sanitizeMarkdown(html: string): string {
  // Strip dangerous tags (script, style, iframe, object, embed, form)
  return html
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
    .replace(/<iframe\b[^>]*>.*?<\/iframe>/gi, '')
    .replace(/<object\b[^>]*>.*?<\/object>/gi, '')
    .replace(/<embed\b[^>]*\/?>/gi, '')
    .replace(/<form\b[^>]*>.*?<\/form>/gi, '')
    .replace(/\bon\w+\s*=\s*(['"]?).*?\1/gi, '');
}