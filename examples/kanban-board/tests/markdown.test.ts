import { describe, it, expect } from 'vitest';
import { markdownToHtml, markdownToText, sanitizeMarkdown } from '../src/utils/markdown.js';

describe('Markdown Utilities', () => {
  describe('markdownToHtml', () => {
    it('should convert basic markdown to HTML', () => {
      const html = markdownToHtml('**bold**');
      expect(html).toContain('<strong>bold</strong>');
    });

    it('should return empty string for empty input', () => {
      expect(markdownToHtml('')).toBe('');
    });

    it('should return empty string for null/undefined input', () => {
      expect(markdownToHtml(null as any)).toBe('');
      expect(markdownToHtml(undefined as any)).toBe('');
    });

    it('should return empty string for non-string input', () => {
      expect(markdownToHtml(123 as any)).toBe('');
    });

    it('should handle inline code', () => {
      const html = markdownToHtml('`code`');
      expect(html).toContain('<code>code</code>');
    });

    it('should handle line breaks with GFM', () => {
      const html = markdownToHtml('line1\nline2');
      expect(html).toContain('<br');
    });
  });

  describe('Link Protocol Validation', () => {
    it('should allow https links', () => {
      const html = markdownToHtml('[link](https://example.com)');
      expect(html).toContain('href="https://example.com"');
    });

    it('should allow http links', () => {
      const html = markdownToHtml('[link](http://example.com)');
      expect(html).toContain('href="http://example.com"');
    });

    it('should allow mailto links', () => {
      const html = markdownToHtml('[email](mailto:user@example.com)');
      expect(html).toContain('href="mailto:user@example.com"');
    });

    it('should allow anchor fragment links', () => {
      const html = markdownToHtml('[section](#heading)');
      expect(html).toContain('href="#heading"');
    });

    it('should block javascript: protocol', () => {
      const html = markdownToHtml('[xss](javascript:alert(1))');
      expect(html).not.toContain('javascript:');
      expect(html).toContain('href="#"');
    });

    it('should block data: protocol', () => {
      const html = markdownToHtml('[xss](data:text/html,<script>alert(1)</script>)');
      expect(html).not.toContain('data:');
      expect(html).toContain('href="#"');
    });

    it('should block vbscript: protocol', () => {
      const html = markdownToHtml('[xss](vbscript:msgbox)');
      expect(html).not.toContain('vbscript:');
      expect(html).toContain('href="#"');
    });

    it('should add target=_blank and rel=noopener noreferrer to links', () => {
      const html = markdownToHtml('[link](https://example.com)');
      expect(html).toContain('target="_blank"');
      expect(html).toContain('rel="noopener noreferrer"');
    });
  });

  describe('markdownToText', () => {
    it('should strip HTML tags from markdown output', () => {
      const text = markdownToText('**bold** and *italic*');
      expect(text).toBe('bold and italic');
    });

    it('should return empty string for empty input', () => {
      expect(markdownToText('')).toBe('');
    });

    it('should return empty string for null/undefined input', () => {
      expect(markdownToText(null as any)).toBe('');
      expect(markdownToText(undefined as any)).toBe('');
    });

    it('should handle links by extracting text', () => {
      const text = markdownToText('[click here](https://example.com)');
      expect(text).toContain('click here');
      expect(text).not.toContain('https://example.com');
    });

    it('should handle code blocks', () => {
      const text = markdownToText('`code`');
      expect(text).toContain('code');
    });
  });

  describe('sanitizeMarkdown', () => {
    it('should strip script tags', () => {
      const result = sanitizeMarkdown('<p>safe</p><script>alert(1)</script>');
      expect(result).not.toContain('<script>');
      expect(result).not.toContain('alert(1)');
      expect(result).toContain('<p>safe</p>');
    });

    it('should strip style tags', () => {
      const result = sanitizeMarkdown('<p>safe</p><style>body{display:none}</style>');
      expect(result).not.toContain('<style>');
      expect(result).toContain('<p>safe</p>');
    });

    it('should strip iframe tags', () => {
      const result = sanitizeMarkdown('<p>safe</p><iframe src="evil.com"></iframe>');
      expect(result).not.toContain('<iframe');
      expect(result).toContain('<p>safe</p>');
    });

    it('should strip object tags', () => {
      const result = sanitizeMarkdown('<p>safe</p><object data="evil.swf"></object>');
      expect(result).not.toContain('<object');
      expect(result).toContain('<p>safe</p>');
    });

    it('should strip embed tags', () => {
      const result = sanitizeMarkdown('<p>safe</p><embed src="evil.swf"/>');
      expect(result).not.toContain('<embed');
      expect(result).toContain('<p>safe</p>');
    });

    it('should strip form tags', () => {
      const result = sanitizeMarkdown('<p>safe</p><form action="/steal"><input/></form>');
      expect(result).not.toContain('<form');
      expect(result).toContain('<p>safe</p>');
    });

    it('should strip inline event handlers', () => {
      const result = sanitizeMarkdown('<img src="x" onerror="alert(1)">');
      expect(result).not.toContain('onerror');
      expect(result).not.toContain('alert');
    });

    it('should strip onclick handlers', () => {
      const result = sanitizeMarkdown('<div onclick="alert(1)">click</div>');
      expect(result).not.toContain('onclick');
    });

    it('should strip onload handlers', () => {
      const result = sanitizeMarkdown('<body onload="alert(1)">');
      expect(result).not.toContain('onload');
    });

    it('should preserve safe HTML', () => {
      const safeHtml = '<p>Hello <strong>world</strong></p>';
      const result = sanitizeMarkdown(safeHtml);
      expect(result).toBe(safeHtml);
    });

    it('should handle multiple dangerous elements', () => {
      const input = '<p>safe</p><script>evil()</script><style>.x{}</style><iframe></iframe>';
      const result = sanitizeMarkdown(input);
      expect(result).not.toContain('<script');
      expect(result).not.toContain('<style');
      expect(result).not.toContain('<iframe');
      expect(result).toContain('<p>safe</p>');
    });
  });
});
