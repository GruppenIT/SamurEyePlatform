import { cn } from "@/lib/utils";

interface RichTextRendererProps {
  html: string;
  className?: string;
}

/**
 * Renders sanitized HTML produced by the backend.
 *
 * SECURITY: The backend must sanitize content on write (see
 * server/lib/htmlSanitizer.ts). Never pass unsanitized content here.
 */
export function RichTextRenderer({ html, className }: RichTextRendererProps) {
  return (
    <div
      className={cn(
        "prose prose-sm dark:prose-invert max-w-none",
        // Align prose colors with app theme tokens
        "prose-p:text-foreground prose-headings:text-foreground prose-strong:text-foreground prose-li:text-foreground prose-code:text-foreground prose-blockquote:text-foreground",
        "prose-a:text-primary prose-a:underline",
        "prose-img:rounded prose-img:max-w-full prose-img:h-auto",
        // Kill first/last child margins so content doesn't have dead space at top/bottom
        "[&>*:first-child]:mt-0 [&>*:last-child]:mb-0",
        className,
      )}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
