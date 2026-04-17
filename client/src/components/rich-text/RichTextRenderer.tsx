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
        "prose-img:rounded prose-img:max-w-full prose-img:h-auto",
        "prose-a:text-primary prose-a:underline",
        className,
      )}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
