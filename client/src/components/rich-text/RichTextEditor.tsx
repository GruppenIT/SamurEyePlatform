import { useEditor, EditorContent, type Editor } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import Image from "@tiptap/extension-image";
import Link from "@tiptap/extension-link";
import { useEffect, useState } from "react";
import {
  Bold,
  Italic,
  Underline,
  List,
  ListOrdered,
  Code,
  Code2,
  Link2,
  Link2Off,
  Strikethrough,
  Loader2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { uploadActionPlanImage } from "@/hooks/useActionPlans";
import { useToast } from "@/hooks/use-toast";

interface RichTextEditorProps {
  value: string;
  onChange: (html: string) => void;
  editable?: boolean;
  placeholder?: string;
  className?: string;
}

export function RichTextEditor({
  value,
  onChange,
  editable = true,
  placeholder,
  className,
}: RichTextEditorProps) {
  const { toast } = useToast();
  const [uploading, setUploading] = useState(false);

  const editor = useEditor({
    extensions: [
      StarterKit,
      Image.configure({ inline: false }),
      Link.configure({
        openOnClick: false,
        autolink: true,
        HTMLAttributes: {
          rel: "noopener noreferrer",
          target: "_blank",
        },
      }),
    ],
    content: value,
    editable,
    editorProps: {
      handlePaste: (_view, event) => {
        const items = event.clipboardData?.items;
        if (!items) return false;
        for (const item of Array.from(items)) {
          if (item.type.startsWith("image/")) {
            const file = item.getAsFile();
            if (file) {
              event.preventDefault();
              handleImageUpload(file);
              return true;
            }
          }
        }
        return false;
      },
    },
    onUpdate: ({ editor: ed }) => {
      onChange(ed.getHTML());
    },
  });

  async function handleImageUpload(file: File) {
    if (!editor) return;
    setUploading(true);
    try {
      const { url } = await uploadActionPlanImage(file);
      editor.chain().focus().setImage({ src: url }).run();
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Tente novamente.";
      toast({
        title: "Erro ao enviar imagem",
        description: message,
        variant: "destructive",
      });
    } finally {
      setUploading(false);
    }
  }

  // Sync external value changes (e.g., form reset) without emitting an update
  useEffect(() => {
    if (editor && value !== editor.getHTML()) {
      editor.commands.setContent(value, { emitUpdate: false });
    }
  }, [value, editor]);

  // Sync editable prop changes
  useEffect(() => {
    if (editor) editor.setEditable(editable);
  }, [editable, editor]);

  if (!editor) return null;

  return (
    <div className={cn("border rounded-md bg-background", className)}>
      {editable && <Toolbar editor={editor} uploading={uploading} />}
      <div className="relative p-3 min-h-[120px] focus-within:outline-none">
        {placeholder && editor.isEmpty && (
          <div className="pointer-events-none absolute top-3 left-3 text-muted-foreground text-sm">
            {placeholder}
          </div>
        )}
        <EditorContent
          editor={editor}
          className={cn(
            "prose prose-sm dark:prose-invert max-w-none focus:outline-none",
            // Align prose colors with app theme tokens
            "prose-p:text-foreground prose-headings:text-foreground prose-strong:text-foreground prose-li:text-foreground prose-code:text-foreground prose-blockquote:text-foreground",
            "prose-a:text-primary",
            // Kill first/last child margins so content starts flush with the padded container
            "[&_.ProseMirror>*:first-child]:mt-0 [&_.ProseMirror>*:last-child]:mb-0",
            "[&_.ProseMirror]:min-h-[100px] [&_.ProseMirror]:focus:outline-none",
          )}
        />
      </div>
    </div>
  );
}

interface ToolbarProps {
  editor: Editor;
  uploading: boolean;
}

function Toolbar({ editor, uploading }: ToolbarProps) {
  function btn(
    active: boolean,
    onClick: () => void,
    icon: React.ReactNode,
    label: string,
  ) {
    return (
      <Button
        key={label}
        type="button"
        variant="ghost"
        size="sm"
        className={cn("h-8 w-8 p-0", active && "bg-accent")}
        onClick={onClick}
        aria-pressed={active}
        aria-label={label}
      >
        {icon}
      </Button>
    );
  }

  function setLink() {
    const prev = editor.getAttributes("link").href as string | undefined;
    const url = window.prompt("URL:", prev ?? "");
    if (url === null) return; // cancelled
    if (url === "") {
      editor.chain().focus().extendMarkRange("link").unsetLink().run();
      return;
    }
    editor.chain().focus().extendMarkRange("link").setLink({ href: url }).run();
  }

  return (
    <div className="flex items-center gap-0.5 p-1 border-b flex-wrap">
      {btn(
        editor.isActive("bold"),
        () => editor.chain().focus().toggleBold().run(),
        <Bold className="h-4 w-4" />,
        "Negrito",
      )}
      {btn(
        editor.isActive("italic"),
        () => editor.chain().focus().toggleItalic().run(),
        <Italic className="h-4 w-4" />,
        "Itálico",
      )}
      {btn(
        editor.isActive("underline"),
        () => editor.chain().focus().toggleUnderline().run(),
        <Underline className="h-4 w-4" />,
        "Sublinhado",
      )}
      {btn(
        editor.isActive("strike"),
        () => editor.chain().focus().toggleStrike().run(),
        <Strikethrough className="h-4 w-4" />,
        "Tachado",
      )}
      <div className="w-px h-5 bg-border mx-1" />
      {btn(
        editor.isActive("bulletList"),
        () => editor.chain().focus().toggleBulletList().run(),
        <List className="h-4 w-4" />,
        "Lista",
      )}
      {btn(
        editor.isActive("orderedList"),
        () => editor.chain().focus().toggleOrderedList().run(),
        <ListOrdered className="h-4 w-4" />,
        "Lista numerada",
      )}
      <div className="w-px h-5 bg-border mx-1" />
      {btn(
        editor.isActive("code"),
        () => editor.chain().focus().toggleCode().run(),
        <Code className="h-4 w-4" />,
        "Código inline",
      )}
      {btn(
        editor.isActive("codeBlock"),
        () => editor.chain().focus().toggleCodeBlock().run(),
        <Code2 className="h-4 w-4" />,
        "Bloco de código",
      )}
      <div className="w-px h-5 bg-border mx-1" />
      {btn(
        editor.isActive("link"),
        setLink,
        <Link2 className="h-4 w-4" />,
        "Inserir link",
      )}
      {editor.isActive("link") &&
        btn(
          false,
          () => editor.chain().focus().unsetLink().run(),
          <Link2Off className="h-4 w-4" />,
          "Remover link",
        )}
      {uploading && (
        <span className="ml-auto text-xs text-muted-foreground flex items-center gap-1 px-2">
          <Loader2 className="h-3 w-3 animate-spin" /> Enviando imagem...
        </span>
      )}
    </div>
  );
}
