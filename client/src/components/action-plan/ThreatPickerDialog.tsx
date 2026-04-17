import { useMemo, useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface ThreatRow {
  id: string;
  title: string;
  severity: string;
  status: string;
}

interface ThreatPickerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Threats already associated — shown but disabled to prevent duplicates. */
  excludedIds?: string[];
  onConfirm: (threatIds: string[]) => void | Promise<void>;
}

export function ThreatPickerDialog({
  open,
  onOpenChange,
  excludedIds = [],
  onConfirm,
}: ThreatPickerDialogProps) {
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (open) {
      setSelected(new Set());
      setSearch("");
    }
  }, [open]);

  // Uses the project's global default queryFn which fetches the URL
  // matching the queryKey path.
  const { data, isLoading } = useQuery<ThreatRow[]>({
    queryKey: ["/api/threats"],
    enabled: open,
  });

  const excludedSet = useMemo(() => new Set(excludedIds), [excludedIds]);

  const filtered = useMemo(() => {
    if (!data) return [];
    const s = search.toLowerCase();
    return data.filter((t) => !s || t.title.toLowerCase().includes(s));
  }, [data, search]);

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleConfirm() {
    if (selected.size === 0) return;
    setSubmitting(true);
    try {
      await onConfirm(Array.from(selected));
      onOpenChange(false);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Selecionar ameaças</DialogTitle>
        </DialogHeader>

        <Input
          placeholder="Buscar por título..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />

        <div className="max-h-[400px] overflow-y-auto border rounded-md">
          {isLoading && (
            <div className="p-4 text-sm text-muted-foreground">
              Carregando...
            </div>
          )}
          {!isLoading && filtered.length === 0 && (
            <div className="p-4 text-sm text-muted-foreground">
              Nenhuma ameaça encontrada.
            </div>
          )}
          <ul className="divide-y">
            {filtered.map((t) => {
              const isExcluded = excludedSet.has(t.id);
              return (
                <li
                  key={t.id}
                  className={cn(
                    "flex items-start gap-3 p-2",
                    isExcluded && "opacity-50",
                  )}
                >
                  <Checkbox
                    checked={selected.has(t.id)}
                    onCheckedChange={() => toggle(t.id)}
                    disabled={isExcluded}
                    aria-label={`Selecionar ${t.title}`}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium truncate">{t.title}</div>
                    <div className="flex gap-1 mt-1">
                      <Badge variant="secondary" className="text-xs">
                        {t.severity}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {t.status}
                      </Badge>
                      {isExcluded && (
                        <Badge variant="outline" className="text-xs">
                          já no plano
                        </Badge>
                      )}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </div>

        <DialogFooter>
          <span className="mr-auto text-sm text-muted-foreground">
            {selected.size} selecionada(s)
          </span>
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={submitting}
          >
            Cancelar
          </Button>
          <Button
            onClick={handleConfirm}
            disabled={selected.size === 0 || submitting}
          >
            {submitting ? "Associando..." : "Associar"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
