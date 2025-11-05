import { useQuery } from '@tanstack/react-query';
import { Checkbox } from '@/components/ui/checkbox';
import { FormLabel } from '@/components/ui/form';

interface TagSelectorProps {
  selectedTags: string[];
  onTagsChange: (tags: string[]) => void;
}

export function TagSelector({ selectedTags, onTagsChange }: TagSelectorProps) {
  const { data: availableTags = [], isLoading } = useQuery<string[]>({
    queryKey: ['/api/assets/tags/unique'],
  });

  const handleTagToggle = (tag: string, checked: boolean) => {
    if (checked) {
      onTagsChange([...selectedTags, tag]);
    } else {
      onTagsChange(selectedTags.filter(t => t !== tag));
    }
  };

  if (isLoading) {
    return (
      <div className="text-sm text-muted-foreground">
        Carregando TAGs disponíveis...
      </div>
    );
  }

  if (availableTags.length === 0) {
    return (
      <div className="text-sm text-muted-foreground">
        Nenhuma TAG disponível. Adicione TAGs aos seus alvos primeiro.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <FormLabel>Selecionar TAGs</FormLabel>
      <div className="mt-2 space-y-2 max-h-40 overflow-y-auto border rounded-md p-3">
        {availableTags.map((tag) => (
          <div key={tag} className="flex items-center space-x-2">
            <Checkbox
              id={`tag-${tag}`}
              checked={selectedTags.includes(tag)}
              onCheckedChange={(checked) => handleTagToggle(tag, checked as boolean)}
              data-testid={`checkbox-tag-${tag}`}
            />
            <label htmlFor={`tag-${tag}`} className="text-sm cursor-pointer">
              {tag}
            </label>
          </div>
        ))}
      </div>
      {selectedTags.length > 0 && (
        <p className="text-sm text-muted-foreground">
          {selectedTags.length} TAG(s) selecionada(s)
        </p>
      )}
    </div>
  );
}
