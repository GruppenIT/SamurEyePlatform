import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { X } from "lucide-react";
import { AssetFormData } from "@/types";

const assetSchema = z.object({
  type: z.enum(['host', 'range'], {
    required_error: "Tipo de ativo é obrigatório",
  }),
  value: z.string().min(1, "Valor é obrigatório"),
  tags: z.array(z.string()).default([]),
});

interface AssetFormProps {
  onSubmit: (data: AssetFormData) => void;
  onCancel: () => void;
  isLoading?: boolean;
  initialData?: Partial<AssetFormData>;
}

export default function AssetForm({ onSubmit, onCancel, isLoading = false, initialData }: AssetFormProps) {
  const [tagInput, setTagInput] = useState("");

  const form = useForm<AssetFormData>({
    resolver: zodResolver(assetSchema),
    defaultValues: {
      type: initialData?.type || 'host',
      value: initialData?.value || '',
      tags: initialData?.tags || [],
    },
  });

  const watchedType = form.watch('type');
  const watchedTags = form.watch('tags');

  const addTag = () => {
    if (tagInput.trim() && !watchedTags.includes(tagInput.trim())) {
      form.setValue('tags', [...watchedTags, tagInput.trim()]);
      setTagInput("");
    }
  };

  const removeTag = (tagToRemove: string) => {
    form.setValue('tags', watchedTags.filter(tag => tag !== tagToRemove));
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addTag();
    }
  };

  const getValuePlaceholder = () => {
    switch (watchedType) {
      case 'host':
        return 'Ex: 192.168.1.10 ou web-server.corp.local';
      case 'range':
        return 'Ex: 192.168.1.0/24 ou 10.0.0.1-10.0.0.50';
      default:
        return '';
    }
  };

  const getValueDescription = () => {
    switch (watchedType) {
      case 'host':
        return 'IP único (IPv4/IPv6) ou FQDN';
      case 'range':
        return 'Notação CIDR ou intervalo com hífen';
      default:
        return '';
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="type"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Tipo de Ativo</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger data-testid="select-asset-type">
                    <SelectValue placeholder="Selecione o tipo" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="host">Host Individual</SelectItem>
                  <SelectItem value="range">Faixa de IPs</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="value"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Valor</FormLabel>
              <FormControl>
                <Input
                  placeholder={getValuePlaceholder()}
                  {...field}
                  data-testid="input-asset-value"
                />
              </FormControl>
              <FormDescription>{getValueDescription()}</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="tags"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Tags</FormLabel>
              <div className="space-y-2">
                <div className="flex space-x-2">
                  <Input
                    placeholder="Digite uma tag"
                    value={tagInput}
                    onChange={(e) => setTagInput(e.target.value)}
                    onKeyPress={handleKeyPress}
                    data-testid="input-tag"
                  />
                  <Button
                    type="button"
                    variant="outline"
                    onClick={addTag}
                    disabled={!tagInput.trim()}
                    data-testid="button-add-tag"
                  >
                    Adicionar
                  </Button>
                </div>
                {watchedTags.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {watchedTags.map((tag, index) => (
                      <Badge
                        key={index}
                        variant="secondary"
                        className="flex items-center gap-1"
                      >
                        {tag}
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="h-auto p-0 text-muted-foreground hover:text-foreground"
                          onClick={() => removeTag(tag)}
                          data-testid={`button-remove-tag-${index}`}
                        >
                          <X className="h-3 w-3" />
                        </Button>
                      </Badge>
                    ))}
                  </div>
                )}
              </div>
              <FormDescription>
                Tags ajudam a organizar e filtrar seus ativos
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex justify-end space-x-2">
          <Button
            type="button"
            variant="outline"
            onClick={onCancel}
            disabled={isLoading}
            data-testid="button-cancel"
          >
            Cancelar
          </Button>
          <Button
            type="submit"
            disabled={isLoading}
            data-testid="button-submit"
          >
            {isLoading ? 'Salvando...' : 'Salvar Ativo'}
          </Button>
        </div>
      </form>
    </Form>
  );
}
