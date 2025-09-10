import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useQuery } from "@tanstack/react-query";
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
import { Switch } from "@/components/ui/switch";
import { ScheduleFormData } from "@/types";
import { Journey } from "@shared/schema";

const scheduleSchema = z.object({
  journeyId: z.string().min(1, "Jornada é obrigatória"),
  name: z.string().min(1, "Nome é obrigatório"),
  kind: z.enum(['on_demand', 'once', 'recurring'], {
    required_error: "Tipo de agendamento é obrigatório",
  }),
  cronExpression: z.string().optional(),
  onceAt: z.date().optional(),
  enabled: z.boolean().default(true),
});

interface ScheduleFormProps {
  onSubmit: (data: ScheduleFormData) => void;
  onCancel: () => void;
  isLoading?: boolean;
  initialData?: Partial<ScheduleFormData>;
}

export default function ScheduleForm({ onSubmit, onCancel, isLoading = false, initialData }: ScheduleFormProps) {
  const form = useForm<ScheduleFormData>({
    resolver: zodResolver(scheduleSchema),
    defaultValues: {
      journeyId: initialData?.journeyId || '',
      name: initialData?.name || '',
      kind: initialData?.kind || 'once',
      cronExpression: initialData?.cronExpression || '',
      onceAt: initialData?.onceAt || undefined,
      enabled: initialData?.enabled ?? true,
    },
  });

  const watchedKind = form.watch('kind');

  // Fetch journeys for selection
  const { data: journeys = [] } = useQuery<Journey[]>({
    queryKey: ["/api/journeys"],
  });

  const cronPresets = [
    { label: "Diário às 02:00", value: "0 2 * * *" },
    { label: "Semanal (Segunda às 06:00)", value: "0 6 * * 1" },
    { label: "Mensal (dia 1 às 03:00)", value: "0 3 1 * *" },
    { label: "A cada 6 horas", value: "0 */6 * * *" },
    { label: "A cada 12 horas", value: "0 */12 * * *" },
  ];

  const handleSubmit = (data: ScheduleFormData) => {
    // Convert onceAt to proper format if needed
    const submitData = { ...data };
    
    if (data.kind === 'once' && data.onceAt) {
      submitData.onceAt = new Date(data.onceAt);
    }
    
    if (data.kind !== 'recurring') {
      submitData.cronExpression = undefined;
    }
    
    if (data.kind !== 'once') {
      submitData.onceAt = undefined;
    }

    onSubmit(submitData);
  };

  const renderKindSpecificFields = () => {
    switch (watchedKind) {
      case 'once':
        return (
          <FormField
            control={form.control}
            name="onceAt"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Data e Hora</FormLabel>
                <FormControl>
                  <Input
                    type="datetime-local"
                    {...field}
                    value={field.value ? new Date(field.value).toISOString().slice(0, 16) : ''}
                    onChange={(e) => field.onChange(e.target.value ? new Date(e.target.value) : undefined)}
                    data-testid="input-once-at"
                  />
                </FormControl>
                <FormDescription>
                  Quando executar esta jornada uma única vez
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        );

      case 'recurring':
        return (
          <div className="space-y-4">
            <FormField
              control={form.control}
              name="cronExpression"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Expressão CRON</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="0 2 * * * (diário às 02:00)"
                      {...field}
                      data-testid="input-cron-expression"
                    />
                  </FormControl>
                  <FormDescription>
                    Formato: minuto hora dia mês dia-da-semana
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div>
              <FormLabel>Presets Comuns</FormLabel>
              <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-2">
                {cronPresets.map((preset, index) => (
                  <Button
                    key={index}
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => form.setValue('cronExpression', preset.value)}
                    className="justify-start"
                    data-testid={`button-cron-preset-${index}`}
                  >
                    {preset.label}
                  </Button>
                ))}
              </div>
            </div>
          </div>
        );

      default:
        return (
          <div className="p-4 bg-muted/30 rounded-lg">
            <p className="text-sm text-muted-foreground">
              Execução sob demanda - será executado imediatamente quando solicitado
            </p>
          </div>
        );
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Nome do Agendamento</FormLabel>
              <FormControl>
                <Input
                  placeholder="Ex: Varredura Diária de Produção"
                  {...field}
                  data-testid="input-schedule-name"
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="journeyId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Jornada</FormLabel>
              <Select onValueChange={field.onChange} value={field.value}>
                <FormControl>
                  <SelectTrigger data-testid="select-journey">
                    <SelectValue placeholder="Selecione uma jornada" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {journeys.map((journey) => (
                    <SelectItem key={journey.id} value={journey.id}>
                      {journey.name} ({journey.type})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="kind"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Tipo de Agendamento</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger data-testid="select-schedule-kind">
                    <SelectValue placeholder="Selecione o tipo" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="on_demand">Sob Demanda</SelectItem>
                  <SelectItem value="once">Execução Única</SelectItem>
                  <SelectItem value="recurring">Recorrente</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        {renderKindSpecificFields()}

        <FormField
          control={form.control}
          name="enabled"
          render={({ field }) => (
            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
              <div className="space-y-0.5">
                <FormLabel className="text-base">Agendamento Ativo</FormLabel>
                <FormDescription>
                  Desative para pausar este agendamento sem removê-lo
                </FormDescription>
              </div>
              <FormControl>
                <Switch
                  checked={field.value}
                  onCheckedChange={field.onChange}
                  data-testid="switch-enabled"
                />
              </FormControl>
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
            {isLoading ? 'Salvando...' : 'Salvar Agendamento'}
          </Button>
        </div>
      </form>
    </Form>
  );
}
