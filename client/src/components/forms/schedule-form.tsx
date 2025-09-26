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
  // Campos para execução única
  onceAt: z.date().optional(),
  // Campos para execução recorrente
  recurrenceType: z.enum(['daily', 'weekly', 'monthly']).optional(),
  hour: z.number().min(0).max(23).optional(),
  minute: z.number().min(0).max(59).default(0),
  dayOfWeek: z.number().min(0).max(6).optional(), // 0=Sunday, 6=Saturday
  dayOfMonth: z.number().min(1).max(31).optional(),
  // Campos legados
  cronExpression: z.string().optional(),
  enabled: z.boolean().default(true),
}).refine(data => {
  // Validação para execução única
  if (data.kind === 'once') {
    return data.onceAt != null;
  }
  // Validação para execução recorrente
  if (data.kind === 'recurring') {
    if (!data.recurrenceType) return false;
    if (data.hour == null) return false;
    
    // Validação específica por tipo de recorrência
    if (data.recurrenceType === 'weekly' && data.dayOfWeek == null) return false;
    if (data.recurrenceType === 'monthly' && data.dayOfMonth == null) return false;
  }
  return true;
}, {
  message: "Configuração de agendamento inválida",
  path: ["recurrenceType"],
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
      // Campos para execução única
      onceAt: initialData?.onceAt || undefined,
      // Campos para execução recorrente
      recurrenceType: initialData?.recurrenceType || undefined,
      hour: initialData?.hour || 9, // 9h por padrão
      minute: initialData?.minute || 0,
      dayOfWeek: initialData?.dayOfWeek || 1, // Segunda-feira por padrão
      dayOfMonth: initialData?.dayOfMonth || 1, // Dia 1 por padrão
      // Campos legados
      cronExpression: initialData?.cronExpression || '',
      enabled: initialData?.enabled ?? true,
    },
  });

  const watchedKind = form.watch('kind');
  const watchedRecurrenceType = form.watch('recurrenceType');

  // Fetch journeys for selection
  const { data: journeys = [] } = useQuery<Journey[]>({
    queryKey: ["/api/journeys"],
  });

  const daysOfWeek = [
    { value: 0, label: "Domingo" },
    { value: 1, label: "Segunda-feira" },
    { value: 2, label: "Terça-feira" },
    { value: 3, label: "Quarta-feira" },
    { value: 4, label: "Quinta-feira" },
    { value: 5, label: "Sexta-feira" },
    { value: 6, label: "Sábado" },
  ];

  const handleSubmit = (data: ScheduleFormData) => {
    // Convert onceAt to proper format if needed
    const submitData = { ...data };
    
    if (data.kind === 'once' && data.onceAt) {
      submitData.onceAt = new Date(data.onceAt);
    }
    
    // Limpar campos não utilizados baseado no tipo
    if (data.kind !== 'recurring') {
      submitData.recurrenceType = undefined;
      submitData.hour = undefined;
      submitData.minute = undefined;
      submitData.dayOfWeek = undefined;
      submitData.dayOfMonth = undefined;
      submitData.cronExpression = undefined;
    }
    
    if (data.kind !== 'once') {
      submitData.onceAt = undefined;
    }
    
    if (data.kind === 'on_demand') {
      submitData.recurrenceType = undefined;
      submitData.hour = undefined;
      submitData.minute = undefined;
      submitData.dayOfWeek = undefined;
      submitData.dayOfMonth = undefined;
      submitData.cronExpression = undefined;
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
              name="recurrenceType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Tipo de Recorrência</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-recurrence-type">
                        <SelectValue placeholder="Selecione a frequência" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="daily">Diário</SelectItem>
                      <SelectItem value="weekly">Semanal</SelectItem>
                      <SelectItem value="monthly">Mensal</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Com que frequência a jornada deve ser executada
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Campos de horário (sempre visíveis para recorrente) */}
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="hour"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Hora</FormLabel>
                    <Select 
                      onValueChange={(value) => field.onChange(parseInt(value))} 
                      value={field.value?.toString()}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-hour">
                          <SelectValue placeholder="00" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent className="max-h-48">
                        {Array.from({ length: 24 }, (_, i) => (
                          <SelectItem key={i} value={i.toString()}>
                            {i.toString().padStart(2, '0')}h
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
                name="minute"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Minuto</FormLabel>
                    <Select 
                      onValueChange={(value) => field.onChange(parseInt(value))} 
                      value={field.value?.toString()}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-minute">
                          <SelectValue placeholder="00" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent className="max-h-48">
                        {Array.from({ length: 60 }, (_, i) => (
                          <SelectItem key={i} value={i.toString()}>
                            {i.toString().padStart(2, '0')}min
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* Campos específicos baseados no tipo de recorrência */}
            {watchedRecurrenceType === 'weekly' && (
              <FormField
                control={form.control}
                name="dayOfWeek"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Dia da Semana</FormLabel>
                    <Select 
                      onValueChange={(value) => field.onChange(parseInt(value))} 
                      value={field.value?.toString()}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-day-of-week">
                          <SelectValue placeholder="Selecione o dia" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {daysOfWeek.map((day) => (
                          <SelectItem key={day.value} value={day.value.toString()}>
                            {day.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormDescription>
                      Em qual dia da semana executar
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}

            {watchedRecurrenceType === 'monthly' && (
              <FormField
                control={form.control}
                name="dayOfMonth"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Dia do Mês</FormLabel>
                    <Select 
                      onValueChange={(value) => field.onChange(parseInt(value))} 
                      value={field.value?.toString()}
                    >
                      <FormControl>
                        <SelectTrigger data-testid="select-day-of-month">
                          <SelectValue placeholder="Selecione o dia" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent className="max-h-48">
                        {Array.from({ length: 31 }, (_, i) => (
                          <SelectItem key={i + 1} value={(i + 1).toString()}>
                            Dia {i + 1}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormDescription>
                      Em qual dia do mês executar (para meses com menos dias, será ajustado automaticamente)
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            )}
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
