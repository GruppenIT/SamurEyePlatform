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
import { CredentialFormData } from "@/types";

const credentialSchema = z.object({
  name: z.string().min(1, "Nome é obrigatório"),
  type: z.enum(['ssh', 'wmi', 'omi', 'ad'], {
    required_error: "Tipo de credencial é obrigatório",
  }),
  hostOverride: z.string().optional(),
  port: z.number().min(1).max(65535).optional(),
  username: z.string().min(1, "Usuário é obrigatório"),
  secret: z.string().min(1, "Senha/chave é obrigatória"),
});

interface CredentialFormProps {
  onSubmit: (data: CredentialFormData) => void;
  onCancel: () => void;
  isLoading?: boolean;
}

export default function CredentialForm({ onSubmit, onCancel, isLoading = false }: CredentialFormProps) {
  const form = useForm<CredentialFormData>({
    resolver: zodResolver(credentialSchema),
    defaultValues: {
      name: '',
      type: 'ssh',
      hostOverride: '',
      port: undefined,
      username: '',
      secret: '',
    },
  });

  const watchedType = form.watch('type');

  const getDefaultPort = () => {
    switch (watchedType) {
      case 'ssh':
        return 22;
      case 'wmi':
        return 135;
      case 'omi':
        return 5985;
      case 'ad':
        return 389;
      default:
        return undefined;
    }
  };

  const getSecretLabel = () => {
    switch (watchedType) {
      case 'ssh':
        return 'Senha ou Chave Privada';
      case 'wmi':
      case 'omi':
      case 'ad':
        return 'Senha';
      default:
        return 'Senha/Chave';
    }
  };

  const getSecretPlaceholder = () => {
    switch (watchedType) {
      case 'ssh':
        return 'Senha ou conteúdo da chave privada';
      case 'wmi':
      case 'omi':
        return 'Senha do usuário';
      case 'ad':
        return 'Senha do usuário Active Directory';
      default:
        return '';
    }
  };

  // Set default port when type changes
  const handleTypeChange = (value: string) => {
    form.setValue('type', value as any);
    const defaultPort = getDefaultPort();
    if (defaultPort) {
      form.setValue('port', defaultPort);
    }
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Nome da Credencial</FormLabel>
              <FormControl>
                <Input
                  placeholder="Ex: SSH Admin Produção"
                  {...field}
                  data-testid="input-credential-name"
                />
              </FormControl>
              <FormDescription>
                Nome descritivo para identificar esta credencial
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="type"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Tipo de Credencial</FormLabel>
              <Select onValueChange={handleTypeChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger data-testid="select-credential-type">
                    <SelectValue placeholder="Selecione o tipo" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="ssh">SSH</SelectItem>
                  <SelectItem value="wmi">WMI (Windows)</SelectItem>
                  <SelectItem value="omi">OMI (Linux/Unix)</SelectItem>
                  <SelectItem value="ad">AD/LDAP</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="grid grid-cols-2 gap-4">
          <FormField
            control={form.control}
            name="hostOverride"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Host Específico (Opcional)</FormLabel>
                <FormControl>
                  <Input
                    placeholder="Ex: 192.168.1.10"
                    {...field}
                    data-testid="input-host-override"
                  />
                </FormControl>
                <FormDescription>
                  Deixe vazio para usar com qualquer host
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="port"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Porta</FormLabel>
                <FormControl>
                  <Input
                    type="number"
                    placeholder={getDefaultPort()?.toString()}
                    {...field}
                    value={field.value || ''}
                    onChange={(e) => {
                      const value = e.target.value;
                      field.onChange(value ? parseInt(value) : undefined);
                    }}
                    data-testid="input-port"
                  />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="username"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Usuário</FormLabel>
              <FormControl>
                <Input
                  placeholder="Ex: administrator ou root"
                  {...field}
                  data-testid="input-username"
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="secret"
          render={({ field }) => (
            <FormItem>
              <FormLabel>{getSecretLabel()}</FormLabel>
              <FormControl>
                <textarea
                  className="flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                  placeholder={getSecretPlaceholder()}
                  {...field}
                  data-testid="textarea-secret"
                />
              </FormControl>
              <FormDescription>
                Esta informação será criptografada e armazenada com segurança
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
            {isLoading ? 'Salvando...' : 'Salvar Credencial'}
          </Button>
        </div>
      </form>
    </Form>
  );
}
