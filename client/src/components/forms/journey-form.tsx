import { useState } from "react";
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
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { JourneyFormData } from "@/types";
import { Asset, Credential } from "@shared/schema";

const journeySchema = z.object({
  name: z.string().min(1, "Nome é obrigatório"),
  type: z.enum(['attack_surface', 'ad_hygiene', 'edr_av'], {
    required_error: "Tipo de jornada é obrigatório",
  }),
  description: z.string().optional(),
  params: z.record(z.any()).default({}),
});

interface JourneyFormProps {
  onSubmit: (data: JourneyFormData) => void;
  onCancel: () => void;
  isLoading?: boolean;
  initialData?: Partial<JourneyFormData>;
}

export default function JourneyForm({ onSubmit, onCancel, isLoading = false, initialData }: JourneyFormProps) {
  const [selectedAssets, setSelectedAssets] = useState<string[]>(
    initialData?.params?.assetIds || []
  );

  const form = useForm<JourneyFormData>({
    resolver: zodResolver(journeySchema),
    defaultValues: {
      name: initialData?.name || '',
      type: initialData?.type || 'attack_surface',
      description: initialData?.description || '',
      params: initialData?.params || {},
    },
  });

  const watchedType = form.watch('type');

  // Fetch assets and credentials for form options
  const { data: assets = [] } = useQuery<Asset[]>({
    queryKey: ["/api/assets"],
  });

  const { data: credentials = [] } = useQuery<Credential[]>({
    queryKey: ["/api/credentials"],
  });

  const handleAssetSelection = (assetId: string, checked: boolean) => {
    if (checked) {
      setSelectedAssets([...selectedAssets, assetId]);
    } else {
      setSelectedAssets(selectedAssets.filter(id => id !== assetId));
    }
  };

  const handleSubmit = (data: JourneyFormData) => {
    const params: Record<string, any> = {};

    switch (data.type) {
      case 'attack_surface':
        params.assetIds = selectedAssets;
        params.nmapProfile = form.getValues('params.nmapProfile') || 'fast';
        params.nucleiSeverity = form.getValues('params.nucleiSeverity') || 'medium';
        break;
      case 'ad_hygiene':
        params.domain = form.getValues('params.domain');
        params.credentialId = form.getValues('params.credentialId');
        break;
      case 'edr_av':
        params.sampleRate = parseInt(form.getValues('params.sampleRate')) || 15;
        params.credentialId = form.getValues('params.credentialId');
        break;
    }

    onSubmit({
      ...data,
      params,
    });
  };

  const renderTypeSpecificFields = () => {
    switch (watchedType) {
      case 'attack_surface':
        return (
          <div className="space-y-4">
            <div>
              <FormLabel>Ativos Selecionados</FormLabel>
              <div className="mt-2 space-y-2 max-h-40 overflow-y-auto border rounded-md p-3">
                {assets.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Nenhum ativo disponível. Crie ativos primeiro.
                  </p>
                ) : (
                  assets.map((asset) => (
                    <div key={asset.id} className="flex items-center space-x-2">
                      <Checkbox
                        id={asset.id}
                        checked={selectedAssets.includes(asset.id)}
                        onCheckedChange={(checked) => 
                          handleAssetSelection(asset.id, checked as boolean)
                        }
                        data-testid={`checkbox-asset-${asset.id}`}
                      />
                      <label htmlFor={asset.id} className="text-sm">
                        {asset.value} ({asset.type})
                      </label>
                    </div>
                  ))
                )}
              </div>
              <FormDescription>
                Selecione os ativos para incluir na varredura
              </FormDescription>
            </div>

            <FormField
              control={form.control}
              name="params.nmapProfile"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Perfil Nmap</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue="fast">
                    <FormControl>
                      <SelectTrigger data-testid="select-nmap-profile">
                        <SelectValue placeholder="Selecione o perfil" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="fast">Rápido (Top 1000 portas)</SelectItem>
                      <SelectItem value="comprehensive">Completo (Todas as portas)</SelectItem>
                      <SelectItem value="stealth">Stealth (SYN scan)</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="params.nucleiSeverity"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Severidade Mínima Nuclei</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue="medium">
                    <FormControl>
                      <SelectTrigger data-testid="select-nuclei-severity">
                        <SelectValue placeholder="Selecione a severidade" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="info">Info</SelectItem>
                      <SelectItem value="low">Baixa</SelectItem>
                      <SelectItem value="medium">Média</SelectItem>
                      <SelectItem value="high">Alta</SelectItem>
                      <SelectItem value="critical">Crítica</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        );

      case 'ad_hygiene':
        return (
          <div className="space-y-4">
            <FormField
              control={form.control}
              name="params.domain"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Domínio AD</FormLabel>
                  <FormControl>
                    <Input
                      placeholder="Ex: corp.local"
                      {...field}
                      data-testid="input-ad-domain"
                    />
                  </FormControl>
                  <FormDescription>
                    FQDN do domínio Active Directory
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="params.credentialId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Credencial</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-ad-credential">
                        <SelectValue placeholder="Selecione uma credencial" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {credentials
                        .filter(cred => cred.type === 'wmi' || cred.type === 'omi' || cred.type === 'ad')
                        .map((credential) => (
                          <SelectItem key={credential.id} value={credential.id}>
                            {credential.name} ({credential.type})
                          </SelectItem>
                        ))}
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Credencial com privilégios de leitura no AD (recomendado: tipo AD/LDAP)
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div>
              <FormLabel>Verificações de Higiene AD</FormLabel>
              <div className="mt-3 space-y-3 border rounded-md p-4 bg-muted/10">
                <div className="text-sm font-medium text-foreground mb-2">
                  Os seguintes testes serão executados:
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                  <div className="flex items-center space-x-2">
                    <Checkbox checked disabled />
                    <span>Análise de Usuários</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox checked disabled />
                    <span>Análise de Grupos Privilegiados</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox checked disabled />
                    <span>Análise de Computadores</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox checked disabled />
                    <span>Análise de Políticas</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Checkbox checked disabled />
                    <span>Configurações de Domínio</span>
                  </div>
                </div>

                <div className="mt-4 pt-3 border-t">
                  <div className="text-sm font-medium text-foreground mb-2">
                    Verificações de Segurança:
                  </div>
                  <div className="grid grid-cols-1 gap-2 text-sm">
                    <div className="flex items-center space-x-2">
                      <Checkbox checked disabled />
                      <span className="text-red-600 dark:text-red-400">
                        🚨 Domain Admins com senhas antigas (Severidade: CRÍTICA)
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox checked disabled />
                      <span className="text-blue-600 dark:text-blue-400">
                        ℹ️ Usuários inativos por período configurado (Severidade: BAIXA)
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox checked disabled />
                      <span>Usuários com senhas que nunca expiram</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox checked disabled />
                      <span>Grupos privilegiados com muitos membros</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox checked disabled />
                      <span>Sistemas operacionais obsoletos</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox checked disabled />
                      <span>Computadores inativos no domínio</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Checkbox checked disabled />
                      <span>Políticas de senha fracas</span>
                    </div>
                  </div>
                </div>
              </div>
              <FormDescription>
                Todos os testes são executados automaticamente. Os limites são configuráveis nas configurações do sistema.
              </FormDescription>
            </div>
          </div>
        );

      case 'edr_av':
        return (
          <div className="space-y-4">
            <FormField
              control={form.control}
              name="params.sampleRate"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Taxa de Amostragem (%)</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min="1"
                      max="100"
                      placeholder="15"
                      {...field}
                      data-testid="input-sample-rate"
                    />
                  </FormControl>
                  <FormDescription>
                    Porcentagem de workstations para testar (recomendado: 10-20%)
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="params.credentialId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Credencial Administrativa</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-edr-credential">
                        <SelectValue placeholder="Selecione uma credencial" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {credentials
                        .filter(cred => cred.type === 'wmi' || cred.type === 'omi' || cred.type === 'ad')
                        .map((credential) => (
                          <SelectItem key={credential.id} value={credential.id}>
                            {credential.name} ({credential.type})
                          </SelectItem>
                        ))}
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Credencial com privilégios administrativos (AD/LDAP, WMI ou OMI)
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
          </div>
        );

      default:
        return null;
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
              <FormLabel>Nome da Jornada</FormLabel>
              <FormControl>
                <Input
                  placeholder="Ex: Varredura Diária de Produção"
                  {...field}
                  data-testid="input-journey-name"
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="type"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Tipo de Jornada</FormLabel>
              <Select onValueChange={field.onChange} defaultValue={field.value}>
                <FormControl>
                  <SelectTrigger data-testid="select-journey-type">
                    <SelectValue placeholder="Selecione o tipo" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value="attack_surface">Attack Surface</SelectItem>
                  <SelectItem value="ad_hygiene">Higiene AD</SelectItem>
                  <SelectItem value="edr_av">Teste EDR/AV</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Descrição (Opcional)</FormLabel>
              <FormControl>
                <Textarea
                  placeholder="Descreva o objetivo desta jornada..."
                  {...field}
                  data-testid="textarea-description"
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        {renderTypeSpecificFields()}

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
            {isLoading ? 'Salvando...' : 'Salvar Jornada'}
          </Button>
        </div>
      </form>
    </Form>
  );
}
