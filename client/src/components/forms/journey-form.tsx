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
      params: {
        ...initialData?.params,
        edrAvType: initialData?.params?.edrAvType || 'network_based',
        sampleRate: initialData?.params?.sampleRate || '15',
        timeout: initialData?.params?.timeout || 30,
        webScanEnabled: initialData?.params?.webScanEnabled ?? false,
        processTimeout: initialData?.params?.processTimeout || 60,
      },
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
        params.webScanEnabled = form.getValues('params.webScanEnabled') ?? false;
        params.processTimeout = parseInt(form.getValues('params.processTimeout')) || 60;
        break;
      case 'ad_hygiene':
        params.domain = form.getValues('params.domain');
        params.credentialId = form.getValues('params.credentialId');
        // Incluir configurações de análises habilitadas
        params.enableUsers = form.getValues('params.enableUsers') ?? true;
        params.enableGroups = form.getValues('params.enableGroups') ?? true;
        params.enableComputers = form.getValues('params.enableComputers') ?? true;
        params.enablePolicies = form.getValues('params.enablePolicies') ?? true;
        params.enableConfiguration = form.getValues('params.enableConfiguration') ?? true;
        params.enableDomainConfiguration = form.getValues('params.enableDomainConfiguration') ?? true;
        break;
      case 'edr_av':
        params.edrAvType = form.getValues('params.edrAvType') || 'network_based';
        params.sampleRate = parseInt(form.getValues('params.sampleRate')) || 15;
        params.timeout = parseInt(form.getValues('params.timeout')) || 30;
        params.credentialId = form.getValues('params.credentialId');
        
        // Parâmetros específicos por tipo
        if (params.edrAvType === 'ad_based') {
          params.domainName = form.getValues('params.domainName');
        } else if (params.edrAvType === 'network_based') {
          params.assetIds = form.getValues('params.assetIds') || [];
          // Fallback para targets se assetIds não estiver definido (compatibilidade)
          if (params.assetIds.length === 0 && selectedAssets.length > 0) {
            params.assetIds = selectedAssets;
          }
        }
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
              <FormLabel>Alvos Selecionados</FormLabel>
              <div className="mt-2 space-y-2 max-h-40 overflow-y-auto border rounded-md p-3">
                {assets.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Nenhum alvo disponível. Crie alvos primeiro.
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
                Selecione os alvos para incluir na varredura
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

            <FormField
              control={form.control}
              name="params.webScanEnabled"
              render={({ field }) => (
                <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4">
                  <FormControl>
                    <Checkbox
                      checked={field.value}
                      onCheckedChange={field.onChange}
                      data-testid="checkbox-web-scan"
                    />
                  </FormControl>
                  <div className="space-y-1 leading-none">
                    <FormLabel>
                      Varrer aplicações web identificadas?
                    </FormLabel>
                    <FormDescription>
                      Quando habilitado, executa Nuclei em portas HTTP/HTTPS detectadas para identificar vulnerabilidades em aplicações web
                    </FormDescription>
                  </div>
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="params.processTimeout"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Timeout por Processo (minutos)</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min="5"
                      max="180"
                      placeholder="60"
                      {...field}
                      onChange={(e) => field.onChange(parseInt(e.target.value) || 60)}
                      data-testid="input-process-timeout"
                    />
                  </FormControl>
                  <FormDescription>
                    Tempo máximo de execução por host (nmap/nuclei). Mínimo: 5min, Máximo: 180min, Padrão: 60min
                  </FormDescription>
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
                  Selecione os testes para executar:
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                  <FormField
                    control={form.control}
                    name="params.enableUsers"
                    render={({ field }) => (
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-ad-users"
                        />
                        <label className="text-sm font-medium">
                          Análise de Usuários
                        </label>
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="params.enableGroups"
                    render={({ field }) => (
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-ad-groups"
                        />
                        <label className="text-sm font-medium">
                          Análise de Grupos Privilegiados
                        </label>
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="params.enableComputers"
                    render={({ field }) => (
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-ad-computers"
                        />
                        <label className="text-sm font-medium">
                          Análise de Computadores
                        </label>
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="params.enablePolicies"
                    render={({ field }) => (
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-ad-policies"
                        />
                        <label className="text-sm font-medium">
                          Análise de Políticas
                        </label>
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="params.enableConfiguration"
                    render={({ field }) => (
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-ad-configuration"
                        />
                        <label className="text-sm font-medium">
                          Configurações de Domínio
                        </label>
                      </div>
                    )}
                  />
                  <FormField
                    control={form.control}
                    name="params.enableDomainConfiguration"
                    render={({ field }) => (
                      <div className="flex items-center space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-ad-domain-config"
                        />
                        <label className="text-sm font-medium">
                          Análise Avançada de Domínio
                        </label>
                      </div>
                    )}
                  />
                </div>

                <div className="mt-4 pt-3 border-t">
                  <div className="text-sm font-medium text-foreground mb-2">
                    Verificações incluídas quando habilitadas:
                  </div>
                  <div className="grid grid-cols-1 gap-1 text-xs">
                    <div className="text-red-600 dark:text-red-400">
                      🚨 Domain Admins com senhas antigas (Severidade: CRÍTICA)
                    </div>
                    <div className="text-blue-600 dark:text-blue-400">
                      ℹ️ Usuários inativos por período configurado (Severidade: BAIXA)
                    </div>
                    <div>• Usuários com senhas que nunca expiram</div>
                    <div>• Grupos privilegiados com muitos membros</div>
                    <div>• Sistemas operacionais obsoletos</div>
                    <div>• Computadores inativos no domínio</div>
                    <div>• Políticas de senha fracas</div>
                    <div>• Trusts bidirecionais de domínio</div>
                  </div>
                </div>
              </div>
              <FormDescription>
                Selecione os módulos de análise para executar. Os limites são configuráveis nas configurações do sistema.
              </FormDescription>
            </div>
          </div>
        );

      case 'edr_av':
        return (
          <div className="space-y-4">
            <FormField
              control={form.control}
              name="params.edrAvType"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Tipo de Jornada EDR/AV</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-edr-type">
                        <SelectValue placeholder="Selecione o tipo de jornada" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="ad_based">AD Based - Descoberta via LDAP</SelectItem>
                      <SelectItem value="network_based">Network Based - Alvos específicos</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormDescription>
                    Escolha entre descoberta automática via Active Directory ou alvos específicos
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {form.watch('params.edrAvType') === 'ad_based' && (
              <div className="space-y-4 border rounded-lg p-4 bg-muted/20">
                <div className="text-sm font-medium text-foreground">Configuração AD Based</div>
                
                <FormField
                  control={form.control}
                  name="params.credentialId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Credencial LDAP/AD</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger data-testid="select-ad-credential">
                            <SelectValue placeholder="Selecione uma credencial AD" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {credentials
                            .filter(cred => cred.type === 'ad')
                            .map((credential) => (
                              <SelectItem key={credential.id} value={credential.id}>
                                {credential.name}{credential.domain ? ` (${credential.domain})` : ''}
                              </SelectItem>
                            ))}
                        </SelectContent>
                      </Select>
                      <FormDescription>
                        Credencial com privilégios para consultar LDAP e acessar compartilhamentos administrativos
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="params.domainName"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Nome do Domínio</FormLabel>
                      <FormControl>
                        <Input
                          placeholder="Ex: contoso.com"
                          {...field}
                          data-testid="input-domain-name"
                        />
                      </FormControl>
                      <FormDescription>
                        Domínio Active Directory para consultar contas de computador
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            )}

            {form.watch('params.edrAvType') === 'network_based' && (
              <div className="space-y-4 border rounded-lg p-4 bg-muted/20">
                <div className="text-sm font-medium text-foreground">Configuração Network Based</div>
                
                <FormField
                  control={form.control}
                  name="params.credentialId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Credencial Administrativa</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger data-testid="select-network-credential">
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
                        Credencial com privilégios administrativos para acessar compartilhamentos C$
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="params.assetIds"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Alvos/Targets</FormLabel>
                      <Select 
                        onValueChange={(value) => {
                          const currentValues = field.value || [];
                          const newValues = currentValues.includes(value) 
                            ? currentValues.filter((v: string) => v !== value)
                            : [...currentValues, value];
                          field.onChange(newValues);
                        }}
                      >
                        <FormControl>
                          <SelectTrigger data-testid="select-assets">
                            <SelectValue placeholder="Selecione alvos para teste" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {assets.map((asset) => (
                            <SelectItem key={asset.id} value={asset.id}>
                              {asset.value} ({asset.type})
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <div className="text-sm text-muted-foreground mt-1">
                        Selecionados: {(field.value || []).length} alvos
                      </div>
                      <FormDescription>
                        Selecione hosts ou ranges de rede para testar
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            )}

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
              name="params.timeout"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Timeout Teste EICAR (segundos)</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min="10"
                      max="300"
                      placeholder="30"
                      {...field}
                      data-testid="input-edr-timeout"
                    />
                  </FormControl>
                  <FormDescription>
                    Tempo para aguardar detecção/remoção do arquivo EICAR pelo EDR/AV
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
