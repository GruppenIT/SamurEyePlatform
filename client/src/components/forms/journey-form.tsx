import { useState, useEffect, useRef } from "react";
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
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { TagSelector } from "./tag-selector";
import { JourneyFormData } from "@/types";
import { Asset, Credential } from "@shared/schema";

const journeySchema = z.object({
  name: z.string().min(1, "Nome é obrigatório"),
  type: z.enum(['attack_surface', 'ad_security', 'edr_av', 'web_application'], {
    required_error: "Tipo de jornada é obrigatório",
  }),
  description: z.string().optional(),
  params: z.record(z.any()).default({}),
  enableCveDetection: z.boolean().optional(),
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
  const [targetSelectionMode, setTargetSelectionMode] = useState<'individual' | 'by_tag'>(
    initialData?.targetSelectionMode || 'individual'
  );
  const [selectedTags, setSelectedTags] = useState<string[]>(
    initialData?.selectedTags || []
  );
  const [selectedCredentials, setSelectedCredentials] = useState<Array<{credentialId: string; protocol: 'wmi' | 'ssh' | 'snmp'; priority: number}>>(
    initialData?.credentials || []
  );
  const [enableAuthentication, setEnableAuthentication] = useState<boolean>(
    !!(initialData?.credentials && initialData.credentials.length > 0)
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
        processTimeout: initialData?.params?.processTimeout || 60,
        vulnScriptTimeout: initialData?.params?.vulnScriptTimeout || 60,
      },
      enableCveDetection: initialData?.enableCveDetection !== false,
    },
  });

  const watchedType = form.watch('type');
  const isHydrated = useRef(false);

  // Hydrate authentication state when initialData changes (e.g., when editing journey)
  useEffect(() => {
    if (initialData?.credentials && initialData.credentials.length > 0 && !isHydrated.current) {
      setSelectedCredentials(initialData.credentials);
      setEnableAuthentication(true);
      isHydrated.current = true;
    }
  }, [initialData]);

  // Fetch assets and credentials for form options
  const { data: assets = [] } = useQuery<Asset[]>({
    queryKey: ["/api/assets"],
  });

  const { data: webApplicationAssets = [] } = useQuery<Asset[]>({
    queryKey: ["/api/assets/by-type/web_application"],
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
    // Validação de alvos selecionados
    if (data.type === 'attack_surface' || (data.type === 'edr_av' && form.getValues('params.edrAvType') === 'network_based')) {
      if (targetSelectionMode === 'individual' && selectedAssets.length === 0) {
        alert('Por favor, selecione pelo menos um alvo');
        return;
      }
      if (targetSelectionMode === 'by_tag' && selectedTags.length === 0) {
        alert('Por favor, selecione pelo menos uma TAG');
        return;
      }
    }

    const params: Record<string, any> = {};

    switch (data.type) {
      case 'attack_surface':
        // Target selection
        if (targetSelectionMode === 'by_tag') {
          params.assetIds = []; // Will be resolved from tags on backend
        } else {
          params.assetIds = selectedAssets;
        }
        params.nmapProfile = form.getValues('params.nmapProfile') || 'fast';
        params.vulnScriptTimeout = parseInt(form.getValues('params.vulnScriptTimeout')) || 60;
        
        // Add credentials if authentication is enabled
        if (enableAuthentication && selectedCredentials.length > 0) {
          (data as any).credentials = selectedCredentials;
        }
        break;
      case 'ad_security':
        params.domain = form.getValues('params.domain');
        params.credentialId = form.getValues('params.credentialId');
        params.primaryDC = form.getValues('params.primaryDC');
        params.secondaryDC = form.getValues('params.secondaryDC');
        // Categorias de testes habilitadas (padrão: todas)
        params.enabledCategories = {
          configuracoes_criticas: form.getValues('params.enabledCategories.configuracoes_criticas') ?? true,
          gerenciamento_contas: form.getValues('params.enabledCategories.gerenciamento_contas') ?? true,
          kerberos_delegacao: form.getValues('params.enabledCategories.kerberos_delegacao') ?? true,
          compartilhamentos_gpos: form.getValues('params.enabledCategories.compartilhamentos_gpos') ?? true,
          politicas_configuracao: form.getValues('params.enabledCategories.politicas_configuracao') ?? true,
          contas_inativas: form.getValues('params.enabledCategories.contas_inativas') ?? true,
        };
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
          // Target selection
          if (targetSelectionMode === 'by_tag') {
            params.assetIds = []; // Will be resolved from tags on backend
          } else {
            params.assetIds = selectedAssets;
          }
        }
        break;
      case 'web_application':
        params.assetIds = selectedAssets;
        params.processTimeout = parseInt(form.getValues('params.processTimeout')) || 60;
        break;
    }

    onSubmit({
      ...data,
      params,
      targetSelectionMode,
      selectedTags: targetSelectionMode === 'by_tag' ? selectedTags : [],
      enableCveDetection: data.enableCveDetection !== false,
    });
  };

  const renderTypeSpecificFields = () => {
    switch (watchedType) {
      case 'attack_surface':
        return (
          <div className="space-y-4">
            <div className="space-y-3">
              <FormLabel>Modo de Seleção de Alvos</FormLabel>
              <RadioGroup
                value={targetSelectionMode}
                onValueChange={(value) => setTargetSelectionMode(value as 'individual' | 'by_tag')}
                className="flex flex-col space-y-2"
              >
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="individual" id="mode-individual" data-testid="radio-mode-individual" />
                  <label htmlFor="mode-individual" className="text-sm cursor-pointer">
                    Seleção Individual - Escolher alvos específicos
                  </label>
                </div>
                <div className="flex items-center space-x-2">
                  <RadioGroupItem value="by_tag" id="mode-by-tag" data-testid="radio-mode-by-tag" />
                  <label htmlFor="mode-by-tag" className="text-sm cursor-pointer">
                    Seleção por TAG - Escolher grupos de alvos com TAGs
                  </label>
                </div>
              </RadioGroup>
              <FormDescription>
                Escolha como selecionar os alvos para a varredura
              </FormDescription>
            </div>

            {targetSelectionMode === 'individual' ? (
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
                        <label htmlFor={asset.id} className="text-sm cursor-pointer">
                          {asset.value} ({asset.type})
                        </label>
                      </div>
                    ))
                  )}
                </div>
                <FormDescription>
                  Selecione os alvos individualmente
                </FormDescription>
              </div>
            ) : (
              <TagSelector
                selectedTags={selectedTags}
                onTagsChange={setSelectedTags}
              />
            )}

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
              name="params.vulnScriptTimeout"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Timeout de Validação de CVEs (minutos)</FormLabel>
                  <FormControl>
                    <Input
                      type="number"
                      min="5"
                      max="180"
                      placeholder="60"
                      {...field}
                      onChange={(e) => field.onChange(parseInt(e.target.value) || 60)}
                      data-testid="input-vuln-timeout"
                    />
                  </FormControl>
                  <FormDescription>
                    Tempo máximo para Fase 2 (nmap vuln scripts) por host. Padrão: 60 minutos
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="enableCveDetection"
              render={({ field }) => (
                <FormItem className="flex flex-row items-start space-x-3 space-y-0 rounded-md border p-4">
                  <FormControl>
                    <Checkbox
                      checked={field.value !== false}
                      onCheckedChange={field.onChange}
                      data-testid="checkbox-enable-cve-detection"
                    />
                  </FormControl>
                  <div className="space-y-1 leading-none">
                    <FormLabel>
                      Buscar CVEs Associados (Fase 2)
                    </FormLabel>
                    <FormDescription>
                      Quando marcado, após a descoberta de hosts (Fase 1), o sistema buscará CVEs associados às versões detectadas usando a base NIST NVD. Desmarcando, apenas a Fase 1 será executada.
                    </FormDescription>
                  </div>
                </FormItem>
              )}
            />

            <div className="rounded-md border p-4 space-y-4">
              <div className="flex flex-row items-start space-x-3 space-y-0">
                <Checkbox
                  checked={enableAuthentication}
                  onCheckedChange={(checked) => setEnableAuthentication(checked === true)}
                  data-testid="checkbox-enable-authentication"
                />
                <div className="space-y-1 leading-none">
                  <FormLabel>
                    Varredura Autenticada (Fase 1.5 - Opcional)
                  </FormLabel>
                  <FormDescription>
                    Habilita coleta de dados detalhados usando credenciais (WMI/SSH). Melhora precisão na detecção de CVEs em até 74%, eliminando falsos positivos através de matching exato de versões de OS e patches instalados.
                  </FormDescription>
                </div>
              </div>

              {enableAuthentication && (
                <div className="space-y-4 pl-7 pt-2">
                  <div className="text-sm text-muted-foreground bg-muted/30 rounded-md p-3 border">
                    <strong>Como funciona:</strong>
                    <ul className="list-disc list-inside mt-1 space-y-1">
                      <li>WMI (Windows): Coleta versão exata do OS, patches KB instalados, aplicações</li>
                      <li>SSH (Linux): Coleta kernel, versão do OS, pacotes instalados</li>
                      <li>Múltiplas credenciais por protocolo com prioridade (0 = maior prioridade)</li>
                      <li>Falha silenciosa: se credencial não funcionar, continua sem autenticação</li>
                    </ul>
                  </div>

                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <FormLabel>Credenciais Configuradas ({selectedCredentials.length})</FormLabel>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          setSelectedCredentials(prev => [...prev, {
                            credentialId: '',
                            protocol: 'wmi',
                            priority: prev.length
                          }]);
                        }}
                        data-testid="button-add-credential"
                      >
                        + Adicionar Credencial
                      </Button>
                    </div>

                    {selectedCredentials.length === 0 && (
                      <div className="text-sm text-muted-foreground text-center py-4 border-2 border-dashed rounded-md">
                        Nenhuma credencial configurada. Clique em "Adicionar Credencial" para começar.
                      </div>
                    )}

                    {selectedCredentials.map((cred, index) => (
                      <div key={index} className="flex gap-3 items-start border rounded-md p-3 bg-muted/10">
                        <div className="flex-1 grid grid-cols-1 md:grid-cols-3 gap-3">
                          <div className="space-y-2">
                            <label className="text-sm font-medium">Protocolo</label>
                            <Select
                              value={cred.protocol}
                              onValueChange={(value: 'wmi' | 'ssh' | 'snmp') => {
                                setSelectedCredentials(prev => {
                                  const updated = [...prev];
                                  updated[index].protocol = value;
                                  return updated;
                                });
                              }}
                            >
                              <SelectTrigger data-testid={`select-protocol-${index}`}>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="wmi">WMI (Windows)</SelectItem>
                                <SelectItem value="ssh">SSH (Linux/Unix)</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>

                          <div className="space-y-2">
                            <label className="text-sm font-medium">Credencial</label>
                            <Select
                              value={cred.credentialId}
                              onValueChange={(value) => {
                                setSelectedCredentials(prev => {
                                  const updated = [...prev];
                                  updated[index].credentialId = value;
                                  return updated;
                                });
                              }}
                            >
                              <SelectTrigger data-testid={`select-credential-${index}`}>
                                <SelectValue placeholder="Selecione..." />
                              </SelectTrigger>
                              <SelectContent>
                                {credentials
                                  .filter(c => 
                                    (cred.protocol === 'wmi' && c.type === 'wmi') ||
                                    (cred.protocol === 'ssh' && c.type === 'ssh')
                                  )
                                  .map((credential) => (
                                    <SelectItem key={credential.id} value={credential.id}>
                                      {credential.name}
                                    </SelectItem>
                                  ))}
                              </SelectContent>
                            </Select>
                          </div>

                          <div className="space-y-2">
                            <label className="text-sm font-medium">Prioridade</label>
                            <Input
                              type="number"
                              min="0"
                              max="99"
                              value={cred.priority}
                              onChange={(e) => {
                                setSelectedCredentials(prev => {
                                  const updated = [...prev];
                                  updated[index].priority = parseInt(e.target.value) || 0;
                                  return updated;
                                });
                              }}
                              data-testid={`input-priority-${index}`}
                              placeholder="0"
                            />
                          </div>
                        </div>

                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setSelectedCredentials(prev => prev.filter((_, i) => i !== index));
                          }}
                          data-testid={`button-remove-credential-${index}`}
                          className="mt-6"
                        >
                          ✕
                        </Button>
                      </div>
                    ))}

                    {selectedCredentials.length > 0 && (
                      <div className="text-xs text-muted-foreground bg-blue-50 dark:bg-blue-950/20 rounded-md p-2 border border-blue-200 dark:border-blue-900">
                        💡 <strong>Dica:</strong> Prioridade 0 = mais alta. O sistema tenta credenciais em ordem crescente de prioridade. Ao suceder, para de tentar outras credenciais daquele protocolo.
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        );

      case 'ad_security':
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

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="params.primaryDC"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>DC Primário (Opcional)</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Ex: 192.168.1.10"
                        {...field}
                        data-testid="input-primary-dc"
                      />
                    </FormControl>
                    <FormDescription>
                      IP do DC primário (autodescoberta se vazio)
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="params.secondaryDC"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>DC Secundário (Opcional)</FormLabel>
                    <FormControl>
                      <Input
                        placeholder="Ex: 192.168.1.11"
                        {...field}
                        data-testid="input-secondary-dc"
                      />
                    </FormControl>
                    <FormDescription>
                      IP do DC secundário (fallback)
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div>
              <FormLabel>Categorias de Testes de Segurança AD</FormLabel>
              <div className="mt-3 space-y-3 border rounded-md p-4 bg-muted/10">
                <div className="text-sm font-medium text-foreground mb-2">
                  Selecione as categorias para executar (28 testes organizados):
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                  <FormField
                    control={form.control}
                    name="params.enabledCategories.configuracoes_criticas"
                    render={({ field }) => (
                      <div className="flex items-start space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-cat-critical"
                        />
                        <div>
                          <label className="text-sm font-medium text-red-600 dark:text-red-400">
                            🔴 Configurações Críticas
                          </label>
                          <p className="text-xs text-muted-foreground mt-1">
                            PrintNightmare, LDAP anônimo, SMBv1, KRBTGT fraca, Schema
                          </p>
                        </div>
                      </div>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="params.enabledCategories.gerenciamento_contas"
                    render={({ field }) => (
                      <div className="flex items-start space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-cat-accounts"
                        />
                        <div>
                          <label className="text-sm font-medium text-orange-600 dark:text-orange-400">
                            👥 Gerenciamento de Contas
                          </label>
                          <p className="text-xs text-muted-foreground mt-1">
                            SPNs privilegiados, pré-auth, senhas, AdminCount, Trusts
                          </p>
                        </div>
                      </div>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="params.enabledCategories.kerberos_delegacao"
                    render={({ field }) => (
                      <div className="flex items-start space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-cat-kerberos"
                        />
                        <div>
                          <label className="text-sm font-medium text-purple-600 dark:text-purple-400">
                            🎫 Kerberos e Delegação
                          </label>
                          <p className="text-xs text-muted-foreground mt-1">
                            RBCD, gMSA, criptografia, RODC
                          </p>
                        </div>
                      </div>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="params.enabledCategories.compartilhamentos_gpos"
                    render={({ field }) => (
                      <div className="flex items-start space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-cat-shares"
                        />
                        <div>
                          <label className="text-sm font-medium text-yellow-600 dark:text-yellow-400">
                            📂 Compartilhamentos e GPOs
                          </label>
                          <p className="text-xs text-muted-foreground mt-1">
                            Credenciais em SYSVOL/NETLOGON, permissões, SMB signing
                          </p>
                        </div>
                      </div>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="params.enabledCategories.politicas_configuracao"
                    render={({ field }) => (
                      <div className="flex items-start space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-cat-policies"
                        />
                        <div>
                          <label className="text-sm font-medium text-blue-600 dark:text-blue-400">
                            ⚙️ Políticas e Configuração
                          </label>
                          <p className="text-xs text-muted-foreground mt-1">
                            UAC, ACEs, nível funcional, LAPS, DNS Admins
                          </p>
                        </div>
                      </div>
                    )}
                  />
                  
                  <FormField
                    control={form.control}
                    name="params.enabledCategories.contas_inativas"
                    render={({ field }) => (
                      <div className="flex items-start space-x-2">
                        <Checkbox
                          checked={field.value}
                          onCheckedChange={field.onChange}
                          data-testid="checkbox-cat-inactive"
                        />
                        <div>
                          <label className="text-sm font-medium text-gray-600 dark:text-gray-400">
                            💤 Contas Inativas
                          </label>
                          <p className="text-xs text-muted-foreground mt-1">
                            Privilegiadas inativas, desabilitadas, serviços, dormentes
                          </p>
                        </div>
                      </div>
                    )}
                  />
                </div>

                <div className="mt-4 pt-3 border-t">
                  <div className="text-sm font-medium text-foreground mb-2">
                    Total: 28 testes de segurança AD organizados em 6 categorias
                  </div>
                  <div className="grid grid-cols-1 gap-1 text-xs">
                    <div className="text-red-600 dark:text-red-400">
                      🔴 5 testes críticos: PrintNightmare, KRBTGT, SMBv1, LDAP, Schema
                    </div>
                    <div className="text-orange-600 dark:text-orange-400">
                      🟠 10 testes de contas: SPNs, senhas, privilégios, trusts
                    </div>
                    <div className="text-blue-600 dark:text-blue-400">
                      🔵 13 testes de configuração, Kerberos, GPOs e contas inativas
                    </div>
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

                <div className="space-y-3">
                  <FormLabel>Modo de Seleção de Alvos</FormLabel>
                  <RadioGroup
                    value={targetSelectionMode}
                    onValueChange={(value) => setTargetSelectionMode(value as 'individual' | 'by_tag')}
                    className="flex flex-col space-y-2"
                  >
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="individual" id="edr-mode-individual" data-testid="radio-edr-mode-individual" />
                      <label htmlFor="edr-mode-individual" className="text-sm cursor-pointer">
                        Seleção Individual - Escolher alvos específicos
                      </label>
                    </div>
                    <div className="flex items-center space-x-2">
                      <RadioGroupItem value="by_tag" id="edr-mode-by-tag" data-testid="radio-edr-mode-by-tag" />
                      <label htmlFor="edr-mode-by-tag" className="text-sm cursor-pointer">
                        Seleção por TAG - Escolher grupos de alvos com TAGs
                      </label>
                    </div>
                  </RadioGroup>
                  <FormDescription>
                    Escolha como selecionar os alvos para o teste
                  </FormDescription>
                </div>

                {targetSelectionMode === 'individual' ? (
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
                              id={`edr-${asset.id}`}
                              checked={selectedAssets.includes(asset.id)}
                              onCheckedChange={(checked) => 
                                handleAssetSelection(asset.id, checked as boolean)
                              }
                              data-testid={`checkbox-edr-asset-${asset.id}`}
                            />
                            <label htmlFor={`edr-${asset.id}`} className="text-sm cursor-pointer">
                              {asset.value} ({asset.type})
                            </label>
                          </div>
                        ))
                      )}
                    </div>
                    <FormDescription>
                      Selecione os alvos individualmente
                    </FormDescription>
                  </div>
                ) : (
                  <TagSelector
                    selectedTags={selectedTags}
                    onTagsChange={setSelectedTags}
                  />
                )}
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

      case 'web_application':
        return (
          <div className="space-y-4">
            <div>
              <FormLabel>Aplicações Web Selecionadas</FormLabel>
              <div className="mt-2 space-y-2 max-h-40 overflow-y-auto border rounded-md p-3">
                {webApplicationAssets.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Nenhuma aplicação web disponível. Crie ativos do tipo web_application primeiro.
                  </p>
                ) : (
                  webApplicationAssets.map((asset) => (
                    <div key={asset.id} className="flex items-center space-x-2">
                      <Checkbox
                        id={asset.id}
                        checked={selectedAssets.includes(asset.id)}
                        onCheckedChange={(checked) => 
                          handleAssetSelection(asset.id, checked as boolean)
                        }
                        data-testid={`checkbox-webapp-${asset.id}`}
                      />
                      <label htmlFor={asset.id} className="text-sm cursor-pointer">
                        {asset.value}
                      </label>
                    </div>
                  ))
                )}
              </div>
              <FormDescription>
                Selecione as aplicações web para testar vulnerabilidades
              </FormDescription>
            </div>

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
                      data-testid="input-webapp-process-timeout"
                    />
                  </FormControl>
                  <FormDescription>
                    Tempo máximo de execução por aplicação web. Mínimo: 5min, Máximo: 180min, Padrão: 60min
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
                  <SelectItem value="ad_security">AD Security</SelectItem>
                  <SelectItem value="edr_av">Teste EDR/AV</SelectItem>
                  <SelectItem value="web_application">Web Application</SelectItem>
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
