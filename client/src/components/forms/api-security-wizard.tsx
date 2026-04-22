import React, { useState, useMemo } from "react";
import { useForm, Controller } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { cn } from "@/lib/utils";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { AlertTriangle, Plus } from "lucide-react";
import { estimateRequests, type StageConfig } from "@shared/ui/estimateRequests";
import type { Asset } from "@shared/schema";
import { isUnauthorizedError } from "@/lib/authUtils";

// Zod schema — mirrors backend payload shape per Phase 15
const wizardSchema = z.object({
  name: z.string().min(1, "Nome é obrigatório"),
  description: z.string().optional(),
  assetIds: z.array(z.string()).min(1, "Selecione ao menos um alvo"),
  targetBaseUrl: z.string().optional(),
  credentialId: z.string().optional(),
  authorizationAck: z.boolean().refine((v) => v === true, {
    message: "Você deve confirmar que tem autorização para testar os alvos",
  }),
  specFirst: z.boolean(),
  crawler: z.boolean(),
  kiterunner: z.boolean(),
  misconfigs: z.boolean(),
  auth: z.boolean(),
  bola: z.boolean(),
  bfla: z.boolean(),
  bopla: z.boolean(),
  rateLimitTest: z.boolean(),
  ssrf: z.boolean(),
  rateLimit: z.number().int().min(1).max(50),
  destructiveEnabled: z.boolean(),
  dryRun: z.boolean(),
});

export type ApiSecurityWizardData = z.infer<typeof wizardSchema>;

interface ApiSecurityWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type NewCredState = {
  name: string;
  authType: string;
  secret: string;
  apiKeyHeaderName: string;
  apiKeyQueryParam: string;
  basicUsername: string;
  oauth2ClientId: string;
  oauth2TokenUrl: string;
  oauth2Scope: string;
  oauth2Audience: string;
  hmacKeyId: string;
  hmacAlgorithm: string;
  hmacSignatureHeader: string;
  mtlsCert: string;
  mtlsKey: string;
  mtlsCa: string;
};

const defaultNewCred: NewCredState = {
  name: "",
  authType: "api_key_header",
  secret: "",
  apiKeyHeaderName: "X-API-Key",
  apiKeyQueryParam: "api_key",
  basicUsername: "",
  oauth2ClientId: "",
  oauth2TokenUrl: "",
  oauth2Scope: "",
  oauth2Audience: "",
  hmacKeyId: "",
  hmacAlgorithm: "HMAC-SHA256",
  hmacSignatureHeader: "Authorization",
  mtlsCert: "",
  mtlsKey: "",
  mtlsCa: "",
};

export default function ApiSecurityWizard({ open, onOpenChange }: ApiSecurityWizardProps) {
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [showNewCred, setShowNewCred] = useState(false);
  const [newCred, setNewCred] = useState<NewCredState>(defaultNewCred);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<ApiSecurityWizardData>({
    resolver: zodResolver(wizardSchema),
    mode: "onChange",
    defaultValues: {
      name: "",
      description: "",
      assetIds: [],
      targetBaseUrl: "",
      credentialId: undefined,
      authorizationAck: false,
      // Step 3 locked defaults per CONTEXT.md
      specFirst: true,
      crawler: true,
      kiterunner: false,
      misconfigs: true,
      auth: true,
      bola: false,
      bfla: false,
      bopla: false,
      rateLimitTest: true,
      ssrf: false,
      rateLimit: 10,
      destructiveEnabled: false,
      dryRun: false,
    },
  });

  const watchedAll = form.watch();
  const stageConfig: StageConfig = {
    specFirst: watchedAll.specFirst,
    crawler: watchedAll.crawler,
    kiterunner: watchedAll.kiterunner,
    misconfigs: watchedAll.misconfigs,
    auth: watchedAll.auth,
    bola: watchedAll.bola,
    bfla: watchedAll.bfla,
    bopla: watchedAll.bopla,
    rateLimitTest: watchedAll.rateLimitTest,
    ssrf: watchedAll.ssrf,
  };

  const { data: assets = [] } = useQuery<Asset[]>({ queryKey: ["/api/assets"] });
  const { data: apiList = [] } = useQuery<any[]>({ queryKey: ["/api/v1/apis"] });
  const { data: credentials = [] } = useQuery<any[]>({ queryKey: ["/api/v1/api-credentials"] });

  // Best-effort endpointCount — sum from APIs linked to selected assets. Fallback 100.
  const endpointCount = useMemo(() => {
    if (!watchedAll.assetIds.length) return 100;
    let total = 0;
    for (const assetId of watchedAll.assetIds) {
      const apisForAsset = apiList.filter((a) => a.parentAssetId === assetId);
      for (const a of apisForAsset) total += a.endpointCount ?? 0;
    }
    return total || 100;
  }, [watchedAll.assetIds, apiList]);

  const estimatedRequests = useMemo(
    () => estimateRequests(endpointCount, stageConfig),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [endpointCount, JSON.stringify(stageConfig)],
  );

  const canAdvance = useMemo(() => {
    if (step === 1) return watchedAll.name.length > 0 && watchedAll.assetIds.length > 0;
    if (step === 2) return watchedAll.authorizationAck === true;
    if (step === 3) return watchedAll.rateLimit >= 1 && watchedAll.rateLimit <= 50;
    return true;
  }, [step, watchedAll]);

  const createMutation = useMutation({
    mutationFn: async (data: ApiSecurityWizardData) =>
      await apiRequest("POST", "/api/v1/jobs", {
        type: "api_security",
        name: data.name,
        description: data.description,
        params: {
          assetIds: data.assetIds,
          targetBaseUrl: data.targetBaseUrl || undefined,
          credentialId: data.credentialId || undefined,
          authorizationAck: data.authorizationAck,
          apiSecurityConfig: {
            discovery: {
              specFirst: data.specFirst,
              crawler: data.crawler,
              kiterunner: data.kiterunner,
            },
            testing: {
              misconfigs: data.misconfigs,
              auth: data.auth,
              bola: data.bola,
              bfla: data.bfla,
              bopla: data.bopla,
              rateLimit: data.rateLimitTest,
              ssrf: data.ssrf,
            },
            rateLimit: data.rateLimit,
            destructiveEnabled: data.destructiveEnabled,
            dryRun: data.dryRun,
          },
        },
      }),
    onSuccess: () => {
      toast({ title: "Sucesso", description: "Jornada criada com sucesso" });
      form.reset();
      setStep(1);
      onOpenChange(false);
      queryClient.invalidateQueries({ queryKey: ["/api/jobs"] });
      queryClient.invalidateQueries({ queryKey: ["/api/v1/apis"] });
    },
    onError: (err: any) => {
      if (isUnauthorizedError(err)) {
        toast({ title: "Não autorizado", description: "Faça login novamente.", variant: "destructive" });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Erro",
        description: err?.message ?? "Falha ao criar jornada",
        variant: "destructive",
      });
    },
  });

  const createCredMutation = useMutation({
    mutationFn: async (payload: Record<string, unknown>) => {
      const res = await apiRequest("POST", "/api/v1/api-credentials", payload);
      return await res.json();
    },
    onSuccess: (cred: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/v1/api-credentials"] });
      form.setValue("credentialId", cred.id);
      setShowNewCred(false);
      setNewCred(defaultNewCred);
      toast({ title: "Credencial criada", description: `"${cred.name}" adicionada e selecionada.` });
    },
    onError: (err: any) => {
      toast({ title: "Erro ao criar credencial", description: err?.message ?? "Falha ao salvar", variant: "destructive" });
    },
  });

  const handleCreateCred = () => {
    const { name, authType, secret, apiKeyHeaderName, apiKeyQueryParam, basicUsername,
      oauth2ClientId, oauth2TokenUrl, oauth2Scope, oauth2Audience,
      hmacKeyId, hmacAlgorithm, hmacSignatureHeader, mtlsCert, mtlsKey, mtlsCa } = newCred;

    if (!name.trim()) {
      toast({ title: "Campo obrigatório", description: "Informe um nome para a credencial.", variant: "destructive" });
      return;
    }

    const base: Record<string, unknown> = { name, authType };

    if (authType === "api_key_header") {
      base.apiKeyHeaderName = apiKeyHeaderName;
      base.secret = secret;
    } else if (authType === "api_key_query") {
      base.apiKeyQueryParam = apiKeyQueryParam;
      base.secret = secret;
    } else if (authType === "bearer_jwt") {
      base.secret = secret;
    } else if (authType === "basic") {
      base.basicUsername = basicUsername;
      base.secret = secret;
    } else if (authType === "oauth2_client_credentials") {
      base.oauth2ClientId = oauth2ClientId;
      base.oauth2TokenUrl = oauth2TokenUrl;
      if (oauth2Scope) base.oauth2Scope = oauth2Scope;
      if (oauth2Audience) base.oauth2Audience = oauth2Audience;
      base.secret = secret;
    } else if (authType === "hmac") {
      base.hmacKeyId = hmacKeyId;
      base.hmacAlgorithm = hmacAlgorithm;
      base.hmacSignatureHeader = hmacSignatureHeader || "Authorization";
      base.secret = secret;
    } else if (authType === "mtls") {
      base.mtlsCert = mtlsCert;
      base.mtlsKey = mtlsKey;
      if (mtlsCa) base.mtlsCa = mtlsCa;
    }

    createCredMutation.mutate(base);
  };

  const handleNext = async () => {
    if (step === 2) {
      const ok = await form.trigger("authorizationAck");
      if (!ok) return;
    }
    if (step < 4) setStep((s) => ((s + 1) as 1 | 2 | 3 | 4));
  };

  const handleSubmit = () => {
    form.handleSubmit((data) => createMutation.mutate(data))();
  };

  return (
    <>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto" data-testid="wizard-dialog">
        <DialogHeader>
          <DialogTitle>Nova Jornada API Security</DialogTitle>
          <div className="flex items-center gap-3 mt-2" data-testid="wizard-stepper">
            {[1, 2, 3, 4].map((n) => (
              <div key={n} className="flex items-center gap-2">
                <div
                  className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center text-sm font-semibold",
                    step >= (n as 1 | 2 | 3 | 4)
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground",
                  )}
                  data-testid={`step-indicator-${n}`}
                >
                  {n}
                </div>
                {n < 4 && <div className="w-6 h-0.5 bg-border" />}
              </div>
            ))}
          </div>
        </DialogHeader>

        <div className="py-4">
          {step === 1 && (
            <div className="space-y-4" data-testid="wizard-step-1">
              <div>
                <Label>Nome da Jornada *</Label>
                <Input
                  {...form.register("name")}
                  placeholder="Ex: Jornada API de produção"
                  data-testid="input-name"
                />
                {form.formState.errors.name && (
                  <p className="text-xs text-destructive mt-1">
                    {form.formState.errors.name.message}
                  </p>
                )}
              </div>
              <div>
                <Label>Descrição</Label>
                <Textarea
                  {...form.register("description")}
                  placeholder="Descrição opcional"
                  data-testid="input-description"
                />
              </div>
              <div>
                <Label>Alvos (assets) *</Label>
                <div
                  className="border rounded-md p-3 max-h-48 overflow-y-auto space-y-1"
                  data-testid="asset-list"
                >
                  {assets.length === 0 ? (
                    <p className="text-sm text-muted-foreground">Nenhum asset disponível.</p>
                  ) : (
                    assets.map((asset) => (
                      <div key={asset.id} className="flex items-center gap-2">
                        <Controller
                          control={form.control}
                          name="assetIds"
                          render={({ field }) => (
                            <Checkbox
                              checked={field.value.includes(asset.id)}
                              onCheckedChange={(checked) => {
                                if (checked) field.onChange([...field.value, asset.id]);
                                else field.onChange(field.value.filter((id: string) => id !== asset.id));
                              }}
                              data-testid={`asset-checkbox-${asset.id}`}
                            />
                          )}
                        />
                        <span className="text-sm">
                          {asset.value}{" "}
                          <Badge variant="outline" className="text-xs ml-1">
                            {asset.type}
                          </Badge>
                        </span>
                      </div>
                    ))
                  )}
                </div>
                {form.formState.errors.assetIds && (
                  <p className="text-xs text-destructive mt-1">
                    {form.formState.errors.assetIds.message}
                  </p>
                )}
              </div>
              <div>
                <Label>URL Base Alvo (opcional)</Label>
                <Input
                  {...form.register("targetBaseUrl")}
                  placeholder="https://api.example.com"
                  data-testid="input-target-url"
                />
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-4" data-testid="wizard-step-2">
              <div>
                <Label>Credencial API (opcional)</Label>
                <Controller
                  control={form.control}
                  name="credentialId"
                  render={({ field }) => (
                    <Select
                      value={field.value ?? "__none__"}
                      onValueChange={(v) => field.onChange(v === "__none__" ? undefined : v)}
                    >
                      <SelectTrigger data-testid="select-credential">
                        <SelectValue placeholder="Selecione uma credencial" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__none__">Sem credencial (testes não autenticados)</SelectItem>
                        {credentials.map((c: any) => (
                          <SelectItem key={c.id} value={c.id}>
                            {c.name} ({c.authType})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                />
              </div>
              <div>
                <Button
                  variant="outline"
                  type="button"
                  onClick={() => setShowNewCred(true)}
                  data-testid="button-new-credential"
                >
                  <Plus className="mr-2 h-4 w-4" />
                  Nova credencial API
                </Button>
              </div>
              <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-md">
                <div className="flex items-start gap-2">
                  <Controller
                    control={form.control}
                    name="authorizationAck"
                    render={({ field }) => (
                      <Checkbox
                        checked={field.value}
                        onCheckedChange={field.onChange}
                        data-testid="checkbox-authorization-ack"
                      />
                    )}
                  />
                  <Label className="text-destructive font-medium leading-tight">
                    Confirmo que tenho autorização explícita para testar os alvos selecionados *
                  </Label>
                </div>
                {form.formState.errors.authorizationAck && (
                  <p className="text-xs text-destructive mt-2">
                    {form.formState.errors.authorizationAck.message}
                  </p>
                )}
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-5" data-testid="wizard-step-3">
              <div>
                <Label className="text-base font-semibold">Discovery</Label>
                <div className="space-y-2 mt-2">
                  {[
                    { key: "specFirst", label: "Spec-first (OpenAPI/Swagger)" },
                    { key: "crawler", label: "Crawler (Katana)" },
                    { key: "kiterunner", label: "Kiterunner (brute-force)" },
                  ].map(({ key, label }) => (
                    <div key={key} className="flex items-center gap-2">
                      <Controller
                        control={form.control}
                        name={key as any}
                        render={({ field }) => (
                          <Checkbox
                            checked={field.value as boolean}
                            onCheckedChange={field.onChange}
                            data-testid={`toggle-${key}`}
                          />
                        )}
                      />
                      <Label>{label}</Label>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <Label className="text-base font-semibold">Testing</Label>
                <div className="grid grid-cols-2 gap-2 mt-2">
                  {[
                    { key: "misconfigs", label: "Misconfigs (Nuclei)" },
                    { key: "auth", label: "Auth failures (JWT/API key)" },
                    { key: "bola", label: "BOLA (API1)" },
                    { key: "bfla", label: "BFLA (API5)" },
                    { key: "bopla", label: "BOPLA (API3)" },
                    { key: "rateLimitTest", label: "Rate limit test (API4)" },
                    { key: "ssrf", label: "SSRF (API7)" },
                  ].map(({ key, label }) => (
                    <div key={key} className="flex items-center gap-2">
                      <Controller
                        control={form.control}
                        name={key as any}
                        render={({ field }) => (
                          <Checkbox
                            checked={field.value as boolean}
                            onCheckedChange={field.onChange}
                            data-testid={`toggle-${key}`}
                          />
                        )}
                      />
                      <Label className="text-sm">{label}</Label>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <Label>Rate Limit (req/s) — máximo 50</Label>
                <Input
                  type="number"
                  min={1}
                  max={50}
                  {...form.register("rateLimit", { valueAsNumber: true })}
                  data-testid="input-rate-limit"
                />
                {form.formState.errors.rateLimit && (
                  <p className="text-xs text-destructive mt-1">
                    {form.formState.errors.rateLimit.message}
                  </p>
                )}
              </div>
              <div className="p-4 bg-destructive/5 border border-destructive/20 rounded-md">
                <div className="flex items-start gap-2">
                  <Controller
                    control={form.control}
                    name="destructiveEnabled"
                    render={({ field }) => (
                      <Checkbox
                        checked={field.value}
                        onCheckedChange={field.onChange}
                        data-testid="checkbox-destructive"
                      />
                    )}
                  />
                  <Label className="text-destructive font-medium">
                    Habilitar métodos destrutivos (DELETE/PUT/PATCH em schemas desconhecidos)
                  </Label>
                </div>
                {watchedAll.destructiveEnabled && (
                  <div
                    className="mt-2 text-xs text-destructive flex items-start gap-1"
                    data-testid="destructive-warning"
                  >
                    <AlertTriangle className="h-3 w-3 mt-0.5 shrink-0" />
                    <span>
                      Atenção: esta opção executa métodos destrutivos contra schemas não documentados. Use com
                      autorização explícita.
                    </span>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="text-sm" data-testid="estimated-requests">
                  ~{estimatedRequests} requests estimados
                </Badge>
                <span className="text-xs text-muted-foreground">
                  ({endpointCount} endpoints × {Object.values(stageConfig).filter(Boolean).length} stages × 2)
                </span>
              </div>
            </div>
          )}

          {step === 4 && (
            <div className="space-y-4" data-testid="wizard-step-4">
              <div className="p-4 bg-muted/30 rounded-md">
                <h4 className="font-semibold mb-2">Resumo da Jornada</h4>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                  <dt className="text-muted-foreground">Nome:</dt>
                  <dd data-testid="summary-name">{watchedAll.name}</dd>
                  <dt className="text-muted-foreground">Alvos:</dt>
                  <dd data-testid="summary-assets">{watchedAll.assetIds.length} asset(s)</dd>
                  <dt className="text-muted-foreground">Credencial:</dt>
                  <dd>{watchedAll.credentialId || "—"}</dd>
                  <dt className="text-muted-foreground">Rate limit:</dt>
                  <dd>{watchedAll.rateLimit} req/s</dd>
                  <dt className="text-muted-foreground">Destrutivos:</dt>
                  <dd>{watchedAll.destructiveEnabled ? "SIM" : "Não"}</dd>
                  <dt className="text-muted-foreground">Discovery ativo:</dt>
                  <dd>
                    {[
                      watchedAll.specFirst && "spec",
                      watchedAll.crawler && "crawler",
                      watchedAll.kiterunner && "kiterunner",
                    ]
                      .filter(Boolean)
                      .join(", ") || "nenhum"}
                  </dd>
                  <dt className="text-muted-foreground">Testing ativo:</dt>
                  <dd>
                    {[
                      watchedAll.misconfigs && "misconfigs",
                      watchedAll.auth && "auth",
                      watchedAll.bola && "bola",
                      watchedAll.bfla && "bfla",
                      watchedAll.bopla && "bopla",
                      watchedAll.rateLimitTest && "rate-limit",
                      watchedAll.ssrf && "ssrf",
                    ]
                      .filter(Boolean)
                      .join(", ") || "nenhum"}
                  </dd>
                  <dt className="text-muted-foreground">Estimativa:</dt>
                  <dd data-testid="summary-estimate">~{estimatedRequests} requests</dd>
                </dl>
              </div>
              <div className="flex items-center gap-2">
                <Controller
                  control={form.control}
                  name="dryRun"
                  render={({ field }) => (
                    <Checkbox
                      checked={field.value}
                      onCheckedChange={field.onChange}
                      data-testid="checkbox-dry-run"
                    />
                  )}
                />
                <Label>Dry-run (não executa scanners — só valida a configuração)</Label>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="flex justify-between gap-2">
          <div>
            {step > 1 && (
              <Button
                variant="outline"
                onClick={() => setStep((s) => ((s - 1) as 1 | 2 | 3 | 4))}
                data-testid="button-previous"
              >
                Anterior
              </Button>
            )}
          </div>
          <div className="flex gap-2">
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            {step < 4 && (
              <Button onClick={handleNext} disabled={!canAdvance} data-testid="button-next">
                Próximo
              </Button>
            )}
            {step === 4 && (
              <Button
                onClick={handleSubmit}
                disabled={createMutation.isPending}
                data-testid="button-submit"
              >
                {createMutation.isPending ? "Criando..." : "Criar Jornada"}
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    {/* Inline dialog — create API credential */}
    <Dialog open={showNewCred} onOpenChange={(o) => { setShowNewCred(o); if (!o) setNewCred(defaultNewCred); }}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Nova Credencial API</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div>
            <Label>Nome *</Label>
            <Input
              value={newCred.name}
              onChange={(e) => setNewCred((p) => ({ ...p, name: e.target.value }))}
              placeholder="Ex: Prod API Key"
            />
          </div>

          <div>
            <Label>Tipo de autenticação *</Label>
            <Select value={newCred.authType} onValueChange={(v) => setNewCred((p) => ({ ...p, authType: v }))}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="api_key_header">API Key — Header</SelectItem>
                <SelectItem value="api_key_query">API Key — Query Param</SelectItem>
                <SelectItem value="bearer_jwt">Bearer / JWT</SelectItem>
                <SelectItem value="basic">Basic (usuário + senha)</SelectItem>
                <SelectItem value="oauth2_client_credentials">OAuth2 Client Credentials</SelectItem>
                <SelectItem value="hmac">HMAC</SelectItem>
                <SelectItem value="mtls">mTLS (certificado)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {newCred.authType === "api_key_header" && (
            <>
              <div>
                <Label>Nome do header *</Label>
                <Input
                  value={newCred.apiKeyHeaderName}
                  onChange={(e) => setNewCred((p) => ({ ...p, apiKeyHeaderName: e.target.value }))}
                  placeholder="X-API-Key"
                />
              </div>
              <div>
                <Label>Valor da API Key *</Label>
                <Input
                  type="password"
                  value={newCred.secret}
                  onChange={(e) => setNewCred((p) => ({ ...p, secret: e.target.value }))}
                  placeholder="sk-..."
                />
              </div>
            </>
          )}

          {newCred.authType === "api_key_query" && (
            <>
              <div>
                <Label>Parâmetro de query *</Label>
                <Input
                  value={newCred.apiKeyQueryParam}
                  onChange={(e) => setNewCred((p) => ({ ...p, apiKeyQueryParam: e.target.value }))}
                  placeholder="api_key"
                />
              </div>
              <div>
                <Label>Valor da API Key *</Label>
                <Input
                  type="password"
                  value={newCred.secret}
                  onChange={(e) => setNewCred((p) => ({ ...p, secret: e.target.value }))}
                  placeholder="sk-..."
                />
              </div>
            </>
          )}

          {newCred.authType === "bearer_jwt" && (
            <div>
              <Label>Token JWT *</Label>
              <Textarea
                value={newCred.secret}
                onChange={(e) => setNewCred((p) => ({ ...p, secret: e.target.value }))}
                placeholder="eyJ..."
                rows={3}
              />
            </div>
          )}

          {newCred.authType === "basic" && (
            <>
              <div>
                <Label>Usuário *</Label>
                <Input
                  value={newCred.basicUsername}
                  onChange={(e) => setNewCred((p) => ({ ...p, basicUsername: e.target.value }))}
                  placeholder="username"
                />
              </div>
              <div>
                <Label>Senha *</Label>
                <Input
                  type="password"
                  value={newCred.secret}
                  onChange={(e) => setNewCred((p) => ({ ...p, secret: e.target.value }))}
                  placeholder="••••••••"
                />
              </div>
            </>
          )}

          {newCred.authType === "oauth2_client_credentials" && (
            <>
              <div>
                <Label>Client ID *</Label>
                <Input
                  value={newCred.oauth2ClientId}
                  onChange={(e) => setNewCred((p) => ({ ...p, oauth2ClientId: e.target.value }))}
                />
              </div>
              <div>
                <Label>Token URL *</Label>
                <Input
                  value={newCred.oauth2TokenUrl}
                  onChange={(e) => setNewCred((p) => ({ ...p, oauth2TokenUrl: e.target.value }))}
                  placeholder="https://auth.example.com/token"
                />
              </div>
              <div>
                <Label>Client Secret *</Label>
                <Input
                  type="password"
                  value={newCred.secret}
                  onChange={(e) => setNewCred((p) => ({ ...p, secret: e.target.value }))}
                />
              </div>
              <div>
                <Label>Scope (opcional)</Label>
                <Input
                  value={newCred.oauth2Scope}
                  onChange={(e) => setNewCred((p) => ({ ...p, oauth2Scope: e.target.value }))}
                  placeholder="read:api write:api"
                />
              </div>
              <div>
                <Label>Audience (opcional)</Label>
                <Input
                  value={newCred.oauth2Audience}
                  onChange={(e) => setNewCred((p) => ({ ...p, oauth2Audience: e.target.value }))}
                />
              </div>
            </>
          )}

          {newCred.authType === "hmac" && (
            <>
              <div>
                <Label>Key ID *</Label>
                <Input
                  value={newCred.hmacKeyId}
                  onChange={(e) => setNewCred((p) => ({ ...p, hmacKeyId: e.target.value }))}
                />
              </div>
              <div>
                <Label>Algoritmo *</Label>
                <Select value={newCred.hmacAlgorithm} onValueChange={(v) => setNewCred((p) => ({ ...p, hmacAlgorithm: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="HMAC-SHA1">HMAC-SHA1</SelectItem>
                    <SelectItem value="HMAC-SHA256">HMAC-SHA256</SelectItem>
                    <SelectItem value="HMAC-SHA512">HMAC-SHA512</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Header de assinatura</Label>
                <Input
                  value={newCred.hmacSignatureHeader}
                  onChange={(e) => setNewCred((p) => ({ ...p, hmacSignatureHeader: e.target.value }))}
                  placeholder="Authorization"
                />
              </div>
              <div>
                <Label>Secret key *</Label>
                <Input
                  type="password"
                  value={newCred.secret}
                  onChange={(e) => setNewCred((p) => ({ ...p, secret: e.target.value }))}
                />
              </div>
            </>
          )}

          {newCred.authType === "mtls" && (
            <>
              <div>
                <Label>Certificado (PEM) *</Label>
                <Textarea
                  value={newCred.mtlsCert}
                  onChange={(e) => setNewCred((p) => ({ ...p, mtlsCert: e.target.value }))}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  rows={4}
                />
              </div>
              <div>
                <Label>Chave privada (PEM) *</Label>
                <Textarea
                  value={newCred.mtlsKey}
                  onChange={(e) => setNewCred((p) => ({ ...p, mtlsKey: e.target.value }))}
                  placeholder="-----BEGIN PRIVATE KEY-----"
                  rows={4}
                />
              </div>
              <div>
                <Label>CA (PEM, opcional)</Label>
                <Textarea
                  value={newCred.mtlsCa}
                  onChange={(e) => setNewCred((p) => ({ ...p, mtlsCa: e.target.value }))}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  rows={3}
                />
              </div>
            </>
          )}
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={() => { setShowNewCred(false); setNewCred(defaultNewCred); }}>
            Cancelar
          </Button>
          <Button onClick={handleCreateCred} disabled={createCredMutation.isPending}>
            {createCredMutation.isPending ? "Salvando..." : "Criar Credencial"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    </>
  );
}
