import React, { useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { format } from "date-fns";
import Sidebar from "@/components/layout/sidebar";
import TopBar from "@/components/layout/topbar";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Skeleton } from "@/components/ui/skeleton";
import { Globe, Lock, ChevronDown, ChevronRight } from "lucide-react";
import { METHOD_COLORS, PARAM_COLORS } from "@shared/ui/methodColors";
import type { Api, ApiEndpoint } from "@shared/schema";

type ApiWithCount = Api & {
  endpointCount: number;
  lastExecutionAt?: string | Date | null;
  discoveryMethod?: string | null;
};

function MethodBadge({ method }: { method: string }) {
  const color = METHOD_COLORS[method.toUpperCase()] ?? "bg-muted text-muted-foreground";
  return (
    <Badge className={`${color} font-mono text-xs`} data-testid={`method-badge-${method.toUpperCase()}`}>
      {method.toUpperCase()}
    </Badge>
  );
}

function ParamChip({
  name,
  location,
}: {
  name: string;
  location: "path" | "query" | "header";
}) {
  const color = PARAM_COLORS[location] ?? "bg-muted text-muted-foreground";
  return (
    <Badge
      className={`text-xs ${color}`}
      data-testid={`chip-${location}-${name}`}
    >
      {name}
    </Badge>
  );
}

function EndpointRow({ endpoint }: { endpoint: ApiEndpoint }) {
  const pathParams = Array.isArray(endpoint.pathParams)
    ? (endpoint.pathParams as Array<{ name: string; type?: string; required?: boolean }>)
    : [];
  const queryParams = Array.isArray(endpoint.queryParams)
    ? (endpoint.queryParams as Array<{ name: string; type?: string; required?: boolean }>)
    : [];
  const headerParams = Array.isArray(endpoint.headerParams)
    ? (endpoint.headerParams as Array<{ name: string; type?: string; required?: boolean }>)
    : [];

  return (
    <div
      className="flex items-center flex-wrap gap-2 py-2 px-4 border-b border-border/40"
      data-testid={`endpoint-${endpoint.id}`}
    >
      <MethodBadge method={endpoint.method} />
      <code className="text-sm font-mono flex-1 truncate min-w-0">{endpoint.path}</code>
      {endpoint.requiresAuth === true && (
        <Badge variant="secondary" className="text-xs" data-testid="auth-badge">
          <Lock className="h-3 w-3 mr-1" />
          Auth
        </Badge>
      )}
      {endpoint.httpxStatus !== null && endpoint.httpxStatus !== undefined && (
        <Badge variant="outline" className="text-xs font-mono">
          {endpoint.httpxStatus}
        </Badge>
      )}
      {(pathParams.length > 0 || queryParams.length > 0 || headerParams.length > 0) && (
        <div className="flex flex-wrap gap-1 w-full mt-1">
          {pathParams.map((p) => (
            <ParamChip key={`p-${p.name}`} name={p.name} location="path" />
          ))}
          {queryParams.map((p) => (
            <ParamChip key={`q-${p.name}`} name={p.name} location="query" />
          ))}
          {headerParams.map((p) => (
            <ParamChip key={`h-${p.name}`} name={p.name} location="header" />
          ))}
        </div>
      )}
    </div>
  );
}

function EndpointGroup({
  path,
  endpoints,
}: {
  path: string;
  endpoints: ApiEndpoint[];
}) {
  const [open, setOpen] = useState(false);

  return (
    <Collapsible
      open={open}
      onOpenChange={setOpen}
      className="border rounded-md mb-2"
      data-testid={`group-${path}`}
    >
      <CollapsibleTrigger asChild>
        <button
          className="flex items-center gap-2 w-full p-3 hover:bg-muted/50 text-left"
          aria-expanded={open}
        >
          {open ? (
            <ChevronDown className="h-4 w-4 shrink-0" />
          ) : (
            <ChevronRight className="h-4 w-4 shrink-0" />
          )}
          <code className="font-mono text-sm flex-1 truncate">{path}</code>
          <Badge variant="secondary" className="text-xs shrink-0">
            {endpoints.length}
          </Badge>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>
        {endpoints.map((ep) => (
          <EndpointRow key={ep.id} endpoint={ep} />
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
}

export default function ApiDiscovery() {
  const [selectedApiId, setSelectedApiId] = useState<string | null>(null);

  const { data: apis = [], isLoading } = useQuery<ApiWithCount[]>({
    queryKey: ["/api/v1/apis"],
  });

  const { data: endpoints = [], isLoading: isLoadingEndpoints } = useQuery<
    ApiEndpoint[]
  >({
    queryKey: [`/api/v1/apis/${selectedApiId}/endpoints`],
    enabled: !!selectedApiId,
  });

  const groupedEndpoints = useMemo(() => {
    const grouped: Record<string, ApiEndpoint[]> = {};
    for (const ep of endpoints) {
      if (!grouped[ep.path]) grouped[ep.path] = [];
      grouped[ep.path].push(ep);
    }
    return Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b));
  }, [endpoints]);

  const selectedApi = apis.find((a) => a.id === selectedApiId);

  return (
    <div className="flex h-screen bg-background">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar title="API Discovery" subtitle="APIs descobertas nas jornadas api_security" />
        <main
          className="flex-1 overflow-y-auto p-6"
          data-testid="api-discovery-page"
        >
          <div className="max-w-7xl mx-auto space-y-6">
            <div>
              <h1 className="text-2xl font-bold">API Discovery</h1>
              <p className="text-muted-foreground text-sm mt-1">
                APIs descobertas nas jornadas <code>api_security</code>.
              </p>
            </div>

            <Card>
              <CardHeader>
                <CardTitle>APIs</CardTitle>
              </CardHeader>
              <CardContent>
                {isLoading ? (
                  <div className="space-y-3">
                    {[...Array(5)].map((_, i) => (
                      <div
                        key={i}
                        className="flex items-center space-x-4 p-3"
                        data-testid="skeleton-row"
                      >
                        <Skeleton className="h-4 w-1/3" />
                        <Skeleton className="h-4 w-20" />
                        <Skeleton className="h-4 w-24" />
                        <Skeleton className="h-4 w-16" />
                        <Skeleton className="h-4 w-32" />
                      </div>
                    ))}
                  </div>
                ) : apis.length === 0 ? (
                  <div
                    className="text-center py-12"
                    data-testid="empty-state"
                  >
                    <Globe className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                    <h3 className="text-lg font-semibold mb-1">
                      Nenhuma API descoberta ainda
                    </h3>
                    <p className="text-muted-foreground text-sm">
                      Execute uma jornada{" "}
                      <code>api_security</code> para descobrir APIs.
                    </p>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Base URL</TableHead>
                        <TableHead>Tipo</TableHead>
                        <TableHead>Descoberto por</TableHead>
                        <TableHead className="text-right">Endpoints</TableHead>
                        <TableHead>Última execução</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {apis.map((api) => (
                        <TableRow
                          key={api.id}
                          className="cursor-pointer hover:bg-muted/50"
                          onClick={() => setSelectedApiId(api.id)}
                          data-testid={`api-row-${api.id}`}
                        >
                          <TableCell className="font-mono text-sm">
                            {api.baseUrl}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="uppercase">
                              {api.apiType}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs">
                            {api.discoveryMethod ?? "—"}
                          </TableCell>
                          <TableCell className="text-right font-mono">
                            {api.endpointCount}
                          </TableCell>
                          <TableCell className="text-muted-foreground text-xs">
                            {api.lastExecutionAt
                              ? format(
                                  new Date(api.lastExecutionAt),
                                  "dd/MM/yyyy HH:mm"
                                )
                              : "—"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </CardContent>
            </Card>
          </div>
        </main>
      </div>

      <Sheet
        open={!!selectedApiId}
        onOpenChange={(open) => !open && setSelectedApiId(null)}
      >
        <SheetContent
          side="right"
          className="w-[700px] sm:max-w-[700px] overflow-y-auto"
        >
          <SheetHeader>
            <SheetTitle>{selectedApi?.baseUrl ?? "API"}</SheetTitle>
            <SheetDescription>
              {selectedApi?.apiType?.toUpperCase()} &middot;{" "}
              {selectedApi?.endpointCount ?? 0} endpoints
            </SheetDescription>
          </SheetHeader>
          <div
            className="mt-6 space-y-2"
            data-testid="endpoints-list"
          >
            {isLoadingEndpoints ? (
              <Skeleton className="h-20 w-full" />
            ) : endpoints.length === 0 ? (
              <p
                className="text-muted-foreground text-sm text-center py-8"
                data-testid="endpoints-empty"
              >
                Nenhum endpoint descoberto nesta API.
              </p>
            ) : (
              groupedEndpoints.map(([path, eps]) => (
                <EndpointGroup key={path} path={path} endpoints={eps} />
              ))
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
