export interface StageConfig {
  specFirst: boolean;
  crawler: boolean;
  kiterunner: boolean;
  misconfigs: boolean;
  auth: boolean;
  bola: boolean;
  bfla: boolean;
  bopla: boolean;
  rateLimitTest: boolean;
  ssrf: boolean;
}

export function estimateRequests(endpointCount: number, config: StageConfig): number {
  const stages = [
    config.specFirst, config.crawler, config.kiterunner,
    config.misconfigs, config.auth, config.bola, config.bfla,
    config.bopla, config.rateLimitTest, config.ssrf,
  ].filter(Boolean).length;
  return endpointCount * stages * 2;
}
