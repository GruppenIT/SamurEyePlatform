// HTTP method → Tailwind badge classes (CONTEXT.md §Specific Ideas)
export const METHOD_COLORS: Record<string, string> = {
  GET: 'bg-green-600/20 text-green-500',
  POST: 'bg-blue-600/20 text-blue-500',
  PUT: 'bg-yellow-500/20 text-yellow-600',
  DELETE: 'bg-destructive/20 text-destructive',
  PATCH: 'bg-orange-500/20 text-orange-600',
};

// Param location → Tailwind chip classes
export const PARAM_COLORS: Record<string, string> = {
  path: 'bg-orange-500/20 text-orange-600',
  query: 'bg-blue-500/20 text-blue-500',
  header: 'bg-purple-500/20 text-purple-500',
};
