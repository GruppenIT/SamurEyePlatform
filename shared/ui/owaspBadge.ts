import { OWASP_API_CATEGORY_LABELS, type OwaspApiCategory } from '../owaspApiCategories';

export interface OwaspBadgeInfo {
  codigo: string;
  titulo: string;
}

export function getOwaspBadgeInfo(category: string | null | undefined): OwaspBadgeInfo | null {
  if (!category) return null;
  if (!(category in OWASP_API_CATEGORY_LABELS)) return null;
  const info = OWASP_API_CATEGORY_LABELS[category as OwaspApiCategory];
  return { codigo: info.codigo, titulo: info.titulo };
}
