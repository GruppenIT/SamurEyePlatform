import { Link } from "wouter";
import { ChevronRight } from "lucide-react";

interface AdminBreadcrumbProps {
  page: string;
}

export function AdminBreadcrumb({ page }: AdminBreadcrumbProps) {
  return (
    <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
      <Link href="/admin">
        <span className="hover:text-foreground cursor-pointer transition-colors">Administração</span>
      </Link>
      <ChevronRight className="h-3.5 w-3.5" />
      <span className="text-foreground font-medium">{page}</span>
    </div>
  );
}
