import { Check, X } from "lucide-react";

interface PasswordChecklistProps {
  password: string;
}

const RULES = [
  { label: "Pelo menos 12 caracteres", test: (p: string) => p.length >= 12 },
  { label: "1 letra maiúscula (A-Z)", test: (p: string) => /[A-Z]/.test(p) },
  { label: "1 letra minúscula (a-z)", test: (p: string) => /[a-z]/.test(p) },
  { label: "1 dígito (0-9)", test: (p: string) => /\d/.test(p) },
  { label: "1 caractere especial (!@#... etc.)", test: (p: string) => /[^A-Za-z0-9]/.test(p) },
];

export function PasswordChecklist({ password }: PasswordChecklistProps) {
  return (
    <ul className="mt-2 space-y-1 text-xs" data-testid="password-checklist">
      {RULES.map((rule) => {
        const ok = rule.test(password);
        const Icon = ok ? Check : X;
        return (
          <li
            key={rule.label}
            className={ok
              ? "flex items-center gap-1.5 text-green-600 dark:text-green-400"
              : "flex items-center gap-1.5 text-muted-foreground"}
          >
            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{rule.label}</span>
          </li>
        );
      })}
    </ul>
  );
}

export function isPasswordStrong(password: string): boolean {
  return RULES.every((r) => r.test(password));
}
