import { useActionPlanAssignees } from "@/hooks/useActionPlans";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

interface AssigneeSelectorProps {
  value: string | null; // user id or null
  onChange: (assigneeId: string | null) => void;
  disabled?: boolean;
  allowUnassigned?: boolean; // default true
}

export function AssigneeSelector({
  value,
  onChange,
  disabled,
  allowUnassigned = true,
}: AssigneeSelectorProps) {
  const { data: users, isLoading } = useActionPlanAssignees();

  return (
    <Select
      value={value ?? "__none__"}
      onValueChange={(v) => onChange(v === "__none__" ? null : v)}
      disabled={disabled || isLoading}
    >
      <SelectTrigger>
        <SelectValue
          placeholder={isLoading ? "Carregando..." : "Selecione um responsável"}
        />
      </SelectTrigger>
      <SelectContent>
        {allowUnassigned && (
          <SelectItem value="__none__">Sem responsável</SelectItem>
        )}
        {users?.map((u) => (
          <SelectItem key={u.id} value={u.id}>
            {u.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
