import { useMemo } from 'react';
import { Check, X } from 'lucide-react';
import { cn } from '@/lib/utils';

interface PasswordStrengthIndicatorProps {
  password: string;
}

interface StrengthCriteria {
  label: string;
  met: boolean;
}

export function PasswordStrengthIndicator({ password }: PasswordStrengthIndicatorProps) {
  const criteria: StrengthCriteria[] = useMemo(() => [
    { label: 'At least 6 characters', met: password.length >= 6 },
    { label: 'Contains uppercase letter', met: /[A-Z]/.test(password) },
    { label: 'Contains lowercase letter', met: /[a-z]/.test(password) },
    { label: 'Contains a number', met: /[0-9]/.test(password) },
  ], [password]);

  const strength = useMemo(() => {
    const metCount = criteria.filter(c => c.met).length;
    if (metCount === 0) return { level: 0, label: '', color: '' };
    if (metCount === 1) return { level: 1, label: 'Weak', color: 'bg-destructive' };
    if (metCount === 2) return { level: 2, label: 'Fair', color: 'bg-orange-500' };
    if (metCount === 3) return { level: 3, label: 'Good', color: 'bg-yellow-500' };
    return { level: 4, label: 'Strong', color: 'bg-green-500' };
  }, [criteria]);

  if (!password) return null;

  return (
    <div className="space-y-3 mt-2">
      {/* Strength bar */}
      <div className="space-y-1">
        <div className="flex justify-between items-center">
          <span className="text-xs text-muted-foreground">Password strength</span>
          <span className={cn(
            "text-xs font-medium",
            strength.level === 1 && "text-destructive",
            strength.level === 2 && "text-orange-500",
            strength.level === 3 && "text-yellow-500",
            strength.level === 4 && "text-green-500"
          )}>
            {strength.label}
          </span>
        </div>
        <div className="flex gap-1">
          {[1, 2, 3, 4].map((level) => (
            <div
              key={level}
              className={cn(
                "h-1.5 flex-1 rounded-full transition-colors",
                level <= strength.level ? strength.color : "bg-muted"
              )}
            />
          ))}
        </div>
      </div>

      {/* Criteria checklist */}
      <ul className="space-y-1">
        {criteria.map((criterion) => (
          <li
            key={criterion.label}
            className={cn(
              "flex items-center gap-2 text-xs transition-colors",
              criterion.met ? "text-green-600 dark:text-green-400" : "text-muted-foreground"
            )}
          >
            {criterion.met ? (
              <Check className="h-3 w-3" />
            ) : (
              <X className="h-3 w-3" />
            )}
            {criterion.label}
          </li>
        ))}
      </ul>
    </div>
  );
}
