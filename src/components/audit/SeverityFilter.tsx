import { cn } from '@/lib/utils';

interface SeverityFilterProps {
  selected: string[];
  onSelect: (severities: string[]) => void;
}

const severities = ['Critical', 'High', 'Medium', 'Low'] as const;

const severityColors: Record<string, string> = {
  Critical: 'bg-severity-critical/20 text-severity-critical border-severity-critical/30 hover:bg-severity-critical/30',
  High: 'bg-severity-high/20 text-severity-high border-severity-high/30 hover:bg-severity-high/30',
  Medium: 'bg-severity-medium/20 text-severity-medium border-severity-medium/30 hover:bg-severity-medium/30',
  Low: 'bg-severity-low/20 text-severity-low border-severity-low/30 hover:bg-severity-low/30',
};

export function SeverityFilter({ selected, onSelect }: SeverityFilterProps) {
  const toggleSeverity = (severity: string) => {
    if (selected.includes(severity)) {
      onSelect(selected.filter(s => s !== severity));
    } else {
      onSelect([...selected, severity]);
    }
  };

  return (
    <div className="flex flex-wrap gap-2">
      {severities.map((severity) => {
        const isSelected = selected.includes(severity);
        return (
          <button
            key={severity}
            onClick={() => toggleSeverity(severity)}
            className={cn(
              "px-3 py-1.5 rounded-full text-xs font-medium border transition-all duration-200",
              isSelected
                ? severityColors[severity]
                : "bg-card/30 text-muted-foreground border-border/30 hover:border-border hover:bg-card/50"
            )}
          >
            {severity}
          </button>
        );
      })}
    </div>
  );
}
