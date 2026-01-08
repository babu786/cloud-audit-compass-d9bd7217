import { Check, FileCheck, Globe, Building } from 'lucide-react';
import { cn } from '@/lib/utils';
import { frameworks } from '@/data/auditContent';

interface FrameworkSelectorProps {
  selected: string[];
  onSelect: (frameworks: string[]) => void;
}

const iconMap: Record<string, typeof FileCheck> = {
  'CIS Benchmark': FileCheck,
  'ISO 27001': Globe,
  'Internal Baseline': Building,
};

export function FrameworkSelector({ selected, onSelect }: FrameworkSelectorProps) {
  const toggleFramework = (id: string) => {
    if (selected.includes(id)) {
      onSelect(selected.filter(f => f !== id));
    } else {
      onSelect([...selected, id]);
    }
  };

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
        Audit Frameworks
      </h3>
      <div className="grid grid-cols-1 min-[400px]:grid-cols-3 gap-2 sm:gap-3">
        {frameworks.map((framework) => {
          const isSelected = selected.includes(framework.id);
          const Icon = iconMap[framework.id] || FileCheck;
          
          return (
            <button
              key={framework.id}
              onClick={() => toggleFramework(framework.id)}
              className={cn(
                "relative group flex flex-col items-center gap-2 sm:gap-3 p-3 sm:p-4 rounded-xl border transition-all duration-300",
                isSelected
                  ? "bg-primary/10 border-primary/50 glow-sm"
                  : "bg-card/50 border-border/50 hover:border-primary/30 hover:bg-card/80"
              )}
            >
              {isSelected && (
                <div className="absolute top-2 right-2">
                  <Check className="h-4 w-4 text-primary" />
                </div>
              )}
              <div className={cn(
                "p-3 rounded-lg transition-colors",
                isSelected ? "bg-primary/20" : "bg-secondary/50 group-hover:bg-secondary"
              )}>
                <Icon className={cn(
                  "h-6 w-6 transition-colors",
                  isSelected ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                )} />
              </div>
              <div className="text-center">
                <p className={cn(
                  "font-medium text-sm transition-colors",
                  isSelected ? "text-primary" : "text-foreground"
                )}>
                  {framework.name}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5 hidden sm:block">
                  {framework.description}
                </p>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
