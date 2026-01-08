import { Shield, Network, Activity, HardDrive, Cpu, Lock, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import { serviceCategories } from '@/data/auditContent';

interface CategorySelectorProps {
  selected: string[];
  onSelect: (categories: string[]) => void;
}

const iconMap = {
  Shield: Shield,
  Network: Network,
  Activity: Activity,
  HardDrive: HardDrive,
  Cpu: Cpu,
  Lock: Lock,
};

export function CategorySelector({ selected, onSelect }: CategorySelectorProps) {
  const toggleCategory = (id: string) => {
    if (selected.includes(id)) {
      onSelect(selected.filter(c => c !== id));
    } else {
      onSelect([...selected, id]);
    }
  };

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
        Service Categories
      </h3>
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
        {serviceCategories.map((category) => {
          const isSelected = selected.includes(category.id);
          const Icon = iconMap[category.icon as keyof typeof iconMap];
          
          return (
            <button
              key={category.id}
              onClick={() => toggleCategory(category.id)}
              className={cn(
                "relative group flex items-center gap-2 px-3 py-2.5 rounded-lg border transition-all duration-200",
                isSelected
                  ? "bg-primary/10 border-primary/50"
                  : "bg-card/30 border-border/30 hover:border-primary/30 hover:bg-card/60"
              )}
            >
              {isSelected && (
                <Check className="absolute -top-1 -right-1 h-3.5 w-3.5 text-primary bg-background rounded-full" />
              )}
              <Icon className={cn(
                "h-4 w-4 flex-shrink-0 transition-colors",
                isSelected ? "text-primary" : "text-muted-foreground"
              )} />
              <span className={cn(
                "text-xs font-medium truncate transition-colors",
                isSelected ? "text-primary" : "text-foreground"
              )}>
                {category.name.split(' ')[0]}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
