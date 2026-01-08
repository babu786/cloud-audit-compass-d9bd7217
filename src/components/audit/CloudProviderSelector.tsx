import { Cloud, Server, Database, Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import { cloudProviders } from '@/data/auditContent';

interface CloudProviderSelectorProps {
  selected: string[];
  onSelect: (providers: string[]) => void;
}

const iconMap = {
  Cloud: Cloud,
  Server: Server,
  Database: Database,
};

export function CloudProviderSelector({ selected, onSelect }: CloudProviderSelectorProps) {
  const toggleProvider = (id: string) => {
    if (selected.includes(id)) {
      onSelect(selected.filter(p => p !== id));
    } else {
      onSelect([...selected, id]);
    }
  };

  return (
    <div className="space-y-3">
      <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">
        Cloud Providers
      </h3>
      <div className="grid grid-cols-3 gap-3">
        {cloudProviders.map((provider) => {
          const isSelected = selected.includes(provider.id);
          const Icon = iconMap[provider.icon as keyof typeof iconMap];
          
          return (
            <button
              key={provider.id}
              onClick={() => toggleProvider(provider.id)}
              className={cn(
                "relative group flex flex-col items-center gap-3 p-4 rounded-xl border transition-all duration-300",
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
                  {provider.id}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5 hidden sm:block">
                  {provider.name}
                </p>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
