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

const providerStyles = {
  AWS: {
    gradient: 'from-[#FF9900] to-[#FF6600]',
    glow: 'shadow-[0_0_20px_rgba(255,153,0,0.4)]',
    text: 'text-[#FF9900]',
    bg: 'bg-[#FF9900]/10',
    border: 'border-[#FF9900]/50',
  },
  Azure: {
    gradient: 'from-[#0078D4] to-[#00BCF2]',
    glow: 'shadow-[0_0_20px_rgba(0,120,212,0.4)]',
    text: 'text-[#0078D4]',
    bg: 'bg-[#0078D4]/10',
    border: 'border-[#0078D4]/50',
  },
  GCP: {
    gradient: 'from-[#EA4335] via-[#FBBC04] to-[#34A853]',
    glow: 'shadow-[0_0_20px_rgba(66,133,244,0.4)]',
    text: 'text-[#4285F4]',
    bg: 'bg-[#4285F4]/10',
    border: 'border-[#4285F4]/50',
  },
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
          const styles = providerStyles[provider.id as keyof typeof providerStyles];
          
          return (
            <button
              key={provider.id}
              onClick={() => toggleProvider(provider.id)}
              className={cn(
                "relative group flex flex-col items-center gap-3 p-4 rounded-xl border transition-all duration-300",
                isSelected
                  ? cn(styles?.bg, styles?.border, styles?.glow, "animate-pulse-subtle")
                  : "bg-card/50 border-border/50 hover:border-primary/30 hover:bg-card/80"
              )}
            >
              {isSelected && (
                <div className="absolute top-2 right-2">
                  <Check className={cn("h-4 w-4", styles?.text || "text-primary")} />
                </div>
              )}
              <div className={cn(
                "relative p-3 rounded-lg transition-all duration-300 overflow-hidden",
                isSelected 
                  ? cn("bg-gradient-to-br", styles?.gradient)
                  : "bg-secondary/50 group-hover:bg-secondary"
              )}>
                <Icon className={cn(
                  "h-6 w-6 transition-colors relative z-10",
                  isSelected ? "text-white" : "text-muted-foreground group-hover:text-foreground"
                )} />
              </div>
              <div className="text-center">
                <p className={cn(
                  "font-medium text-sm transition-colors",
                  isSelected ? styles?.text : "text-foreground"
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
