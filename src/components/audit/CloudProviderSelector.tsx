import { Check } from 'lucide-react';
import { cn } from '@/lib/utils';
import { cloudProviders } from '@/data/auditContent';

interface CloudProviderSelectorProps {
  selected: string[];
  onSelect: (providers: string[]) => void;
}

// SVG Logos for cloud providers
const AwsLogo = () => (
  <svg viewBox="0 0 24 24" className="w-8 h-8" fill="currentColor">
    <path d="M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.415-.287-.806-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.176 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167z"/>
  </svg>
);

const AzureLogo = () => (
  <svg viewBox="0 0 24 24" className="w-8 h-8" fill="currentColor">
    <path d="M5.483 21.3H24L14.025 4.013l-3.038 8.347 5.836 6.938L5.483 21.3zM13.23 2.7L6.105 8.677 0 19.253h5.505l7.725-16.553z"/>
  </svg>
);

const GcpLogo = () => (
  <svg viewBox="0 0 24 24" className="w-8 h-8" fill="currentColor">
    <path d="M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-8.825-6.893zM8.073 19.658H5.777a4.576 4.576 0 0 1-2.41-.873 5.26 5.26 0 0 1-.036-8.25c-.247.56-.379 1.168-.379 1.79a5.325 5.325 0 0 0 5.319 5.319h4.988l-5.186 2.014zm9.086-2.014h-4.988L17.357 15.63h.022a3.287 3.287 0 0 0 3.28-3.28 3.222 3.222 0 0 0-.054-.582 6.814 6.814 0 0 1-.014 5.876zm1.168-8.357a7.32 7.32 0 0 0-6.146-5.009 7.317 7.317 0 0 1 6.908 5.009h-.762z"/>
  </svg>
);

const providerLogos = {
  AWS: AwsLogo,
  Azure: AzureLogo,
  GCP: GcpLogo,
};

const providerStyles = {
  AWS: {
    gradient: 'from-[#FF9900] to-[#FF6600]',
    glow: 'shadow-[0_0_30px_rgba(255,153,0,0.5)]',
    text: 'text-[#FF9900]',
    bg: 'bg-[#FF9900]/15',
    border: 'border-[#FF9900]/60',
    hoverGlow: 'hover:shadow-[0_0_25px_rgba(255,153,0,0.3)]',
  },
  Azure: {
    gradient: 'from-[#0078D4] to-[#00BCF2]',
    glow: 'shadow-[0_0_30px_rgba(0,120,212,0.5)]',
    text: 'text-[#0078D4]',
    bg: 'bg-[#0078D4]/15',
    border: 'border-[#0078D4]/60',
    hoverGlow: 'hover:shadow-[0_0_25px_rgba(0,120,212,0.3)]',
  },
  GCP: {
    gradient: 'from-[#EA4335] via-[#FBBC04] to-[#34A853]',
    glow: 'shadow-[0_0_30px_rgba(66,133,244,0.5)]',
    text: 'text-[#4285F4]',
    bg: 'bg-[#4285F4]/15',
    border: 'border-[#4285F4]/60',
    hoverGlow: 'hover:shadow-[0_0_25px_rgba(66,133,244,0.3)]',
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
      <div className="grid grid-cols-3 gap-4">
        {cloudProviders.map((provider) => {
          const isSelected = selected.includes(provider.id);
          const Logo = providerLogos[provider.id as keyof typeof providerLogos];
          const styles = providerStyles[provider.id as keyof typeof providerStyles];
          
          return (
            <button
              key={provider.id}
              onClick={() => toggleProvider(provider.id)}
              className={cn(
                "relative group flex flex-col items-center gap-3 p-5 rounded-2xl border-2 transition-all duration-500",
                "hover:-translate-y-1",
                isSelected
                  ? cn(styles?.bg, styles?.border, styles?.glow, "scale-[1.02]")
                  : cn("bg-card/50 border-border/50", styles?.hoverGlow, "hover:border-primary/30 hover:bg-card/80")
              )}
            >
              {/* Selection checkmark */}
              {isSelected && (
                <div className={cn(
                  "absolute top-2 right-2 p-1 rounded-full",
                  "bg-gradient-to-br", styles?.gradient
                )}>
                  <Check className="h-3.5 w-3.5 text-white" />
                </div>
              )}
              
              {/* Logo container with gradient background */}
              <div className={cn(
                "relative p-4 rounded-xl transition-all duration-300 overflow-hidden",
                isSelected 
                  ? cn("bg-gradient-to-br", styles?.gradient)
                  : "bg-secondary/50 group-hover:bg-secondary"
              )}>
                {/* Animated ring */}
                {isSelected && (
                  <div className="absolute inset-0 rounded-xl animate-ping opacity-30 bg-white" 
                       style={{ animationDuration: '2s' }} />
                )}
                <div className={cn(
                  "relative z-10 transition-transform duration-300 group-hover:scale-110",
                  isSelected ? "text-white" : "text-muted-foreground group-hover:text-foreground"
                )}>
                  <Logo />
                </div>
              </div>
              
              {/* Provider name */}
              <div className="text-center">
                <p className={cn(
                  "font-bold text-lg transition-colors",
                  isSelected ? styles?.text : "text-foreground"
                )}>
                  {provider.id}
                </p>
                <p className="text-xs text-muted-foreground mt-0.5 hidden sm:block">
                  {provider.name}
                </p>
              </div>
              
              {/* Ripple effect on click */}
              <div className="absolute inset-0 rounded-2xl overflow-hidden pointer-events-none">
                <div className={cn(
                  "absolute inset-0 opacity-0 group-active:opacity-100 transition-opacity",
                  "bg-gradient-to-r from-transparent via-white/20 to-transparent",
                  "translate-x-[-100%] group-active:translate-x-[100%] transition-transform duration-500"
                )} />
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
