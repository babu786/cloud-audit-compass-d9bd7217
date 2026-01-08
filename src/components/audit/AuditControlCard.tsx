import { useState } from 'react';
import { ChevronDown, ChevronRight, Terminal, CheckCircle2, XCircle, Lightbulb, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AuditControl } from '@/data/auditContent';
import { SeverityBadge } from './SeverityBadge';

interface AuditControlCardProps {
  control: AuditControl;
  defaultExpanded?: boolean;
}

// SVG Logos for cloud providers
const AwsLogo = () => (
  <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
    <path d="M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.415-.287-.806-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.176 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167z"/>
  </svg>
);

const AzureLogo = () => (
  <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
    <path d="M5.483 21.3H24L14.025 4.013l-3.038 8.347 5.836 6.938L5.483 21.3zM13.23 2.7L6.105 8.677 0 19.253h5.505l7.725-16.553z"/>
  </svg>
);

const GcpLogo = () => (
  <svg viewBox="0 0 24 24" className="w-5 h-5" fill="currentColor">
    <path d="M12.19 2.38a9.344 9.344 0 0 0-9.234 6.893c.053-.02-.055.013 0 0-3.875 2.551-3.922 8.11-.247 10.941l.006-.007-.007.03a6.717 6.717 0 0 0 4.077 1.356h5.173l.03.03h5.192c6.687.053 9.376-8.605 3.835-12.35a9.365 9.365 0 0 0-8.825-6.893zM8.073 19.658H5.777a4.576 4.576 0 0 1-2.41-.873 5.26 5.26 0 0 1-.036-8.25c-.247.56-.379 1.168-.379 1.79a5.325 5.325 0 0 0 5.319 5.319h4.988l-5.186 2.014zm9.086-2.014h-4.988L17.357 15.63h.022a3.287 3.287 0 0 0 3.28-3.28 3.222 3.222 0 0 0-.054-.582 6.814 6.814 0 0 1-.014 5.876zm1.168-8.357a7.32 7.32 0 0 0-6.146-5.009 7.317 7.317 0 0 1 6.908 5.009h-.762z"/>
  </svg>
);

const cloudLogos = {
  AWS: AwsLogo,
  Azure: AzureLogo,
  GCP: GcpLogo,
};

const cloudStyles = {
  AWS: {
    color: 'text-[#FF9900]',
    bg: 'bg-[#FF9900]/20',
    border: 'border-l-[#FF9900]',
  },
  Azure: {
    color: 'text-[#0078D4]',
    bg: 'bg-[#0078D4]/20',
    border: 'border-l-[#0078D4]',
  },
  GCP: {
    color: 'text-[#4285F4]',
    bg: 'bg-[#4285F4]/20',
    border: 'border-l-[#4285F4]',
  },
};

const severityAccent = {
  Critical: 'from-severity-critical/20 via-transparent',
  High: 'from-severity-high/20 via-transparent',
  Medium: 'from-severity-medium/20 via-transparent',
  Low: 'from-severity-low/20 via-transparent',
};

export function AuditControlCard({ control, defaultExpanded = false }: AuditControlCardProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  const CloudLogo = cloudLogos[control.cloudProvider];
  const cloudStyle = cloudStyles[control.cloudProvider];

  return (
    <div className={cn(
      "group relative rounded-2xl border-l-4 transition-all duration-500 overflow-hidden",
      cloudStyle.border,
      isExpanded 
        ? "bg-card/90 backdrop-blur-xl border border-primary/30 shadow-xl shadow-primary/5" 
        : "bg-card/50 backdrop-blur-lg border border-border/50 hover:border-primary/20 hover:bg-card/70 hover:shadow-lg hover:-translate-y-0.5"
    )}>
      {/* Severity gradient accent */}
      <div className={cn(
        "absolute inset-0 bg-gradient-to-r opacity-50 pointer-events-none",
        severityAccent[control.severity]
      )} />
      
      {/* Rainbow border on hover */}
      <div className={cn(
        "absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none",
        "before:absolute before:inset-0 before:rounded-2xl before:p-[1px]",
        "before:bg-gradient-to-r before:from-primary before:via-purple-500 before:to-pink-500",
        "before:animate-gradient-shift before:bg-[length:200%_100%]"
      )} style={{ 
        mask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
        maskComposite: 'exclude',
        WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
        WebkitMaskComposite: 'xor',
        padding: '1px'
      }} />
      
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="relative w-full flex items-start gap-4 p-5 text-left z-10"
      >
        <div className={cn(
          "p-2.5 rounded-xl transition-all duration-300",
          isExpanded ? cloudStyle.bg : "bg-secondary/50 group-hover:bg-secondary",
          cloudStyle.color
        )}>
          <CloudLogo />
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-mono text-muted-foreground bg-muted/50 px-2 py-0.5 rounded">
              {control.id}
            </span>
            <SeverityBadge severity={control.severity} size="sm" />
          </div>
          <h3 className="font-semibold text-foreground leading-tight text-base">
            {control.title}
          </h3>
          <p className="text-sm text-muted-foreground mt-1.5 line-clamp-2">
            {control.whatToCheck}
          </p>
        </div>
        
        <div className={cn(
          "flex-shrink-0 p-2 rounded-lg transition-all duration-300",
          isExpanded ? "bg-primary/20 rotate-0" : "bg-transparent group-hover:bg-secondary/50"
        )}>
          {isExpanded ? (
            <ChevronDown className="h-5 w-5 text-primary" />
          ) : (
            <ChevronRight className="h-5 w-5 text-muted-foreground group-hover:text-foreground transition-colors" />
          )}
        </div>
      </button>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="relative px-5 pb-5 space-y-5 border-t border-border/50 pt-5 animate-accordion-spring z-10">
          {/* Why It Matters */}
          <section className="space-y-2">
            <h4 className="text-sm font-semibold text-primary flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Why It Matters
            </h4>
            <p className="text-sm text-muted-foreground pl-6">
              {control.whyItMatters}
            </p>
          </section>

          {/* Console Steps */}
          <section className="space-y-3">
            <h4 className="text-sm font-semibold text-foreground">Step-by-Step Console Instructions</h4>
            <ol className="space-y-2.5 pl-4">
              {control.consoleSteps.map((step, index) => (
                <li key={index} className="flex items-start gap-3 text-sm group/step">
                  <span className="flex-shrink-0 w-6 h-6 rounded-full bg-gradient-to-br from-primary/30 to-primary/10 text-primary text-xs flex items-center justify-center font-bold border border-primary/20">
                    {index + 1}
                  </span>
                  <span className="text-muted-foreground group-hover/step:text-foreground transition-colors">
                    {step}
                  </span>
                </li>
              ))}
            </ol>
          </section>

          {/* CLI Check */}
          {control.cliCheck && (
            <section className="space-y-2">
              <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
                <Terminal className="h-4 w-4" />
                CLI Command
              </h4>
              <pre className="bg-background/80 border border-border/50 rounded-xl p-4 overflow-x-auto group/code hover:border-primary/30 transition-colors">
                <code className="text-xs font-mono text-primary">{control.cliCheck}</code>
              </pre>
            </section>
          )}

          {/* Expected Configuration */}
          <section className="space-y-2">
            <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-severity-low" />
              Expected Secure Configuration
            </h4>
            <p className="text-sm text-muted-foreground pl-6 bg-severity-low/10 rounded-xl p-4 border border-severity-low/20">
              {control.expectedConfig}
            </p>
          </section>

          {/* Common Misconfigurations */}
          <section className="space-y-2">
            <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <XCircle className="h-4 w-4 text-severity-high" />
              Common Misconfigurations
            </h4>
            <ul className="space-y-2 pl-6">
              {control.commonMisconfigs.map((misconfig, index) => (
                <li key={index} className="text-sm text-muted-foreground flex items-start gap-2">
                  <span className="text-severity-high mt-1.5 text-lg leading-none">•</span>
                  {misconfig}
                </li>
              ))}
            </ul>
          </section>

          {/* Fix Hint */}
          <section className="space-y-2">
            <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Lightbulb className="h-4 w-4 text-severity-medium" />
              Hardening Hint
            </h4>
            <p className="text-sm text-muted-foreground pl-6 bg-severity-medium/10 rounded-xl p-4 border border-severity-medium/20">
              {control.fixHint}
            </p>
          </section>
        </div>
      )}
    </div>
  );
}
