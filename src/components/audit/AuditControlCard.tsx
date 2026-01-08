import { useState } from 'react';
import { ChevronDown, ChevronRight, Cloud, Server, Database, Terminal, CheckCircle2, XCircle, Lightbulb, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AuditControl } from '@/data/auditContent';
import { SeverityBadge } from './SeverityBadge';

interface AuditControlCardProps {
  control: AuditControl;
  defaultExpanded?: boolean;
}

const cloudIcons = {
  AWS: Cloud,
  Azure: Server,
  GCP: Database,
};

export function AuditControlCard({ control, defaultExpanded = false }: AuditControlCardProps) {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  const CloudIcon = cloudIcons[control.cloudProvider];

  return (
    <div className={cn(
      "group rounded-xl border transition-all duration-300 animate-fade-in",
      isExpanded 
        ? "bg-card border-primary/30 glow-sm" 
        : "bg-card/50 border-border/50 hover:border-primary/20 hover:bg-card/80"
    )}>
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-start gap-4 p-4 text-left"
      >
        <div className={cn(
          "p-2 rounded-lg transition-colors mt-0.5",
          isExpanded ? "bg-primary/20" : "bg-secondary/50"
        )}>
          <CloudIcon className={cn(
            "h-5 w-5 transition-colors",
            isExpanded ? "text-primary" : "text-muted-foreground"
          )} />
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-muted-foreground">{control.id}</span>
            <SeverityBadge severity={control.severity} size="sm" />
          </div>
          <h3 className="font-medium text-foreground leading-tight">
            {control.title}
          </h3>
          <p className="text-sm text-muted-foreground mt-1 line-clamp-2">
            {control.whatToCheck}
          </p>
        </div>
        
        <div className="flex-shrink-0 p-1">
          {isExpanded ? (
            <ChevronDown className="h-5 w-5 text-primary" />
          ) : (
            <ChevronRight className="h-5 w-5 text-muted-foreground group-hover:text-foreground transition-colors" />
          )}
        </div>
      </button>

      {/* Expanded Content */}
      {isExpanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-border/50 pt-4 animate-fade-in">
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
          <section className="space-y-2">
            <h4 className="text-sm font-semibold text-foreground">Step-by-Step Console Instructions</h4>
            <ol className="space-y-2 pl-4">
              {control.consoleSteps.map((step, index) => (
                <li key={index} className="flex items-start gap-3 text-sm">
                  <span className="flex-shrink-0 w-5 h-5 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center font-medium">
                    {index + 1}
                  </span>
                  <span className="text-muted-foreground">{step}</span>
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
              <pre className="bg-background/80 border border-border/50 rounded-lg p-3 overflow-x-auto">
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
            <p className="text-sm text-muted-foreground pl-6 bg-severity-low/10 rounded-lg p-3 border border-severity-low/20">
              {control.expectedConfig}
            </p>
          </section>

          {/* Common Misconfigurations */}
          <section className="space-y-2">
            <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <XCircle className="h-4 w-4 text-severity-high" />
              Common Misconfigurations
            </h4>
            <ul className="space-y-1.5 pl-6">
              {control.commonMisconfigs.map((misconfig, index) => (
                <li key={index} className="text-sm text-muted-foreground flex items-start gap-2">
                  <span className="text-severity-high mt-1">•</span>
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
            <p className="text-sm text-muted-foreground pl-6 bg-severity-medium/10 rounded-lg p-3 border border-severity-medium/20">
              {control.fixHint}
            </p>
          </section>
        </div>
      )}
    </div>
  );
}
