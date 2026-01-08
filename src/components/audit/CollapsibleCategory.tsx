import { useState } from 'react';
import { ChevronDown, ChevronRight, Shield, Network, Activity, HardDrive, Cpu, Lock, Database, ShieldCheck, ClipboardCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AuditControl } from '@/data/auditContent';
import { AuditControlCard } from './AuditControlCard';

interface CollapsibleCategoryProps {
  category: {
    id: string;
    name: string;
    icon: string;
  };
  controls: AuditControl[];
  defaultOpen?: boolean;
}

const iconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  Shield: Shield,
  Network: Network,
  Activity: Activity,
  HardDrive: HardDrive,
  Cpu: Cpu,
  Lock: Lock,
  Database: Database,
  ShieldCheck: ShieldCheck,
  ClipboardCheck: ClipboardCheck,
};

export function CollapsibleCategory({ category, controls, defaultOpen = false }: CollapsibleCategoryProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const Icon = iconMap[category.icon] || Shield;

  return (
    <div className="rounded-lg border border-border/50 bg-card/30 overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className={cn(
          "w-full flex items-center justify-between px-4 py-3 transition-colors",
          "hover:bg-muted/50",
          isOpen && "border-b border-border/50 bg-muted/30"
        )}
      >
        <div className="flex items-center gap-3">
          {isOpen ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
          <Icon className="h-5 w-5 text-primary" />
          <span className="font-medium text-foreground">{category.name}</span>
        </div>
        <span className="text-sm text-muted-foreground bg-muted/50 px-2 py-0.5 rounded-full">
          {controls.length} controls
        </span>
      </button>
      
      {isOpen && (
        <div className="p-4 space-y-4 animate-in slide-in-from-top-2 duration-200">
          {controls.map((control) => (
            <AuditControlCard key={control.id} control={control} />
          ))}
        </div>
      )}
    </div>
  );
}
