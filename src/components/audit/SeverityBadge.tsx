import { cn } from '@/lib/utils';
import { AlertTriangle, AlertCircle, Info, XCircle } from 'lucide-react';

interface SeverityBadgeProps {
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  showIcon?: boolean;
  size?: 'sm' | 'md';
}

const severityConfig = {
  Critical: {
    icon: XCircle,
    gradient: 'bg-gradient-to-r from-red-600 to-red-500',
    textClass: 'text-white',
    pulseClass: 'animate-pulse-glow-red',
    shadow: 'shadow-lg shadow-red-500/30',
  },
  High: {
    icon: AlertTriangle,
    gradient: 'bg-gradient-to-r from-orange-600 to-orange-500',
    textClass: 'text-white',
    pulseClass: 'animate-pulse-glow-orange',
    shadow: 'shadow-lg shadow-orange-500/30',
  },
  Medium: {
    icon: AlertCircle,
    gradient: 'bg-gradient-to-r from-amber-500 to-yellow-500',
    textClass: 'text-amber-950',
    pulseClass: '',
    shadow: 'shadow-md shadow-amber-500/20',
  },
  Low: {
    icon: Info,
    gradient: 'bg-gradient-to-r from-emerald-600 to-green-500',
    textClass: 'text-white',
    pulseClass: '',
    shadow: 'shadow-md shadow-emerald-500/20',
  },
};

export function SeverityBadge({ severity, showIcon = true, size = 'md' }: SeverityBadgeProps) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded-full font-semibold uppercase tracking-wide",
      config.gradient,
      config.textClass,
      config.pulseClass,
      config.shadow,
      size === 'sm' ? 'px-2.5 py-0.5 text-[10px]' : 'px-3 py-1 text-xs'
    )}>
      {showIcon && (
        <Icon className={cn(
          "drop-shadow-sm",
          size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5'
        )} />
      )}
      {severity}
    </span>
  );
}
