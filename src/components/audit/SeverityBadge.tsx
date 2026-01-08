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
    bgClass: 'bg-severity-critical',
    textClass: 'text-severity-critical',
  },
  High: {
    icon: AlertTriangle,
    bgClass: 'bg-severity-high',
    textClass: 'text-severity-high',
  },
  Medium: {
    icon: AlertCircle,
    bgClass: 'bg-severity-medium',
    textClass: 'text-severity-medium',
  },
  Low: {
    icon: Info,
    bgClass: 'bg-severity-low',
    textClass: 'text-severity-low',
  },
};

export function SeverityBadge({ severity, showIcon = true, size = 'md' }: SeverityBadgeProps) {
  const config = severityConfig[severity];
  const Icon = config.icon;

  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded-full font-medium",
      config.bgClass,
      config.textClass,
      size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs'
    )}>
      {showIcon && <Icon className={cn(size === 'sm' ? 'h-3 w-3' : 'h-3.5 w-3.5')} />}
      {severity}
    </span>
  );
}
