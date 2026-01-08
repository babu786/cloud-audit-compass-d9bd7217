import { useEffect, useState } from 'react';
import { Shield, AlertTriangle, AlertCircle, Info, Cloud } from 'lucide-react';
import { auditControls } from '@/data/auditContent';
import { cn } from '@/lib/utils';

interface StatItemProps {
  icon: React.ReactNode;
  value: number;
  label: string;
  color: string;
  glowColor: string;
  delay: number;
  breakdown?: StatBreakdown[];
  total?: number;
  isPrimary?: boolean;
}

function AnimatedCounter({ value, delay }: { value: number; delay: number }) {
  const [count, setCount] = useState(0);
  const [isAnimating, setIsAnimating] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsAnimating(true);
      const duration = 2000;
      const steps = 60;
      const increment = value / steps;
      let current = 0;
      
      const interval = setInterval(() => {
        current += increment;
        if (current >= value) {
          setCount(value);
          clearInterval(interval);
        } else {
          setCount(Math.floor(current));
        }
      }, duration / steps);

      return () => clearInterval(interval);
    }, delay);

    return () => clearTimeout(timer);
  }, [value, delay]);

  return (
    <span className={cn(
      "transition-all duration-300",
      isAnimating && "animate-number-glow"
    )}>
      {count}
    </span>
  );
}

interface StatBreakdown {
  label: string;
  value: number;
  color: string;
}

function MiniProgressBar({ value, max, color }: { value: number; max: number; color: string }) {
  const percentage = max > 0 ? (value / max) * 100 : 0;
  return (
    <div className="w-full h-1.5 bg-muted/50 rounded-full overflow-hidden">
      <div 
        className={`h-full rounded-full transition-all duration-500 ${color}`}
        style={{ width: `${percentage}%` }}
      />
    </div>
  );
}

function StatItem({ icon, value, label, color, glowColor, delay, breakdown, total, isPrimary }: StatItemProps) {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), delay);
    return () => clearTimeout(timer);
  }, [delay]);

  return (
    <div 
      className={cn(
        "group relative flex flex-col items-center p-6 rounded-2xl border transition-all duration-500 cursor-default overflow-hidden",
        isPrimary 
          ? "col-span-2 md:col-span-1 bg-gradient-to-br from-primary/20 via-primary/10 to-transparent border-primary/30" 
          : "bg-card/60 backdrop-blur-xl border-border/50",
        "hover:border-primary/50 hover:-translate-y-2 hover:shadow-2xl",
        isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
      )}
      style={{ 
        transitionDelay: `${delay}ms`,
        boxShadow: isVisible ? `0 0 40px ${glowColor}` : 'none'
      }}
    >
      {/* Animated glow ring */}
      <div className={cn(
        "absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500",
        "bg-gradient-to-r from-transparent via-primary/10 to-transparent"
      )} />
      
      {/* Pulsing ring behind icon */}
      <div className="relative mb-4">
        <div className={cn(
          "absolute inset-0 rounded-full animate-ping opacity-20",
          color
        )} style={{ animationDuration: '2s' }} />
        <div className={cn(
          "relative p-4 rounded-full transition-all duration-300 group-hover:scale-110",
          color
        )}>
          {icon}
        </div>
      </div>
      
      {/* Large animated number */}
      <div className={cn(
        "text-5xl md:text-6xl font-bold font-mono tracking-tight",
        isPrimary ? "text-primary" : "text-foreground"
      )}>
        <AnimatedCounter value={value} delay={delay + 200} />
      </div>
      
      {/* Label */}
      <div className="text-sm font-medium text-muted-foreground mt-2 uppercase tracking-wider">
        {label}
      </div>
      
      {/* Shine effect on hover */}
      <div className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none overflow-hidden rounded-2xl">
        <div className="absolute inset-0 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-1000 bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      </div>
      
      {/* Hover tooltip with breakdown */}
      {breakdown && breakdown.length > 0 && (
        <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-3 opacity-0 group-hover:opacity-100 
                        transition-all duration-300 pointer-events-none z-20 translate-y-2 group-hover:translate-y-0">
          <div className="bg-popover/95 backdrop-blur-sm border border-border rounded-xl p-4 shadow-2xl min-w-[160px]">
            <div className="space-y-3">
              {breakdown.map((item) => (
                <div key={item.label} className="space-y-1.5">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">{item.label}</span>
                    <span className="font-mono font-bold">{item.value}</span>
                  </div>
                  <MiniProgressBar value={item.value} max={total || value} color={item.color} />
                </div>
              ))}
            </div>
            <div className="absolute -bottom-1.5 left-1/2 -translate-x-1/2 w-3 h-3 bg-popover border-r border-b border-border rotate-45" />
          </div>
        </div>
      )}
    </div>
  );
}

export function StatsBar() {
  const stats = {
    total: auditControls.length,
    critical: auditControls.filter(c => c.severity === 'Critical').length,
    high: auditControls.filter(c => c.severity === 'High').length,
    medium: auditControls.filter(c => c.severity === 'Medium').length,
    low: auditControls.filter(c => c.severity === 'Low').length,
    aws: auditControls.filter(c => c.cloudProvider === 'AWS').length,
    azure: auditControls.filter(c => c.cloudProvider === 'Azure').length,
    gcp: auditControls.filter(c => c.cloudProvider === 'GCP').length,
  };

  const severityBreakdown = [
    { label: 'Critical', value: stats.critical, color: 'bg-severity-critical' },
    { label: 'High', value: stats.high, color: 'bg-severity-high' },
    { label: 'Medium', value: stats.medium, color: 'bg-severity-medium' },
    { label: 'Low', value: stats.low, color: 'bg-severity-low' },
  ];

  const providerBreakdown = [
    { label: 'AWS', value: stats.aws, color: 'bg-orange-500' },
    { label: 'Azure', value: stats.azure, color: 'bg-blue-500' },
    { label: 'GCP', value: stats.gcp, color: 'bg-red-500' },
  ];

  return (
    <div className="w-full mb-10">
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4 md:gap-6">
        <StatItem
          icon={<Shield className="w-8 h-8 text-primary" />}
          value={stats.total}
          label="Total Controls"
          color="bg-primary/20"
          glowColor="hsl(187 80% 55% / 0.15)"
          delay={0}
          breakdown={severityBreakdown}
          total={stats.total}
          isPrimary
        />
        <StatItem
          icon={<AlertTriangle className="w-7 h-7 text-severity-critical" />}
          value={stats.critical}
          label="Critical"
          color="bg-severity-critical/30"
          glowColor="hsl(0 84% 60% / 0.15)"
          delay={150}
        />
        <StatItem
          icon={<AlertCircle className="w-7 h-7 text-severity-high" />}
          value={stats.high}
          label="High"
          color="bg-severity-high/30"
          glowColor="hsl(25 95% 53% / 0.15)"
          delay={300}
        />
        <StatItem
          icon={<Info className="w-7 h-7 text-severity-medium" />}
          value={stats.medium}
          label="Medium"
          color="bg-severity-medium/30"
          glowColor="hsl(45 93% 47% / 0.15)"
          delay={450}
        />
        <StatItem
          icon={<Cloud className="w-7 h-7 text-primary" />}
          value={3}
          label="Cloud Providers"
          color="bg-primary/20"
          glowColor="hsl(187 80% 55% / 0.1)"
          delay={600}
          breakdown={providerBreakdown}
          total={stats.total}
        />
      </div>
    </div>
  );
}
