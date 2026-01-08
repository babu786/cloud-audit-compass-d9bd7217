import { useEffect, useState } from 'react';
import { Shield, AlertTriangle, AlertCircle, Info, Cloud } from 'lucide-react';
import { auditControls } from '@/data/auditContent';

interface StatItemProps {
  icon: React.ReactNode;
  value: number;
  label: string;
  color: string;
  delay: number;
}

function AnimatedCounter({ value, delay }: { value: number; delay: number }) {
  const [count, setCount] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => {
      const duration = 1500;
      const steps = 30;
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

  return <span>{count}</span>;
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

function StatItem({ icon, value, label, color, delay, breakdown, total }: StatItemProps & { breakdown?: StatBreakdown[]; total?: number }) {
  return (
    <div 
      className={`group relative flex flex-col items-center p-2 sm:p-4 rounded-xl glass border border-border/50 
                  hover:border-primary/50 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg
                  animate-fade-in cursor-default`}
      style={{ animationDelay: `${delay}ms`, animationFillMode: 'backwards' }}
    >
      <div className={`p-1.5 xs:p-2 sm:p-3 rounded-full ${color} mb-1 sm:mb-2 group-hover:scale-110 transition-transform duration-300`}>
        {icon}
      </div>
      <div className="text-lg xs:text-xl sm:text-3xl font-bold text-foreground font-mono">
        <AnimatedCounter value={value} delay={delay} />
      </div>
      <div className="text-[10px] xs:text-xs sm:text-sm text-muted-foreground mt-0.5 sm:mt-1 text-center">{label}</div>
      
      {/* Glow effect on hover */}
      <div className={`absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 
                       bg-gradient-to-b from-primary/5 to-transparent pointer-events-none`} />
      
      {/* Hover tooltip with breakdown - hidden on mobile */}
      {breakdown && breakdown.length > 0 && (
        <div className="absolute bottom-full left-0 sm:left-1/2 sm:-translate-x-1/2 mb-2 opacity-0 group-hover:opacity-100 
                        transition-all duration-300 pointer-events-none z-20 translate-y-2 group-hover:translate-y-0 hidden sm:block">
          <div className="bg-popover/95 backdrop-blur-sm border border-border rounded-lg p-3 shadow-xl min-w-[140px]">
            <div className="space-y-2">
              {breakdown.map((item) => (
                <div key={item.label} className="space-y-1">
                  <div className="flex justify-between text-xs">
                    <span className="text-muted-foreground">{item.label}</span>
                    <span className="font-mono font-medium">{item.value}</span>
                  </div>
                  <MiniProgressBar value={item.value} max={total || value} color={item.color} />
                </div>
              ))}
            </div>
            <div className="absolute -bottom-1 left-4 sm:left-1/2 sm:-translate-x-1/2 w-2 h-2 bg-popover border-r border-b border-border rotate-45" />
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
    <div className="w-full mb-6 sm:mb-8">
      <div className="grid grid-cols-2 xs:grid-cols-3 md:grid-cols-5 gap-2 sm:gap-4">
        <StatItem
          icon={<Shield className="w-6 h-6 text-primary" />}
          value={stats.total}
          label="Total Controls"
          color="bg-primary/20"
          delay={0}
          breakdown={severityBreakdown}
          total={stats.total}
        />
        <StatItem
          icon={<AlertTriangle className="w-6 h-6 text-severity-critical" />}
          value={stats.critical}
          label="Critical"
          color="bg-severity-critical/20"
          delay={100}
        />
        <StatItem
          icon={<AlertCircle className="w-6 h-6 text-severity-high" />}
          value={stats.high}
          label="High"
          color="bg-severity-high/20"
          delay={200}
        />
        <StatItem
          icon={<Info className="w-6 h-6 text-severity-medium" />}
          value={stats.medium}
          label="Medium"
          color="bg-severity-medium/20"
          delay={300}
        />
        <div className="hidden xs:block">
          <StatItem
            icon={<Cloud className="w-6 h-6 text-muted-foreground" />}
            value={stats.aws + stats.azure + stats.gcp}
            label="Providers"
            color="bg-muted/50"
            delay={400}
            breakdown={providerBreakdown}
            total={stats.total}
          />
        </div>
      </div>
    </div>
  );
}
