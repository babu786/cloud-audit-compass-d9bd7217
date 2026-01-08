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

function StatItem({ icon, value, label, color, delay }: StatItemProps) {
  return (
    <div 
      className={`group relative flex flex-col items-center p-4 rounded-xl glass border border-border/50 
                  hover:border-primary/50 transition-all duration-300 hover:-translate-y-1 hover:shadow-lg
                  animate-fade-in cursor-default`}
      style={{ animationDelay: `${delay}ms`, animationFillMode: 'backwards' }}
    >
      <div className={`p-3 rounded-full ${color} mb-2 group-hover:scale-110 transition-transform duration-300`}>
        {icon}
      </div>
      <div className="text-3xl font-bold text-foreground font-mono">
        <AnimatedCounter value={value} delay={delay} />
      </div>
      <div className="text-sm text-muted-foreground mt-1">{label}</div>
      
      {/* Glow effect on hover */}
      <div className={`absolute inset-0 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 
                       bg-gradient-to-b from-primary/5 to-transparent pointer-events-none`} />
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

  return (
    <div className="w-full mb-8">
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
        <StatItem
          icon={<Shield className="w-6 h-6 text-primary" />}
          value={stats.total}
          label="Total Controls"
          color="bg-primary/20"
          delay={0}
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
        <StatItem
          icon={<Cloud className="w-6 h-6 text-muted-foreground" />}
          value={stats.aws + stats.azure + stats.gcp}
          label="Providers"
          color="bg-muted/50"
          delay={400}
        />
      </div>
    </div>
  );
}
