import { CheckCircle2, Trophy, Shield, Clock, RotateCcw, Home } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/i18n/LanguageContext';

interface CompletionStats {
  totalControls: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  providers: string[];
  frameworks: string[];
}

interface CompletionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRestart: () => void;
  onGoHome: () => void;
  stats: CompletionStats;
}

export function CompletionModal({ 
  isOpen, 
  onClose, 
  onRestart, 
  onGoHome, 
  stats 
}: CompletionModalProps) {
  const { t } = useLanguage();

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-background/80 backdrop-blur-sm animate-fade-in"
        onClick={onClose}
      />
      
      {/* Modal */}
      <div className="relative bg-card border border-border rounded-2xl shadow-2xl max-w-md w-full overflow-hidden animate-scale-in">
        {/* Header with gradient */}
        <div className="bg-gradient-to-br from-primary/20 via-primary/10 to-transparent p-8 text-center relative overflow-hidden">
          {/* Animated rings */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-32 h-32 rounded-full border-2 border-primary/20 animate-ping" style={{ animationDuration: '2s' }} />
          </div>
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="w-24 h-24 rounded-full border-2 border-primary/30 animate-ping" style={{ animationDuration: '2s', animationDelay: '0.5s' }} />
          </div>
          
          {/* Trophy icon */}
          <div className="relative">
            <div className="inline-flex items-center justify-center w-20 h-20 rounded-full bg-primary/20 mb-4">
              <Trophy className="w-10 h-10 text-primary animate-bounce" style={{ animationDuration: '1s' }} />
            </div>
          </div>
          
          <h2 className="text-2xl font-bold text-foreground mb-2">
            Audit Complete!
          </h2>
          <p className="text-muted-foreground text-sm">
            Congratulations on completing your security audit
          </p>
        </div>

        {/* Stats */}
        <div className="p-6 space-y-4">
          {/* Total reviewed */}
          <div className="flex items-center justify-between p-3 bg-secondary/30 rounded-lg">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-primary" />
              <span className="text-sm font-medium">Controls Reviewed</span>
            </div>
            <span className="text-lg font-bold text-primary">{stats.totalControls}</span>
          </div>

          {/* Severity breakdown */}
          <div className="grid grid-cols-4 gap-2">
            <div className="text-center p-2 rounded-lg bg-severity-critical/10">
              <div className="text-lg font-bold text-severity-critical">{stats.criticalCount}</div>
              <div className="text-xs text-muted-foreground">Critical</div>
            </div>
            <div className="text-center p-2 rounded-lg bg-severity-high/10">
              <div className="text-lg font-bold text-severity-high">{stats.highCount}</div>
              <div className="text-xs text-muted-foreground">High</div>
            </div>
            <div className="text-center p-2 rounded-lg bg-severity-medium/10">
              <div className="text-lg font-bold text-severity-medium">{stats.mediumCount}</div>
              <div className="text-xs text-muted-foreground">Medium</div>
            </div>
            <div className="text-center p-2 rounded-lg bg-severity-low/10">
              <div className="text-lg font-bold text-severity-low">{stats.lowCount}</div>
              <div className="text-xs text-muted-foreground">Low</div>
            </div>
          </div>

          {/* Providers & Frameworks */}
          <div className="flex flex-wrap gap-2 justify-center pt-2">
            {stats.providers.map(provider => (
              <span key={provider} className="px-2 py-1 text-xs bg-secondary rounded-full text-muted-foreground">
                {provider}
              </span>
            ))}
            {stats.frameworks.map(framework => (
              <span key={framework} className="px-2 py-1 text-xs bg-primary/20 text-primary rounded-full">
                {framework}
              </span>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="p-6 pt-0 flex gap-3">
          <Button 
            variant="outline" 
            className="flex-1 gap-2"
            onClick={onRestart}
          >
            <RotateCcw className="w-4 h-4" />
            Start New
          </Button>
          <Button 
            className="flex-1 gap-2"
            onClick={onGoHome}
          >
            <Home className="w-4 h-4" />
            Back to Home
          </Button>
        </div>
      </div>
    </div>
  );
}
