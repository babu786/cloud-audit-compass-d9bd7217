import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { ChevronLeft, ChevronRight, Home, Filter, X, Terminal, CheckCircle2, XCircle, Lightbulb, AlertTriangle } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { CloudProviderSelector } from '@/components/audit/CloudProviderSelector';
import { FrameworkSelector } from '@/components/audit/FrameworkSelector';
import { CategorySelector } from '@/components/audit/CategorySelector';
import { SeverityBadge } from '@/components/audit/SeverityBadge';
import { Button } from '@/components/ui/button';
import { auditControls, serviceCategories } from '@/data/auditContent';
import { cn } from '@/lib/utils';

const GuidedAudit = () => {
  const [selectedProviders, setSelectedProviders] = useState<string[]>([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [showFilters, setShowFilters] = useState(true);

  const filteredControls = useMemo(() => {
    return auditControls.filter(control => {
      if (selectedProviders.length > 0 && !selectedProviders.includes(control.cloudProvider)) {
        return false;
      }
      if (selectedFrameworks.length > 0 && !selectedFrameworks.includes(control.framework)) {
        return false;
      }
      if (selectedCategories.length > 0 && !selectedCategories.includes(control.category)) {
        return false;
      }
      return true;
    });
  }, [selectedProviders, selectedFrameworks, selectedCategories]);

  const currentControl = filteredControls[currentIndex];
  const totalControls = filteredControls.length;
  const progress = totalControls > 0 ? ((currentIndex + 1) / totalControls) * 100 : 0;

  const handlePrevious = () => {
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1);
    }
  };

  const handleNext = () => {
    if (currentIndex < totalControls - 1) {
      setCurrentIndex(currentIndex + 1);
    }
  };

  const startAudit = () => {
    setShowFilters(false);
    setCurrentIndex(0);
  };

  const getCategoryName = (categoryId: string) => {
    return serviceCategories.find(c => c.id === categoryId)?.name || categoryId;
  };

  if (showFilters) {
    return (
      <AppLayout>
        <div className="container py-8 max-w-4xl">
          <div className="mb-8">
            <h1 className="text-3xl font-bold gradient-text mb-2">
              Guided Audit Mode
            </h1>
            <p className="text-muted-foreground">
              Focus on one control at a time. Select your audit scope to begin.
            </p>
          </div>

          <div className="space-y-6 p-6 rounded-xl bg-card/30 border border-border/30">
            <CloudProviderSelector 
              selected={selectedProviders} 
              onSelect={setSelectedProviders} 
            />
            
            <FrameworkSelector 
              selected={selectedFrameworks} 
              onSelect={setSelectedFrameworks} 
            />
            
            <CategorySelector 
              selected={selectedCategories} 
              onSelect={setSelectedCategories} 
            />

            <div className="flex items-center justify-between pt-4 border-t border-border/30">
              <p className="text-sm text-muted-foreground">
                {filteredControls.length} controls selected
              </p>
              <Button 
                onClick={startAudit}
                disabled={filteredControls.length === 0}
                className="gap-2"
              >
                Start Guided Audit
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="mt-6 text-center">
            <Link to="/" className="text-sm text-muted-foreground hover:text-foreground transition-colors">
              ← Back to all controls
            </Link>
          </div>
        </div>
      </AppLayout>
    );
  }

  if (!currentControl) {
    return (
      <AppLayout>
        <div className="container py-12 text-center">
          <p className="text-muted-foreground mb-4">No controls match your selection.</p>
          <Button onClick={() => setShowFilters(true)}>
            Update Selection
          </Button>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="container py-6 max-w-4xl">
        {/* Progress Bar */}
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <button
              onClick={() => setShowFilters(true)}
              className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <Filter className="h-4 w-4" />
              Change scope
            </button>
            <span className="text-sm text-muted-foreground">
              {currentIndex + 1} of {totalControls}
            </span>
          </div>
          <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
            <div 
              className="h-full bg-primary transition-all duration-300 ease-out"
              style={{ width: `${progress}%` }}
            />
          </div>
        </div>

        {/* Control Card */}
        <div className="bg-card rounded-xl border border-border/50 animate-fade-in">
          {/* Header */}
          <div className="p-6 border-b border-border/50">
            <div className="flex items-start justify-between gap-4 mb-4">
              <div className="flex items-center gap-3">
                <span className="text-sm font-mono text-muted-foreground bg-secondary/50 px-2 py-1 rounded">
                  {currentControl.id}
                </span>
                <SeverityBadge severity={currentControl.severity} />
              </div>
              <div className="flex items-center gap-2 text-xs text-muted-foreground flex-wrap">
                <span className="px-2 py-1 bg-secondary/50 rounded">{currentControl.cloudProvider}</span>
                <span className="px-2 py-1 bg-primary/20 text-primary rounded font-medium">{currentControl.framework}</span>
                <span className="px-2 py-1 bg-secondary/50 rounded">{getCategoryName(currentControl.category)}</span>
              </div>
            </div>
            <h2 className="text-xl font-semibold text-foreground">
              {currentControl.title}
            </h2>
          </div>

          {/* Content */}
          <div className="p-6 space-y-6">
            {/* What to Check */}
            <section>
              <h3 className="text-sm font-semibold text-foreground mb-2">What to Check</h3>
              <p className="text-muted-foreground">{currentControl.whatToCheck}</p>
            </section>

            {/* Why It Matters */}
            <section className="bg-primary/5 border border-primary/20 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-primary flex items-center gap-2 mb-2">
                <AlertTriangle className="h-4 w-4" />
                Why It Matters
              </h3>
              <p className="text-sm text-muted-foreground">{currentControl.whyItMatters}</p>
            </section>

            {/* Console Steps */}
            <section>
              <h3 className="text-sm font-semibold text-foreground mb-3">Step-by-Step Instructions</h3>
              <ol className="space-y-3">
                {currentControl.consoleSteps.map((step, index) => (
                  <li key={index} className="flex items-start gap-3">
                    <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary/20 text-primary text-sm flex items-center justify-center font-medium">
                      {index + 1}
                    </span>
                    <span className="text-muted-foreground pt-0.5">{step}</span>
                  </li>
                ))}
              </ol>
            </section>

            {/* CLI Check */}
            {currentControl.cliCheck && (
              <section>
                <h3 className="text-sm font-semibold text-foreground flex items-center gap-2 mb-3">
                  <Terminal className="h-4 w-4" />
                  CLI Command
                </h3>
                <pre className="bg-background border border-border/50 rounded-lg p-4 overflow-x-auto">
                  <code className="text-sm font-mono text-primary">{currentControl.cliCheck}</code>
                </pre>
              </section>
            )}

            {/* Expected Configuration */}
            <section className="bg-severity-low/10 border border-severity-low/20 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-2 mb-2">
                <CheckCircle2 className="h-4 w-4 text-severity-low" />
                Expected Secure Configuration
              </h3>
              <p className="text-sm text-muted-foreground">{currentControl.expectedConfig}</p>
            </section>

            {/* Common Misconfigurations */}
            <section>
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-2 mb-3">
                <XCircle className="h-4 w-4 text-severity-high" />
                Common Misconfigurations
              </h3>
              <ul className="space-y-2">
                {currentControl.commonMisconfigs.map((misconfig, index) => (
                  <li key={index} className="flex items-start gap-2 text-sm text-muted-foreground">
                    <span className="text-severity-high mt-0.5">•</span>
                    {misconfig}
                  </li>
                ))}
              </ul>
            </section>

            {/* Fix Hint */}
            <section className="bg-severity-medium/10 border border-severity-medium/20 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-foreground flex items-center gap-2 mb-2">
                <Lightbulb className="h-4 w-4 text-severity-medium" />
                Hardening Hint
              </h3>
              <p className="text-sm text-muted-foreground">{currentControl.fixHint}</p>
            </section>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex items-center justify-between mt-6">
          <Button
            variant="outline"
            onClick={handlePrevious}
            disabled={currentIndex === 0}
            className="gap-2"
          >
            <ChevronLeft className="h-4 w-4" />
            Previous
          </Button>

          <Link to="/">
            <Button variant="ghost" size="sm" className="gap-2">
              <Home className="h-4 w-4" />
              Exit to Controls
            </Button>
          </Link>

          <Button
            onClick={handleNext}
            disabled={currentIndex === totalControls - 1}
            className="gap-2"
          >
            Next
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </AppLayout>
  );
};

export default GuidedAudit;
