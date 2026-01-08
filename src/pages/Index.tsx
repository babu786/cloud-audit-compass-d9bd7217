import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { Filter, Compass, ChevronDown, ChevronUp, RotateCcw } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { CloudProviderSelector } from '@/components/audit/CloudProviderSelector';
import { FrameworkSelector } from '@/components/audit/FrameworkSelector';
import { CategorySelector } from '@/components/audit/CategorySelector';
import { SearchFilter } from '@/components/audit/SearchFilter';
import { SeverityFilter } from '@/components/audit/SeverityFilter';
import { AuditControlCard } from '@/components/audit/AuditControlCard';
import { StatsBar } from '@/components/dashboard/StatsBar';
import { AnimatedBackground } from '@/components/hero/AnimatedBackground';
import { Button } from '@/components/ui/button';
import { auditControls } from '@/data/auditContent';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/i18n/LanguageContext';

const Index = () => {
  const { t } = useLanguage();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProviders, setSelectedProviders] = useState<string[]>([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [showFilters, setShowFilters] = useState(true);

  const filteredControls = useMemo(() => {
    return auditControls.filter(control => {
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch = 
          control.id.toLowerCase().includes(query) ||
          control.title.toLowerCase().includes(query) ||
          control.whatToCheck.toLowerCase().includes(query);
        if (!matchesSearch) return false;
      }

      // Provider filter
      if (selectedProviders.length > 0 && !selectedProviders.includes(control.cloudProvider)) {
        return false;
      }

      // Framework filter
      if (selectedFrameworks.length > 0 && !selectedFrameworks.includes(control.framework)) {
        return false;
      }

      // Category filter
      if (selectedCategories.length > 0 && !selectedCategories.includes(control.category)) {
        return false;
      }

      // Severity filter
      if (selectedSeverities.length > 0 && !selectedSeverities.includes(control.severity)) {
        return false;
      }

      return true;
    });
  }, [searchQuery, selectedProviders, selectedFrameworks, selectedCategories, selectedSeverities]);

  const hasActiveFilters = 
    selectedProviders.length > 0 || 
    selectedFrameworks.length > 0 || 
    selectedCategories.length > 0 || 
    selectedSeverities.length > 0;

  const resetFilters = () => {
    setSelectedProviders([]);
    setSelectedFrameworks([]);
    setSelectedCategories([]);
    setSelectedSeverities([]);
    setSearchQuery('');
  };

  return (
    <AppLayout>
      <div className="container py-8 relative">
        {/* Animated Background */}
        <AnimatedBackground />
        
        {/* Hero Section */}
        <div className="mb-8 relative z-10">
          <h1 className="text-3xl md:text-4xl font-bold gradient-text mb-3">
            {t.index.title}
          </h1>
          <p className="text-muted-foreground max-w-2xl mb-8">
            {t.index.subtitle}
          </p>
          
          {/* Stats Dashboard */}
          <StatsBar />
        </div>

        {/* Filters Section */}
        <div className="mb-6 space-y-4 relative z-10">
          <div className="flex items-center justify-between">
            <button
              onClick={() => setShowFilters(!showFilters)}
              className="flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
            >
              <Filter className="h-4 w-4" />
              {t.common.filters}
              {showFilters ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
            </button>
            
            <div className="flex items-center gap-3">
              {hasActiveFilters && (
                <button
                  onClick={resetFilters}
                  className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  <RotateCcw className="h-3 w-3" />
                  {t.common.resetFilters}
                </button>
              )}
              <Link to="/guided">
                <Button variant="outline" size="sm" className="gap-2">
                  <Compass className="h-4 w-4" />
                  {t.index.startGuidedAudit}
                </Button>
              </Link>
            </div>
          </div>

          {showFilters && (
            <div className="space-y-6 p-6 rounded-xl bg-card/30 border border-border/30 animate-fade-in">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <CloudProviderSelector 
                  selected={selectedProviders} 
                  onSelect={setSelectedProviders} 
                />
                <FrameworkSelector 
                  selected={selectedFrameworks} 
                  onSelect={setSelectedFrameworks} 
                />
              </div>
              
              <CategorySelector 
                selected={selectedCategories} 
                onSelect={setSelectedCategories} 
              />

              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1">
                  <SearchFilter 
                    value={searchQuery} 
                    onChange={setSearchQuery}
                    placeholder={t.index.searchPlaceholder}
                  />
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground">{t.index.severity}:</span>
                  <SeverityFilter 
                    selected={selectedSeverities} 
                    onSelect={setSelectedSeverities} 
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Results Header */}
        <div className="mb-4 flex items-center justify-between">
          <p className="text-sm text-muted-foreground">
            {t.common.showing} <span className="font-medium text-foreground">{filteredControls.length}</span> {t.common.of} {auditControls.length} {t.common.controls}
          </p>
        </div>

        {/* Controls List */}
        <div className="space-y-3">
          {filteredControls.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-muted-foreground">{t.index.noControlsMatch}</p>
              <button
                onClick={resetFilters}
                className="mt-2 text-sm text-primary hover:underline"
              >
                {t.index.clearAllFilters}
              </button>
            </div>
          ) : (
            filteredControls.map((control) => (
              <AuditControlCard key={control.id} control={control} />
            ))
          )}
        </div>
      </div>
    </AppLayout>
  );
};

export default Index;
