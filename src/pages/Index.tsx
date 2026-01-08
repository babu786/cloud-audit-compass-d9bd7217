import { useState, useMemo, useEffect, useTransition } from 'react';
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
import { TypingEffect } from '@/components/hero/TypingEffect';
import { CardSkeleton } from '@/components/ui/CardSkeleton';
import { Button } from '@/components/ui/button';
import { auditControls } from '@/data/auditContent';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/i18n/LanguageContext';

const heroTexts = [
  "Cloud Security Audit Portal",
  "AWS • Azure • GCP Controls",
  "ISO 27001 • CIS Benchmarks",
  "Secure Your Cloud Infrastructure",
];

const Index = () => {
  const { t } = useLanguage();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedProviders, setSelectedProviders] = useState<string[]>([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([]);
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([]);
  const [showFilters, setShowFilters] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [isPending, startTransition] = useTransition();

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
    setIsLoading(true);
    startTransition(() => {
      setSelectedProviders([]);
      setSelectedFrameworks([]);
      setSelectedCategories([]);
      setSelectedSeverities([]);
      setSearchQuery('');
    });
    setTimeout(() => setIsLoading(false), 300);
  };

  // Show skeleton when filters change
  const handleProviderSelect = (providers: string[]) => {
    setIsLoading(true);
    startTransition(() => setSelectedProviders(providers));
    setTimeout(() => setIsLoading(false), 300);
  };

  const handleFrameworkSelect = (frameworks: string[]) => {
    setIsLoading(true);
    startTransition(() => setSelectedFrameworks(frameworks));
    setTimeout(() => setIsLoading(false), 300);
  };

  const handleCategorySelect = (categories: string[]) => {
    setIsLoading(true);
    startTransition(() => setSelectedCategories(categories));
    setTimeout(() => setIsLoading(false), 300);
  };

  const handleSeveritySelect = (severities: string[]) => {
    setIsLoading(true);
    startTransition(() => setSelectedSeverities(severities));
    setTimeout(() => setIsLoading(false), 300);
  };

  const handleSearchChange = (query: string) => {
    setIsLoading(true);
    startTransition(() => setSearchQuery(query));
    setTimeout(() => setIsLoading(false), 300);
  };

  const showSkeleton = isLoading || isPending;

  return (
    <AppLayout>
      <div className="container px-4 sm:px-6 lg:px-8 py-6 sm:py-8 relative">
        {/* Animated Background */}
        <AnimatedBackground />
        
        {/* Hero Section */}
        <div className="mb-8 relative z-10">
          <h1 className="text-3xl md:text-4xl font-bold gradient-text mb-3 min-h-[2.5rem] md:min-h-[3rem]">
            <TypingEffect texts={heroTexts} typingSpeed={80} deletingSpeed={40} pauseDuration={2500} />
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
            <div className="space-y-4 sm:space-y-6 p-4 sm:p-6 rounded-xl backdrop-blur-xl bg-card/40 border border-white/10 dark:border-white/5 shadow-[0_8px_32px_rgba(0,0,0,0.08)] dark:shadow-[0_8px_32px_rgba(0,0,0,0.3)] hover:shadow-[0_12px_40px_rgba(0,200,200,0.08)] transition-all duration-500 relative overflow-hidden group animate-fade-in">
              {/* Glass highlight */}
              <div className="absolute inset-0 bg-gradient-to-br from-white/5 via-transparent to-transparent pointer-events-none" />
              <div className="absolute inset-0 bg-gradient-to-t from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none" />
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <CloudProviderSelector 
                  selected={selectedProviders} 
                  onSelect={handleProviderSelect} 
                />
                <FrameworkSelector 
                  selected={selectedFrameworks} 
                  onSelect={handleFrameworkSelect} 
                />
              </div>
              
              <CategorySelector 
                selected={selectedCategories} 
                onSelect={handleCategorySelect} 
              />

              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1">
                  <SearchFilter 
                    value={searchQuery} 
                    onChange={handleSearchChange}
                    placeholder={t.index.searchPlaceholder}
                  />
                </div>
              <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs text-muted-foreground whitespace-nowrap">{t.index.severity}:</span>
                  <SeverityFilter 
                    selected={selectedSeverities} 
                    onSelect={handleSeveritySelect} 
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
          {showSkeleton ? (
            // Skeleton loading state
            <>
              {Array.from({ length: 5 }).map((_, i) => (
                <CardSkeleton key={i} variant="control" />
              ))}
            </>
          ) : filteredControls.length === 0 ? (
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
            filteredControls.map((control, index) => (
              <div 
                key={control.id}
                className="animate-fade-in"
                style={{ animationDelay: `${Math.min(index * 50, 500)}ms` }}
              >
                <AuditControlCard control={control} />
              </div>
            ))
          )}
        </div>
      </div>
    </AppLayout>
  );
};

export default Index;
