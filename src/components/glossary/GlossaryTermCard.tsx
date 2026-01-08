import { useState } from 'react';
import { GlossaryTerm, GlossaryCategory, glossaryTerms } from '@/data/glossaryContent';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { 
  Key, 
  Network, 
  Database, 
  Server, 
  FileCheck, 
  Shield,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Heart
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';

const categoryIcons: Record<GlossaryCategory, React.ElementType> = {
  identity: Key,
  network: Network,
  storage: Database,
  compute: Server,
  compliance: FileCheck,
  general: Shield,
};

const categoryColors: Record<GlossaryCategory, string> = {
  identity: 'border-l-category-identity',
  network: 'border-l-category-network',
  storage: 'border-l-category-storage',
  compute: 'border-l-category-compute',
  compliance: 'border-l-category-compliance',
  general: 'border-l-category-general',
};

const categoryGlowColors: Record<GlossaryCategory, string> = {
  identity: 'shadow-[0_0_12px_hsl(var(--category-identity)/0.4)]',
  network: 'shadow-[0_0_12px_hsl(var(--category-network)/0.4)]',
  storage: 'shadow-[0_0_12px_hsl(var(--category-storage)/0.4)]',
  compute: 'shadow-[0_0_12px_hsl(var(--category-compute)/0.4)]',
  compliance: 'shadow-[0_0_12px_hsl(var(--category-compliance)/0.4)]',
  general: 'shadow-[0_0_12px_hsl(var(--category-general)/0.4)]',
};

const providerIcons: Record<string, { color: string; bg: string }> = {
  AWS: { color: 'text-orange-500', bg: 'bg-orange-500/10' },
  Azure: { color: 'text-blue-500', bg: 'bg-blue-500/10' },
  GCP: { color: 'text-red-500', bg: 'bg-red-500/10' },
};

interface GlossaryTermCardProps {
  term: GlossaryTerm;
  searchQuery: string;
  highlightMatch: (text: string, query: string) => React.ReactNode;
  isBookmarked: boolean;
  onToggleBookmark: (termId: string) => void;
  animationDelay?: number;
  t: any;
}

export function GlossaryTermCard({ 
  term, 
  searchQuery, 
  highlightMatch, 
  isBookmarked,
  onToggleBookmark,
  animationDelay = 0,
  t 
}: GlossaryTermCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();
  
  const CategoryIcon = categoryIcons[term.category];

  const relatedTerms = term.relatedTermIds?.map(id => 
    glossaryTerms.find(t => t.id === id)
  ).filter(Boolean) as GlossaryTerm[] | undefined;

  const hasRelated = (relatedTerms && relatedTerms.length > 0) || 
                     (term.relatedControlIds && term.relatedControlIds.length > 0) ||
                     (term.relatedFAQIds && term.relatedFAQIds.length > 0);

  const relatedCount = (relatedTerms?.length || 0) + 
                       (term.relatedControlIds?.length || 0) + 
                       (term.relatedFAQIds?.length || 0);

  const handleCopy = async () => {
    const text = `${term.term}${term.acronym ? ` (${term.acronym})` : ''}: ${term.definition}`;
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast({ description: t.glossary.copied });
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      id={`term-${term.id}`}
      className={cn(
        'group relative rounded-lg border-l-4 glass glass-hover overflow-hidden',
        'opacity-0 animate-fade-in',
        'hover:-translate-y-0.5 hover:shadow-lg transition-all duration-300',
        categoryColors[term.category]
      )}
      style={{ animationDelay: `${animationDelay}ms`, animationFillMode: 'forwards' }}
    >
      {/* Main Content */}
      <div className="p-4 space-y-3">
        {/* Header Row */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {term.acronym && (
                <Badge 
                  variant="secondary" 
                  className={cn(
                    'font-mono font-semibold text-sm px-2.5 py-0.5',
                    categoryGlowColors[term.category]
                  )}
                >
                  {term.acronym}
                </Badge>
              )}
              <h3 className="text-base font-semibold leading-tight">
                {highlightMatch(term.term, searchQuery)}
              </h3>
            </div>
            {term.aliases && term.aliases.length > 0 && (
              <p className="text-xs text-muted-foreground mt-1">
                {t.glossary.alsoKnownAs}: {term.aliases.join(', ')}
              </p>
            )}
          </div>
          
          {/* Action buttons */}
          <div className="flex items-center gap-1 shrink-0">
            <Button
              variant="ghost"
              size="icon"
              className={cn(
                'h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity',
                copied && 'opacity-100'
              )}
              onClick={handleCopy}
              title={t.glossary.copyDefinition}
            >
              {copied ? (
                <Check className="h-4 w-4 text-green-500" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => onToggleBookmark(term.id)}
              title={isBookmarked ? t.glossary.removeBookmark : t.glossary.addBookmark}
            >
              <Heart 
                className={cn(
                  'h-4 w-4 transition-colors',
                  isBookmarked ? 'fill-red-500 text-red-500' : 'text-muted-foreground'
                )} 
              />
            </Button>
          </div>
        </div>

        {/* Definition */}
        <p className="text-sm text-muted-foreground leading-relaxed">
          {highlightMatch(term.definition, searchQuery)}
        </p>

        {/* Footer Row */}
        <div className="flex items-center justify-between gap-2 flex-wrap">
          {/* Cloud Providers */}
          <div className="flex items-center gap-1.5">
            {term.cloudProviders?.map(provider => (
              <div
                key={provider}
                className={cn(
                  'px-2 py-0.5 rounded text-xs font-medium',
                  providerIcons[provider]?.bg,
                  providerIcons[provider]?.color
                )}
              >
                {provider}
              </div>
            ))}
          </div>

          {/* Category Badge */}
          <Badge variant="outline" className="gap-1 shrink-0">
            <CategoryIcon className="h-3 w-3" />
            <span className="text-xs">{t.glossary.categories[term.category]}</span>
          </Badge>
        </div>

        {/* Expand/Collapse for Related */}
        {hasRelated && (
          <Button
            variant="ghost"
            size="sm"
            className="w-full mt-2 text-xs text-muted-foreground hover:text-foreground"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? (
              <>
                <ChevronUp className="h-3 w-3 mr-1" />
                {t.glossary.hideRelated}
              </>
            ) : (
              <>
                <ChevronDown className="h-3 w-3 mr-1" />
                {t.glossary.showRelated} ({relatedCount})
              </>
            )}
          </Button>
        )}
      </div>

      {/* Expanded Related Content */}
      {isExpanded && hasRelated && (
        <div className="px-4 pb-4 pt-2 border-t border-border/50 space-y-3 animate-fade-in">
          {/* Related Terms */}
          {relatedTerms && relatedTerms.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2">
                {t.glossary.relatedTerms}:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {relatedTerms.map(related => (
                  <Badge 
                    key={related.id}
                    variant="secondary"
                    className="text-xs cursor-pointer hover:bg-secondary/80 transition-colors"
                    onClick={() => {
                      const element = document.getElementById(`term-${related.id}`);
                      if (element) {
                        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        element.classList.add('ring-2', 'ring-primary');
                        setTimeout(() => element.classList.remove('ring-2', 'ring-primary'), 2000);
                      }
                    }}
                  >
                    {related.acronym || related.term}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Related Controls */}
          {term.relatedControlIds && term.relatedControlIds.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2">
                {t.glossary.relatedControls}:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {term.relatedControlIds.map(controlId => (
                  <Link 
                    key={controlId}
                    to={`/?search=${encodeURIComponent(controlId)}`}
                  >
                    <Badge 
                      variant="outline"
                      className="text-xs cursor-pointer hover:bg-primary/10 hover:text-primary gap-1 transition-colors"
                    >
                      {controlId}
                      <ExternalLink className="h-2.5 w-2.5" />
                    </Badge>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Related FAQs */}
          {term.relatedFAQIds && term.relatedFAQIds.length > 0 && (
            <div>
              <p className="text-xs font-medium text-muted-foreground mb-2">
                {t.glossary.relatedFAQs}:
              </p>
              <div className="flex flex-wrap gap-1.5">
                {term.relatedFAQIds.map(faqId => (
                  <Link 
                    key={faqId}
                    to={`/faq?expand=${encodeURIComponent(faqId)}`}
                  >
                    <Badge 
                      variant="outline"
                      className="text-xs cursor-pointer hover:bg-primary/10 hover:text-primary gap-1 transition-colors"
                    >
                      FAQ
                      <ExternalLink className="h-2.5 w-2.5" />
                    </Badge>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
