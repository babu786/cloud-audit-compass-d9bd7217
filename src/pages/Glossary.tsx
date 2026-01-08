import { useState, useMemo, useRef, useEffect } from 'react';
import { AppLayout } from '@/components/layout/AppLayout';
import { useLanguage } from '@/i18n/LanguageContext';
import { glossaryTerms, GlossaryCategory, GlossaryTerm } from '@/data/glossaryContent';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { 
  Search, 
  BookText, 
  Key, 
  Network, 
  Database, 
  Server, 
  FileCheck, 
  Shield,
  ExternalLink,
  Hash
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '@/lib/utils';

const categoryIcons: Record<GlossaryCategory, React.ElementType> = {
  identity: Key,
  network: Network,
  storage: Database,
  compute: Server,
  compliance: FileCheck,
  general: Shield,
};

const providerColors: Record<string, string> = {
  AWS: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
  Azure: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
  GCP: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20',
};

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');

export default function Glossary() {
  const { t } = useLanguage();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<GlossaryCategory | 'all'>('all');
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});

  const filteredTerms = useMemo(() => {
    return glossaryTerms.filter(term => {
      // Category filter
      if (selectedCategory !== 'all' && term.category !== selectedCategory) {
        return false;
      }

      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const searchableText = [
          term.term,
          term.acronym,
          term.definition,
          ...(term.aliases || []),
        ].filter(Boolean).join(' ').toLowerCase();
        
        return searchableText.includes(query);
      }

      return true;
    }).sort((a, b) => a.term.localeCompare(b.term));
  }, [searchQuery, selectedCategory]);

  const groupedTerms = useMemo(() => {
    const groups: Record<string, GlossaryTerm[]> = {};
    filteredTerms.forEach(term => {
      const letter = term.term[0].toUpperCase();
      if (!groups[letter]) {
        groups[letter] = [];
      }
      groups[letter].push(term);
    });
    return groups;
  }, [filteredTerms]);

  const availableLetters = useMemo(() => {
    return new Set(Object.keys(groupedTerms));
  }, [groupedTerms]);

  const scrollToLetter = (letter: string) => {
    const element = sectionRefs.current[letter];
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  const highlightMatch = (text: string, query: string) => {
    if (!query) return text;
    const regex = new RegExp(`(${query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    const parts = text.split(regex);
    return parts.map((part, i) => 
      regex.test(part) ? <mark key={i} className="bg-primary/20 text-foreground rounded px-0.5">{part}</mark> : part
    );
  };

  const categories: { id: GlossaryCategory | 'all'; label: string }[] = [
    { id: 'all', label: t.glossary.categories.all },
    { id: 'identity', label: t.glossary.categories.identity },
    { id: 'network', label: t.glossary.categories.network },
    { id: 'storage', label: t.glossary.categories.storage },
    { id: 'compute', label: t.glossary.categories.compute },
    { id: 'compliance', label: t.glossary.categories.compliance },
    { id: 'general', label: t.glossary.categories.general },
  ];

  return (
    <AppLayout>
      <div className="container py-8 space-y-8">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-primary/10 text-primary">
            <BookText className="h-5 w-5" />
            <span className="text-sm font-medium">{t.glossary.title}</span>
          </div>
          <h1 className="text-4xl font-bold tracking-tight">{t.glossary.title}</h1>
          <p className="text-muted-foreground max-w-2xl mx-auto">
            {t.glossary.subtitle}
          </p>
        </div>

        {/* Search */}
        <div className="max-w-xl mx-auto">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t.glossary.searchPlaceholder}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {/* Category Tabs */}
        <div className="flex flex-wrap justify-center gap-2">
          {categories.map(({ id, label }) => {
            const Icon = id !== 'all' ? categoryIcons[id] : Hash;
            return (
              <Button
                key={id}
                variant={selectedCategory === id ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedCategory(id)}
                className="gap-2"
              >
                <Icon className="h-4 w-4" />
                {label}
              </Button>
            );
          })}
        </div>

        {/* Alphabetical Navigation */}
        <div className="flex flex-wrap justify-center gap-1 text-sm">
          <span className="text-muted-foreground mr-2">{t.glossary.jumpToLetter}:</span>
          {ALPHABET.map(letter => (
            <button
              key={letter}
              onClick={() => scrollToLetter(letter)}
              disabled={!availableLetters.has(letter)}
              className={cn(
                'w-7 h-7 rounded font-medium transition-colors',
                availableLetters.has(letter)
                  ? 'hover:bg-primary/10 hover:text-primary cursor-pointer'
                  : 'text-muted-foreground/30 cursor-not-allowed'
              )}
            >
              {letter}
            </button>
          ))}
        </div>

        {/* Results Count */}
        <div className="text-center text-sm text-muted-foreground">
          {filteredTerms.length} {t.glossary.termsFound}
        </div>

        {/* Terms List */}
        {filteredTerms.length === 0 ? (
          <div className="text-center py-12">
            <p className="text-muted-foreground">{t.glossary.noResults}</p>
          </div>
        ) : (
          <div className="space-y-8">
            {ALPHABET.map(letter => {
              const terms = groupedTerms[letter];
              if (!terms || terms.length === 0) return null;

              return (
                <div 
                  key={letter} 
                  ref={(el) => { sectionRefs.current[letter] = el; }}
                  className="scroll-mt-24"
                >
                  <div className="flex items-center gap-4 mb-4">
                    <span className="text-3xl font-bold text-primary">{letter}</span>
                    <div className="flex-1 h-px bg-border" />
                  </div>
                  
                  <div className="grid gap-4 md:grid-cols-2">
                    {terms.map(term => (
                      <TermCard 
                        key={term.id} 
                        term={term} 
                        searchQuery={searchQuery}
                        highlightMatch={highlightMatch}
                        t={t}
                      />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppLayout>
  );
}

interface TermCardProps {
  term: GlossaryTerm;
  searchQuery: string;
  highlightMatch: (text: string, query: string) => React.ReactNode;
  t: any;
}

function TermCard({ term, searchQuery, highlightMatch, t }: TermCardProps) {
  const CategoryIcon = categoryIcons[term.category];

  const relatedTerms = term.relatedTermIds?.map(id => 
    glossaryTerms.find(t => t.id === id)
  ).filter(Boolean) as GlossaryTerm[] | undefined;

  return (
    <Card className="group hover:shadow-md transition-shadow">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="space-y-1">
            <CardTitle className="text-lg leading-tight">
              {highlightMatch(term.term, searchQuery)}
              {term.acronym && (
                <Badge variant="secondary" className="ml-2 font-mono">
                  {term.acronym}
                </Badge>
              )}
            </CardTitle>
            {term.aliases && term.aliases.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {t.glossary.alsoKnownAs}: {term.aliases.join(', ')}
              </p>
            )}
          </div>
          <Badge variant="outline" className="shrink-0 gap-1">
            <CategoryIcon className="h-3 w-3" />
            {t.glossary.categories[term.category]}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground leading-relaxed">
          {highlightMatch(term.definition, searchQuery)}
        </p>

        {/* Cloud Providers */}
        {term.cloudProviders && term.cloudProviders.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {term.cloudProviders.map(provider => (
              <Badge 
                key={provider} 
                variant="outline" 
                className={cn('text-xs', providerColors[provider])}
              >
                {provider}
              </Badge>
            ))}
          </div>
        )}

        {/* Related Terms */}
        {relatedTerms && relatedTerms.length > 0 && (
          <div className="pt-2 border-t border-border/50">
            <p className="text-xs font-medium text-muted-foreground mb-2">
              {t.glossary.relatedTerms}:
            </p>
            <div className="flex flex-wrap gap-1.5">
              {relatedTerms.slice(0, 4).map(related => (
                <Badge 
                  key={related.id}
                  variant="secondary"
                  className="text-xs cursor-pointer hover:bg-secondary/80"
                  onClick={() => {
                    const element = document.getElementById(`term-${related.id}`);
                    if (element) {
                      element.scrollIntoView({ behavior: 'smooth', block: 'center' });
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
          <div className="pt-2 border-t border-border/50">
            <p className="text-xs font-medium text-muted-foreground mb-2">
              {t.glossary.relatedControls}:
            </p>
            <div className="flex flex-wrap gap-1.5">
              {term.relatedControlIds.slice(0, 3).map(controlId => (
                <Link 
                  key={controlId}
                  to={`/?search=${encodeURIComponent(controlId)}`}
                  className="inline-flex items-center gap-1"
                >
                  <Badge 
                    variant="outline"
                    className="text-xs cursor-pointer hover:bg-primary/10 hover:text-primary gap-1"
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
          <div className="pt-2 border-t border-border/50">
            <p className="text-xs font-medium text-muted-foreground mb-2">
              {t.glossary.relatedFAQs}:
            </p>
            <div className="flex flex-wrap gap-1.5">
              {term.relatedFAQIds.slice(0, 2).map(faqId => (
                <Link 
                  key={faqId}
                  to={`/faq?expand=${encodeURIComponent(faqId)}`}
                  className="inline-flex items-center gap-1"
                >
                  <Badge 
                    variant="outline"
                    className="text-xs cursor-pointer hover:bg-primary/10 hover:text-primary gap-1"
                  >
                    FAQ
                    <ExternalLink className="h-2.5 w-2.5" />
                  </Badge>
                </Link>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
