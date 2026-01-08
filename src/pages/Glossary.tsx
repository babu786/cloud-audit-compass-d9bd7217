import { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { AppLayout } from '@/components/layout/AppLayout';
import { useLanguage } from '@/i18n/LanguageContext';
import { glossaryTerms, GlossaryCategory, GlossaryTerm } from '@/data/glossaryContent';
import { GlossaryTermCard } from '@/components/glossary/GlossaryTermCard';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
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
  Hash,
  Heart,
  X,
  Command
} from 'lucide-react';
import { cn } from '@/lib/utils';

const categoryIcons: Record<GlossaryCategory | 'all' | 'bookmarked', React.ElementType> = {
  all: Hash,
  bookmarked: Heart,
  identity: Key,
  network: Network,
  storage: Database,
  compute: Server,
  compliance: FileCheck,
  general: Shield,
};

const categoryBgColors: Record<GlossaryCategory, string> = {
  identity: 'bg-category-identity/10 hover:bg-category-identity/20 border-category-identity/30',
  network: 'bg-category-network/10 hover:bg-category-network/20 border-category-network/30',
  storage: 'bg-category-storage/10 hover:bg-category-storage/20 border-category-storage/30',
  compute: 'bg-category-compute/10 hover:bg-category-compute/20 border-category-compute/30',
  compliance: 'bg-category-compliance/10 hover:bg-category-compliance/20 border-category-compliance/30',
  general: 'bg-category-general/10 hover:bg-category-general/20 border-category-general/30',
};

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');
const BOOKMARKS_KEY = 'glossary-bookmarks';

export default function Glossary() {
  const { t } = useLanguage();
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<GlossaryCategory | 'all' | 'bookmarked'>('all');
  const [bookmarks, setBookmarks] = useState<string[]>(() => {
    const saved = localStorage.getItem(BOOKMARKS_KEY);
    return saved ? JSON.parse(saved) : [];
  });
  const sectionRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Keyboard shortcut for search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement).tagName)) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
      if (e.key === 'Escape') {
        searchInputRef.current?.blur();
        setSearchQuery('');
      }
    };
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Save bookmarks to localStorage
  useEffect(() => {
    localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(bookmarks));
  }, [bookmarks]);

  const toggleBookmark = useCallback((termId: string) => {
    setBookmarks(prev => 
      prev.includes(termId) 
        ? prev.filter(id => id !== termId)
        : [...prev, termId]
    );
  }, []);

  // Category counts
  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { all: glossaryTerms.length, bookmarked: bookmarks.length };
    glossaryTerms.forEach(term => {
      counts[term.category] = (counts[term.category] || 0) + 1;
    });
    return counts;
  }, [bookmarks.length]);

  const filteredTerms = useMemo(() => {
    return glossaryTerms.filter(term => {
      // Bookmark filter
      if (selectedCategory === 'bookmarked') {
        if (!bookmarks.includes(term.id)) return false;
      }
      // Category filter
      else if (selectedCategory !== 'all' && term.category !== selectedCategory) {
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
  }, [searchQuery, selectedCategory, bookmarks]);

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

  const categories: { id: GlossaryCategory | 'all' | 'bookmarked'; label: string }[] = [
    { id: 'all', label: t.glossary.categories.all },
    { id: 'bookmarked', label: t.glossary.bookmarkedTerms },
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
        {/* Hero Header */}
        <div className="relative text-center space-y-6">
          {/* Glow effect */}
          <div className="absolute inset-0 -z-10 overflow-hidden">
            <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-primary/5 rounded-full blur-3xl" />
          </div>

          <div className="inline-flex items-center gap-3 px-4 py-2 rounded-full glass border border-primary/20">
            <BookText className="h-5 w-5 text-primary" />
            <span className="text-sm font-medium">{glossaryTerms.length} {t.glossary.termsFound}</span>
          </div>
          
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight gradient-text">
            {t.glossary.title}
          </h1>
          
          <p className="text-muted-foreground max-w-2xl mx-auto">
            {t.glossary.subtitle}
          </p>

          {/* Stats Bar */}
          <div className="flex flex-wrap justify-center gap-2 pt-2">
            {(['identity', 'network', 'storage', 'compute', 'compliance', 'general'] as GlossaryCategory[]).map(cat => {
              const Icon = categoryIcons[cat];
              return (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={cn(
                    'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border transition-all',
                    categoryBgColors[cat],
                    selectedCategory === cat && 'ring-2 ring-primary/50'
                  )}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span>{categoryCounts[cat]}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Enhanced Search */}
        <div className="max-w-2xl mx-auto">
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-muted-foreground" />
            <Input
              ref={searchInputRef}
              placeholder={t.glossary.searchPlaceholder}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-12 pr-24 h-12 text-base glass border-border/50 focus:border-primary/50"
            />
            {searchQuery ? (
              <Button
                variant="ghost"
                size="sm"
                className="absolute right-2 top-1/2 -translate-y-1/2"
                onClick={() => setSearchQuery('')}
              >
                <X className="h-4 w-4" />
              </Button>
            ) : (
              <div className="absolute right-4 top-1/2 -translate-y-1/2 flex items-center gap-1 text-xs text-muted-foreground">
                <kbd className="px-1.5 py-0.5 rounded bg-muted font-mono">/</kbd>
                <span>{t.glossary.pressToSearch}</span>
              </div>
            )}
          </div>
        </div>

        {/* Category Tabs */}
        <div className="flex flex-wrap justify-center gap-2">
          {categories.map(({ id, label }) => {
            const Icon = categoryIcons[id];
            const isBookmarked = id === 'bookmarked';
            return (
              <Button
                key={id}
                variant={selectedCategory === id ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedCategory(id)}
                className={cn(
                  'gap-2 transition-all',
                  selectedCategory === id && 'glow-sm',
                  isBookmarked && bookmarks.length > 0 && selectedCategory !== id && 'border-red-500/30'
                )}
              >
                <Icon className={cn('h-4 w-4', isBookmarked && bookmarks.length > 0 && 'text-red-500')} />
                {label}
                {(categoryCounts[id] !== undefined && categoryCounts[id] > 0) && (
                  <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-xs">
                    {categoryCounts[id]}
                  </Badge>
                )}
              </Button>
            );
          })}
        </div>

        {/* Sticky Alphabetical Navigation */}
        <div className="sticky top-16 z-20 py-3 -mx-4 px-4 backdrop-blur-xl bg-background/80 border-b border-border/50">
          <div className="flex flex-wrap justify-center gap-1 text-sm">
            <span className="text-muted-foreground mr-2 hidden sm:inline">{t.glossary.jumpToLetter}:</span>
            {ALPHABET.map(letter => (
              <button
                key={letter}
                onClick={() => scrollToLetter(letter)}
                disabled={!availableLetters.has(letter)}
                className={cn(
                  'w-7 h-7 rounded font-medium transition-all',
                  availableLetters.has(letter)
                    ? 'hover:bg-primary/10 hover:text-primary cursor-pointer hover:glow-sm'
                    : 'text-muted-foreground/30 cursor-not-allowed'
                )}
              >
                {letter}
              </button>
            ))}
          </div>
        </div>

        {/* Results Count */}
        <div className="text-center text-sm text-muted-foreground">
          {filteredTerms.length} {t.glossary.termsFound}
        </div>

        {/* Terms List */}
        {filteredTerms.length === 0 ? (
          <div className="text-center py-12 glass rounded-lg">
            <p className="text-muted-foreground">
              {selectedCategory === 'bookmarked' ? t.glossary.noBookmarks : t.glossary.noResults}
            </p>
          </div>
        ) : (
          <div className="space-y-10">
            {ALPHABET.map(letter => {
              const terms = groupedTerms[letter];
              if (!terms || terms.length === 0) return null;

              return (
                <div 
                  key={letter} 
                  ref={(el) => { sectionRefs.current[letter] = el; }}
                  className="scroll-mt-32"
                >
                  <div className="flex items-center gap-4 mb-6">
                    <span className="text-4xl font-bold gradient-text">{letter}</span>
                    <div className="flex-1 h-px bg-gradient-to-r from-border to-transparent" />
                    <Badge variant="outline" className="text-xs">
                      {terms.length}
                    </Badge>
                  </div>
                  
                  <div className="grid gap-4 md:grid-cols-2">
                    {terms.map((term, index) => (
                      <GlossaryTermCard 
                        key={term.id} 
                        term={term} 
                        searchQuery={searchQuery}
                        highlightMatch={highlightMatch}
                        isBookmarked={bookmarks.includes(term.id)}
                        onToggleBookmark={toggleBookmark}
                        animationDelay={Math.min(index * 50, 300)}
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
