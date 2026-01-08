import { useState, useMemo } from 'react';
import { Search, HelpCircle, AlertTriangle, Zap, Users, ChevronDown, ChevronUp } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { useLanguage } from '@/i18n/LanguageContext';
import { faqContent, FAQItem } from '@/data/faqContent';

type CategoryFilter = 'all' | 'common' | 'misconfig' | 'quirks' | 'interview';

const categoryIcons = {
  all: HelpCircle,
  common: HelpCircle,
  misconfig: AlertTriangle,
  quirks: Zap,
  interview: Users
};

const providerColors: Record<string, string> = {
  AWS: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
  Azure: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
  GCP: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20',
  All: 'bg-muted text-muted-foreground border-border'
};

export default function FAQ() {
  const { t } = useLanguage();
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [expandedItems, setExpandedItems] = useState<string[]>([]);

  const filteredFAQs = useMemo(() => {
    return faqContent.filter((faq) => {
      const matchesCategory = categoryFilter === 'all' || faq.category === categoryFilter;
      const searchLower = searchQuery.toLowerCase();
      const matchesSearch =
        searchQuery === '' ||
        faq.question.toLowerCase().includes(searchLower) ||
        faq.answer.toLowerCase().includes(searchLower) ||
        faq.tags.some((tag) => tag.toLowerCase().includes(searchLower));
      return matchesCategory && matchesSearch;
    });
  }, [searchQuery, categoryFilter]);

  const handleExpandAll = () => {
    setExpandedItems(filteredFAQs.map((faq) => faq.id));
  };

  const handleCollapseAll = () => {
    setExpandedItems([]);
  };

  const categories: { id: CategoryFilter; label: string }[] = [
    { id: 'all', label: t.faq.categories.all },
    { id: 'common', label: t.faq.categories.common },
    { id: 'misconfig', label: t.faq.categories.misconfig },
    { id: 'quirks', label: t.faq.categories.quirks },
    { id: 'interview', label: t.faq.categories.interview }
  ];

  return (
    <AppLayout>
      <div className="container mx-auto px-4 py-8 max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-3xl md:text-4xl font-bold text-foreground mb-3">
            {t.faq.title}
          </h1>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            {t.faq.subtitle}
          </p>
        </div>

        {/* Search */}
        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder={t.faq.searchPlaceholder}
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10"
          />
          {searchQuery && (
            <Button
              variant="ghost"
              size="sm"
              className="absolute right-2 top-1/2 -translate-y-1/2 h-6 px-2"
              onClick={() => setSearchQuery('')}
            >
              {t.common.clear}
            </Button>
          )}
        </div>

        {/* Category Tabs */}
        <div className="flex flex-wrap gap-2 mb-6">
          {categories.map((category) => {
            const Icon = categoryIcons[category.id];
            return (
              <Button
                key={category.id}
                variant={categoryFilter === category.id ? 'default' : 'outline'}
                size="sm"
                onClick={() => setCategoryFilter(category.id)}
                className="gap-2"
              >
                <Icon className="h-4 w-4" />
                {category.label}
              </Button>
            );
          })}
        </div>

        {/* Expand/Collapse Controls */}
        <div className="flex justify-between items-center mb-4">
          <span className="text-sm text-muted-foreground">
            {filteredFAQs.length} {t.faq.questionsFound}
          </span>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm" onClick={handleExpandAll} className="gap-1">
              <ChevronDown className="h-4 w-4" />
              {t.faq.expandAll}
            </Button>
            <Button variant="ghost" size="sm" onClick={handleCollapseAll} className="gap-1">
              <ChevronUp className="h-4 w-4" />
              {t.faq.collapseAll}
            </Button>
          </div>
        </div>

        {/* FAQ Accordion */}
        {filteredFAQs.length > 0 ? (
          <Accordion
            type="multiple"
            value={expandedItems}
            onValueChange={setExpandedItems}
            className="space-y-3"
          >
            {filteredFAQs.map((faq) => (
              <FAQAccordionItem key={faq.id} faq={faq} searchQuery={searchQuery} />
            ))}
          </Accordion>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <HelpCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>{t.faq.noResults}</p>
          </div>
        )}
      </div>
    </AppLayout>
  );
}

interface FAQAccordionItemProps {
  faq: FAQItem;
  searchQuery: string;
}

function FAQAccordionItem({ faq, searchQuery }: FAQAccordionItemProps) {
  const { t } = useLanguage();
  const CategoryIcon = categoryIcons[faq.category];

  const highlightText = (text: string, query: string) => {
    if (!query) return text;
    const parts = text.split(new RegExp(`(${query})`, 'gi'));
    return parts.map((part, i) =>
      part.toLowerCase() === query.toLowerCase() ? (
        <mark key={i} className="bg-primary/20 text-foreground rounded px-0.5">
          {part}
        </mark>
      ) : (
        part
      )
    );
  };

  return (
    <AccordionItem
      value={faq.id}
      className="border rounded-lg px-4 bg-card transition-all duration-300 
                 hover:bg-accent/30
                 data-[state=open]:bg-card data-[state=open]:border-primary/40 
                 data-[state=open]:shadow-lg data-[state=open]:shadow-primary/10
                 data-[state=open]:hover:bg-card"
    >
      <AccordionTrigger className="text-left hover:no-underline py-4 group/trigger">
        <div className="flex items-start gap-3 flex-1">
          <CategoryIcon className="h-5 w-5 text-primary mt-0.5 shrink-0 transition-transform duration-300 
                                   group-data-[state=open]/trigger:rotate-12" />
          <div className="flex-1">
            <span className="font-medium text-foreground">
              {highlightText(faq.question, searchQuery)}
            </span>
            <div className="flex flex-wrap gap-2 mt-2">
              {faq.cloudProvider && (
                <Badge variant="outline" className={providerColors[faq.cloudProvider]}>
                  {faq.cloudProvider}
                </Badge>
              )}
              {faq.tags.slice(0, 3).map((tag) => (
                <Badge key={tag} variant="secondary" className="text-xs">
                  {tag}
                </Badge>
              ))}
            </div>
          </div>
        </div>
      </AccordionTrigger>
      <AccordionContent className="pb-4 animate-accordion-spring">
        <div className="pl-8 prose prose-sm dark:prose-invert max-w-none">
          <div className="whitespace-pre-wrap text-muted-foreground leading-relaxed">
            {faq.answer.split('\n').map((line, i) => {
              if (line.startsWith('**') && line.endsWith('**')) {
                return (
                  <p key={i} className="font-semibold text-foreground mt-4 mb-2">
                    {line.replace(/\*\*/g, '')}
                  </p>
                );
              }
              if (line.startsWith('- ')) {
                return (
                  <li key={i} className="ml-4">
                    {highlightText(line.substring(2), searchQuery)}
                  </li>
                );
              }
              if (line.match(/^\d+\. /)) {
                return (
                  <li key={i} className="ml-4 list-decimal">
                    {highlightText(line.replace(/^\d+\. /, ''), searchQuery)}
                  </li>
                );
              }
              if (line.startsWith('```')) {
                return null;
              }
              if (line.trim() === '') {
                return <br key={i} />;
              }
              return (
                <p key={i} className="my-1">
                  {highlightText(line, searchQuery)}
                </p>
              );
            })}
          </div>
          {faq.relatedControlIds && faq.relatedControlIds.length > 0 && (
            <div className="mt-4 pt-4 border-t">
              <span className="text-sm font-medium text-foreground">
                {t.faq.relatedControls}:
              </span>
              <div className="flex flex-wrap gap-2 mt-2">
                {faq.relatedControlIds.map((controlId) => (
                  <Badge key={controlId} variant="outline" className="cursor-pointer hover:bg-accent">
                    {controlId}
                  </Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      </AccordionContent>
    </AccordionItem>
  );
}
