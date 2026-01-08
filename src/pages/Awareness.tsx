import { useState } from 'react';
import { Newspaper, AlertTriangle, BookOpen, Lightbulb } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { AwarenessCard } from '@/components/awareness/AwarenessCard';
import { AwarenessModal } from '@/components/awareness/AwarenessModal';
import { awarenessArticles, AwarenessArticle } from '@/data/auditContent';
import { cn } from '@/lib/utils';

const categories = [
  { id: 'all', name: 'All Articles', icon: BookOpen },
  { id: 'Weekly Awareness', name: 'Weekly Awareness', icon: Newspaper },
  { id: 'Misconfigurations', name: 'Misconfigurations', icon: AlertTriangle },
  { id: 'Best Practices', name: 'Best Practices', icon: BookOpen },
  { id: 'Audit Tips', name: 'Audit Tips', icon: Lightbulb },
] as const;

const Awareness = () => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedArticle, setSelectedArticle] = useState<AwarenessArticle | null>(null);

  const filteredArticles = selectedCategory === 'all' 
    ? awarenessArticles 
    : awarenessArticles.filter(a => a.category === selectedCategory);

  return (
    <AppLayout>
      <div className="container py-8">
        {/* Hero Section */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold gradient-text mb-2">
            Security Awareness & Knowledge
          </h1>
          <p className="text-muted-foreground max-w-2xl">
            Stay updated with the latest cloud security insights, common misconfigurations, 
            and best practices for effective auditing.
          </p>
        </div>

        {/* Category Tabs */}
        <div className="flex flex-wrap gap-2 mb-8">
          {categories.map((category) => {
            const isSelected = selectedCategory === category.id;
            const Icon = category.icon;
            return (
              <button
                key={category.id}
                onClick={() => setSelectedCategory(category.id)}
                className={cn(
                  "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200",
                  isSelected
                    ? "bg-primary/10 text-primary border border-primary/30"
                    : "bg-card/50 text-muted-foreground border border-border/30 hover:border-primary/20 hover:text-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                {category.name}
              </button>
            );
          })}
        </div>

        {/* Articles Grid */}
        <div className="grid gap-4 md:grid-cols-2">
          {filteredArticles.map((article) => (
            <AwarenessCard 
              key={article.id} 
              article={article}
              onClick={() => setSelectedArticle(article)}
            />
          ))}
        </div>

        {filteredArticles.length === 0 && (
          <div className="text-center py-12">
            <p className="text-muted-foreground">No articles in this category yet.</p>
          </div>
        )}

        {/* Article Modal */}
        <AwarenessModal 
          article={selectedArticle}
          open={!!selectedArticle}
          onClose={() => setSelectedArticle(null)}
        />
      </div>
    </AppLayout>
  );
};

export default Awareness;
