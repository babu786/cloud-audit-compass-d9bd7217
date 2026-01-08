import { useState, useEffect } from 'react';
import { Newspaper, AlertTriangle, BookOpen, Lightbulb, Plus, LogOut } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { AwarenessCard } from '@/components/awareness/AwarenessCard';
import { AwarenessModal } from '@/components/awareness/AwarenessModal';
import { AdminLoginModal } from '@/components/admin/AdminLoginModal';
import { AddAwarenessModal } from '@/components/admin/AddAwarenessModal';
import { awarenessArticles as defaultArticles, AwarenessArticle } from '@/data/auditContent';
import { Button } from '@/components/ui/button';
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
  const [isAdmin, setIsAdmin] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [articles, setArticles] = useState<AwarenessArticle[]>(defaultArticles);

  useEffect(() => {
    const adminStatus = sessionStorage.getItem('isAdmin') === 'true';
    setIsAdmin(adminStatus);
    
    // Load any saved articles from localStorage
    const savedArticles = localStorage.getItem('awarenessArticles');
    if (savedArticles) {
      setArticles(JSON.parse(savedArticles));
    }
  }, []);

  const handleAddArticle = (article: AwarenessArticle) => {
    const newArticles = [article, ...articles];
    setArticles(newArticles);
    localStorage.setItem('awarenessArticles', JSON.stringify(newArticles));
  };

  const handleLogout = () => {
    sessionStorage.removeItem('isAdmin');
    setIsAdmin(false);
  };

  const filteredArticles = selectedCategory === 'all' 
    ? articles 
    : articles.filter(a => a.category === selectedCategory);

  return (
    <AppLayout>
      <div className="container py-8">
        {/* Hero Section */}
        <div className="mb-8 flex items-start justify-between">
          <div>
            <h1 className="text-3xl font-bold gradient-text mb-2">
              Security Awareness & Knowledge
            </h1>
            <p className="text-muted-foreground max-w-2xl">
              Stay updated with the latest cloud security insights, common misconfigurations, 
              and best practices for effective auditing.
            </p>
          </div>
          <div className="flex gap-2">
            {isAdmin ? (
              <>
                <Button onClick={() => setShowAddModal(true)} size="sm">
                  <Plus className="h-4 w-4 mr-1" />
                  Add Article
                </Button>
                <Button variant="outline" size="sm" onClick={handleLogout}>
                  <LogOut className="h-4 w-4 mr-1" />
                  Logout
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={() => setShowLoginModal(true)}>
                Admin Login
              </Button>
            )}
          </div>
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

        {/* Admin Login Modal */}
        <AdminLoginModal
          open={showLoginModal}
          onClose={() => setShowLoginModal(false)}
          onSuccess={() => {
            setIsAdmin(true);
            setShowLoginModal(false);
          }}
        />

        {/* Add Article Modal */}
        <AddAwarenessModal
          open={showAddModal}
          onClose={() => setShowAddModal(false)}
          onAdd={handleAddArticle}
        />
      </div>
    </AppLayout>
  );
};

export default Awareness;
