import { useState, useEffect } from 'react';
import { Newspaper, AlertTriangle, BookOpen, Lightbulb, Plus, LogOut, Pencil, Trash2 } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { AwarenessCard } from '@/components/awareness/AwarenessCard';
import { AwarenessModal } from '@/components/awareness/AwarenessModal';
import { AdminLoginModal } from '@/components/admin/AdminLoginModal';
import { AddAwarenessModal } from '@/components/admin/AddAwarenessModal';
import { EditAwarenessModal } from '@/components/admin/EditAwarenessModal';
import { DeleteConfirmModal } from '@/components/admin/DeleteConfirmModal';
import { awarenessArticles as defaultArticles, AwarenessArticle } from '@/data/auditContent';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useLanguage } from '@/i18n/LanguageContext';

const Awareness = () => {
  const { t } = useLanguage();
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedArticle, setSelectedArticle] = useState<AwarenessArticle | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [articleToEdit, setArticleToEdit] = useState<AwarenessArticle | null>(null);
  const [articleToDelete, setArticleToDelete] = useState<AwarenessArticle | null>(null);
  const [articles, setArticles] = useState<AwarenessArticle[]>(defaultArticles);

  const categories = [
    { id: 'all', name: t.awareness.allArticles, icon: BookOpen },
    { id: 'Weekly Awareness', name: t.awareness.weeklyAwareness, icon: Newspaper },
    { id: 'Misconfigurations', name: t.awareness.misconfigurations, icon: AlertTriangle },
    { id: 'Best Practices', name: t.awareness.bestPractices, icon: BookOpen },
    { id: 'Audit Tips', name: t.awareness.auditTips, icon: Lightbulb },
  ] as const;

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

  const handleEditArticle = (updatedArticle: AwarenessArticle) => {
    const newArticles = articles.map(a => 
      a.id === updatedArticle.id ? updatedArticle : a
    );
    setArticles(newArticles);
    localStorage.setItem('awarenessArticles', JSON.stringify(newArticles));
  };

  const handleDeleteArticle = () => {
    if (!articleToDelete) return;
    
    const newArticles = articles.filter(a => a.id !== articleToDelete.id);
    setArticles(newArticles);
    localStorage.setItem('awarenessArticles', JSON.stringify(newArticles));
    setArticleToDelete(null);
    setShowDeleteModal(false);
  };

  const handleLogout = () => {
    sessionStorage.removeItem('isAdmin');
    setIsAdmin(false);
  };

  const openEditModal = (article: AwarenessArticle, e: React.MouseEvent) => {
    e.stopPropagation();
    setArticleToEdit(article);
    setShowEditModal(true);
  };

  const openDeleteModal = (article: AwarenessArticle, e: React.MouseEvent) => {
    e.stopPropagation();
    setArticleToDelete(article);
    setShowDeleteModal(true);
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
              {t.awareness.title}
            </h1>
            <p className="text-muted-foreground max-w-2xl">
              {t.awareness.subtitle}
            </p>
          </div>
          <div className="flex gap-2">
            {isAdmin ? (
              <>
                <Button onClick={() => setShowAddModal(true)} size="sm">
                  <Plus className="h-4 w-4 mr-1" />
                  {t.awareness.addArticle}
                </Button>
                <Button variant="outline" size="sm" onClick={handleLogout}>
                  <LogOut className="h-4 w-4 mr-1" />
                  {t.awareness.logout}
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={() => setShowLoginModal(true)}>
                {t.awareness.adminLogin}
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
            <div key={article.id} className="relative group">
              <AwarenessCard 
                article={article}
                onClick={() => setSelectedArticle(article)}
              />
              {isAdmin && (
                <div className="absolute top-2 right-2 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                  <Button
                    size="icon"
                    variant="secondary"
                    className="h-8 w-8"
                    onClick={(e) => openEditModal(article, e)}
                  >
                    <Pencil className="h-4 w-4" />
                  </Button>
                  <Button
                    size="icon"
                    variant="destructive"
                    className="h-8 w-8"
                    onClick={(e) => openDeleteModal(article, e)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>

        {filteredArticles.length === 0 && (
          <div className="text-center py-12">
            <p className="text-muted-foreground">{t.awareness.noArticles}</p>
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

        {/* Edit Article Modal */}
        <EditAwarenessModal
          open={showEditModal}
          article={articleToEdit}
          onClose={() => {
            setShowEditModal(false);
            setArticleToEdit(null);
          }}
          onSave={handleEditArticle}
        />

        {/* Delete Confirm Modal */}
        <DeleteConfirmModal
          open={showDeleteModal}
          onClose={() => {
            setShowDeleteModal(false);
            setArticleToDelete(null);
          }}
          onConfirm={handleDeleteArticle}
          title={articleToDelete?.title}
        />
      </div>
    </AppLayout>
  );
};

export default Awareness;
