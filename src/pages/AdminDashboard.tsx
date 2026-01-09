import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Upload, FileText, LogOut, LayoutDashboard } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAdminAuth } from '@/hooks/useAdminAuth';
import { AddAwarenessModal } from '@/components/admin/AddAwarenessModal';
import { useToast } from '@/hooks/use-toast';
import { useLanguage } from '@/i18n/LanguageContext';
import type { AwarenessArticle } from '@/data/auditContent';

export default function AdminDashboard() {
  const { isAdmin, isLoading, openLoginModal, logout } = useAdminAuth();
  const [showAddModal, setShowAddModal] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();
  const { t } = useLanguage();

  const handleAddArticle = (article: AwarenessArticle) => {
    // Get existing articles from localStorage
    const stored = localStorage.getItem('awarenessArticles');
    const existingArticles: AwarenessArticle[] = stored ? JSON.parse(stored) : [];
    
    // Add new article
    const updatedArticles = [article, ...existingArticles];
    localStorage.setItem('awarenessArticles', JSON.stringify(updatedArticles));
    
    toast({
      title: "Article Added",
      description: `"${article.title}" has been added successfully.`,
    });
    
    setShowAddModal(false);
  };

  if (isLoading) {
    return (
      <AppLayout>
        <div className="container py-12 flex items-center justify-center min-h-[60vh]">
          <div className="animate-pulse text-muted-foreground">Loading...</div>
        </div>
      </AppLayout>
    );
  }

  if (!isAdmin) {
    return (
      <AppLayout>
        <div className="container py-12 flex flex-col items-center justify-center min-h-[60vh] gap-6">
          <div className="text-center space-y-2">
            <LayoutDashboard className="h-16 w-16 mx-auto text-muted-foreground/50" />
            <h1 className="text-2xl font-bold">Admin Dashboard</h1>
            <p className="text-muted-foreground">Please login to access the admin dashboard.</p>
          </div>
          <Button onClick={openLoginModal} size="lg">
            Login as Admin
          </Button>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="container py-8 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <h1 className="text-3xl font-bold tracking-tight">Admin Dashboard</h1>
            <p className="text-muted-foreground">Manage your content and controls</p>
          </div>
          <Button variant="outline" onClick={logout} className="gap-2">
            <LogOut className="h-4 w-4" />
            Logout
          </Button>
        </div>

        {/* Action Cards */}
        <div className="grid gap-6 md:grid-cols-2 max-w-3xl">
          {/* Import Controls Card */}
          <Card 
            className="group cursor-pointer transition-all duration-300 hover:shadow-lg hover:shadow-primary/10 hover:border-primary/50"
            onClick={() => navigate('/import')}
          >
            <CardHeader className="space-y-1">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                  <Upload className="h-6 w-6" />
                </div>
                <CardTitle className="text-xl">Import Controls</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-base">
                Import audit controls from CSV or JSON files. Download templates to get started quickly.
              </CardDescription>
              <Button variant="ghost" className="mt-4 gap-2 group-hover:bg-primary/10">
                Go to Import
                <span className="transition-transform group-hover:translate-x-1">→</span>
              </Button>
            </CardContent>
          </Card>

          {/* Add Article Card */}
          <Card 
            className="group cursor-pointer transition-all duration-300 hover:shadow-lg hover:shadow-primary/10 hover:border-primary/50"
            onClick={() => setShowAddModal(true)}
          >
            <CardHeader className="space-y-1">
              <div className="flex items-center gap-3">
                <div className="p-3 rounded-xl bg-primary/10 text-primary group-hover:bg-primary group-hover:text-primary-foreground transition-colors">
                  <FileText className="h-6 w-6" />
                </div>
                <CardTitle className="text-xl">Add Article</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              <CardDescription className="text-base">
                Create a new awareness article for the security library. Add educational content for users.
              </CardDescription>
              <Button variant="ghost" className="mt-4 gap-2 group-hover:bg-primary/10">
                Add New Article
                <span className="transition-transform group-hover:translate-x-1">→</span>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Add Article Modal */}
      <AddAwarenessModal
        open={showAddModal}
        onClose={() => setShowAddModal(false)}
        onAdd={handleAddArticle}
      />
    </AppLayout>
  );
}
