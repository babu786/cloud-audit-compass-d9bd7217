import { useState, useRef, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Pencil, Image, X } from 'lucide-react';
import { AwarenessArticle } from '@/data/auditContent';
import { useLanguage } from '@/i18n/LanguageContext';

interface EditAwarenessModalProps {
  open: boolean;
  article: AwarenessArticle | null;
  onClose: () => void;
  onSave: (article: AwarenessArticle) => void;
}

const categories = [
  'Weekly Awareness',
  'Misconfigurations',
  'Best Practices',
  'Audit Tips',
];

export const EditAwarenessModal = ({ open, article, onClose, onSave }: EditAwarenessModalProps) => {
  const { t } = useLanguage();
  const [title, setTitle] = useState('');
  const [summary, setSummary] = useState('');
  const [content, setContent] = useState('');
  const [category, setCategory] = useState('');
  const [date, setDate] = useState('');
  const [imageUrl, setImageUrl] = useState('');
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (article) {
      setTitle(article.title);
      setSummary(article.summary);
      setContent(article.content);
      setCategory(article.category);
      setDate(article.date);
      setImageUrl(article.imageUrl || '');
      setImagePreview(article.imageUrl || null);
    }
  }, [article]);

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64 = reader.result as string;
        setImagePreview(base64);
        setImageUrl(base64);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleRemoveImage = () => {
    setImagePreview(null);
    setImageUrl('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!title || !summary || !content || !category || !article) return;

    const updatedArticle: AwarenessArticle = {
      ...article,
      title,
      summary,
      content,
      category: category as AwarenessArticle['category'],
      date,
      imageUrl: imageUrl || undefined,
    };

    onSave(updatedArticle);
    onClose();
  };

  if (!article) return null;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Pencil className="h-5 w-5 text-primary" />
            {t.articleForm.editTitle}
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="edit-title">{t.articleForm.title}</Label>
            <Input
              id="edit-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={t.articleForm.titlePlaceholder}
              required
            />
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="edit-category">{t.articleForm.category}</Label>
              <Select value={category} onValueChange={setCategory} required>
                <SelectTrigger>
                  <SelectValue placeholder={t.articleForm.selectCategory} />
                </SelectTrigger>
                <SelectContent>
                  {categories.map((cat) => (
                    <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-date">{t.articleForm.date}</Label>
              <Input
                id="edit-date"
                type="date"
                value={date}
                onChange={(e) => setDate(e.target.value)}
                required
              />
            </div>
          </div>

          {/* Image Upload */}
          <div className="space-y-2">
            <Label>{t.articleForm.image}</Label>
            {imagePreview ? (
              <div className="relative rounded-lg overflow-hidden border border-border">
                <img 
                  src={imagePreview} 
                  alt="Preview" 
                  className="w-full h-40 object-cover"
                />
                <Button
                  type="button"
                  variant="destructive"
                  size="icon"
                  className="absolute top-2 right-2 h-8 w-8"
                  onClick={handleRemoveImage}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            ) : (
              <div 
                onClick={() => fileInputRef.current?.click()}
                className="flex flex-col items-center justify-center gap-2 p-6 border-2 border-dashed border-border rounded-lg cursor-pointer hover:border-primary/50 transition-colors"
              >
                <Image className="h-8 w-8 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">{t.articleForm.clickToUpload}</span>
              </div>
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept="image/*"
              onChange={handleImageUpload}
              className="hidden"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="edit-summary">{t.articleForm.summary}</Label>
            <Textarea
              id="edit-summary"
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder={t.articleForm.summaryPlaceholder}
              rows={2}
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="edit-content">{t.articleForm.content}</Label>
            <Textarea
              id="edit-content"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={t.articleForm.contentPlaceholder}
              rows={8}
              required
            />
          </div>

          <div className="flex gap-2 justify-end">
            <Button type="button" variant="outline" onClick={onClose}>
              {t.common.cancel}
            </Button>
            <Button type="submit">{t.common.save}</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};
