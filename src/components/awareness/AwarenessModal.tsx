import { X, Calendar, Newspaper, AlertTriangle, BookOpen, Lightbulb } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AwarenessArticle } from '@/data/auditContent';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

interface AwarenessModalProps {
  article: AwarenessArticle | null;
  open: boolean;
  onClose: () => void;
}

const categoryConfig = {
  'Weekly Awareness': { icon: Newspaper, color: 'text-primary' },
  'Misconfigurations': { icon: AlertTriangle, color: 'text-severity-high' },
  'Best Practices': { icon: BookOpen, color: 'text-severity-low' },
  'Audit Tips': { icon: Lightbulb, color: 'text-severity-medium' },
};

export function AwarenessModal({ article, open, onClose }: AwarenessModalProps) {
  if (!article) return null;

  const config = categoryConfig[article.category];
  const Icon = config.icon;

  // Simple markdown-like rendering
  const renderContent = (content: string) => {
    return content.split('\n\n').map((paragraph, idx) => {
      // Headers
      if (paragraph.startsWith('**') && paragraph.endsWith('**')) {
        return (
          <h4 key={idx} className="text-sm font-semibold text-foreground mt-4 mb-2">
            {paragraph.slice(2, -2)}
          </h4>
        );
      }
      
      // Code blocks
      if (paragraph.startsWith('```')) {
        const code = paragraph.replace(/```\w*\n?/g, '').trim();
        return (
          <pre key={idx} className="bg-background/80 border border-border/50 rounded-lg p-3 overflow-x-auto my-3">
            <code className="text-xs font-mono text-primary">{code}</code>
          </pre>
        );
      }

      // Lists
      if (paragraph.startsWith('- ') || paragraph.match(/^\d+\./)) {
        const items = paragraph.split('\n');
        return (
          <ul key={idx} className="space-y-1 my-2 pl-4">
            {items.map((item, i) => (
              <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                <span className="text-primary mt-1">•</span>
                {item.replace(/^[-\d.]+\s*/, '')}
              </li>
            ))}
          </ul>
        );
      }

      // Regular paragraphs
      return (
        <p key={idx} className="text-sm text-muted-foreground mb-3 leading-relaxed">
          {paragraph}
        </p>
      );
    });
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto glass border-border/50">
        <DialogHeader className="space-y-4">
          <div className="flex items-center gap-3">
            <div className={cn("p-2 rounded-lg bg-secondary/50")}>
              <Icon className={cn("h-5 w-5", config.color)} />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-secondary text-muted-foreground">
                {article.category}
              </span>
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                <Calendar className="h-3 w-3" />
                {article.date}
              </span>
            </div>
          </div>
          <DialogTitle className="text-xl font-semibold text-foreground">
            {article.title}
          </DialogTitle>
        </DialogHeader>
        
        <div className="mt-4 border-t border-border/50 pt-4">
          <p className="text-sm text-foreground font-medium mb-4">{article.summary}</p>
          <div className="prose prose-sm prose-invert max-w-none">
            {renderContent(article.content)}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
