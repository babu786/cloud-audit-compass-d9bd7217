import { Calendar, ChevronRight, Newspaper, AlertTriangle, BookOpen, Lightbulb } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AwarenessArticle } from '@/data/auditContent';

interface AwarenessCardProps {
  article: AwarenessArticle;
  onClick: () => void;
}

const categoryConfig = {
  'Weekly Awareness': { icon: Newspaper, color: 'text-primary' },
  'Misconfigurations': { icon: AlertTriangle, color: 'text-severity-high' },
  'Best Practices': { icon: BookOpen, color: 'text-severity-low' },
  'Audit Tips': { icon: Lightbulb, color: 'text-severity-medium' },
};

export function AwarenessCard({ article, onClick }: AwarenessCardProps) {
  const config = categoryConfig[article.category];
  const Icon = config.icon;

  return (
    <button
      onClick={onClick}
      className={cn(
        "group w-full text-left rounded-xl border transition-all duration-300 overflow-hidden",
        "bg-card/50 border-border/50 hover:border-primary/30 hover:bg-card/80"
      )}
    >
      {article.imageUrl && (
        <div className="w-full h-40 overflow-hidden">
          <img 
            src={article.imageUrl} 
            alt={article.title}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
          />
        </div>
      )}
      <div className="p-5">
        <div className="flex items-start gap-4">
          <div className={cn(
            "p-2.5 rounded-lg bg-secondary/50 group-hover:bg-secondary transition-colors"
          )}>
            <Icon className={cn("h-5 w-5", config.color)} />
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <span className={cn(
                "text-xs font-medium px-2 py-0.5 rounded-full",
                "bg-secondary text-muted-foreground"
              )}>
                {article.category}
              </span>
              <span className="flex items-center gap-1 text-xs text-muted-foreground">
                <Calendar className="h-3 w-3" />
                {article.date}
              </span>
            </div>
            
            <h3 className="font-semibold text-foreground group-hover:text-primary transition-colors mb-1">
              {article.title}
            </h3>
            
            <p className="text-sm text-muted-foreground line-clamp-2">
              {article.summary}
            </p>
          </div>
          
          <ChevronRight className="h-5 w-5 text-muted-foreground group-hover:text-primary group-hover:translate-x-1 transition-all flex-shrink-0" />
        </div>
      </div>
    </button>
  );
}
