import { Calendar, ChevronRight, Newspaper, AlertTriangle, BookOpen, Lightbulb } from 'lucide-react';
import { cn } from '@/lib/utils';
import { AwarenessArticle } from '@/data/auditContent';
import { useRef, useState } from 'react';

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
  const cardRef = useRef<HTMLButtonElement>(null);
  const [transform, setTransform] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);

  const handleMouseMove = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const x = (e.clientX - rect.left - rect.width / 2) / 20;
    const y = (e.clientY - rect.top - rect.height / 2) / 20;
    setTransform({ x: -x, y: -y });
  };

  const handleMouseLeave = () => {
    setTransform({ x: 0, y: 0 });
    setIsHovered(false);
  };

  return (
    <button
      ref={cardRef}
      onClick={onClick}
      onMouseMove={handleMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={handleMouseLeave}
      className={cn(
        "group w-full text-left rounded-xl border transition-all duration-300 overflow-hidden relative",
        "bg-card/50 border-border/50 hover:border-primary/30 hover:bg-card/80",
        "hover:shadow-[0_8px_30px_rgba(0,0,0,0.12)]"
      )}
      style={{
        transform: isHovered ? `perspective(1000px) rotateX(${transform.y}deg) rotateY(${-transform.x}deg)` : 'none',
        transition: 'transform 0.1s ease-out'
      }}
    >
      {/* Shine sweep overlay */}
      <div 
        className={cn(
          "absolute inset-0 z-10 pointer-events-none",
          "bg-gradient-to-r from-transparent via-white/10 to-transparent",
          "-translate-x-full skew-x-12",
          isHovered && "animate-shine-sweep"
        )}
      />

      {article.imageUrl && (
        <div className="w-full h-40 overflow-hidden relative">
          <img 
            src={article.imageUrl} 
            alt={article.title}
            className="w-full h-full object-cover transition-transform duration-500"
            style={{
              transform: isHovered 
                ? `scale(1.1) translateX(${transform.x * 2}px) translateY(${transform.y * 2}px)` 
                : 'scale(1)'
            }}
          />
          {/* Gradient overlay that intensifies on hover */}
          <div className={cn(
            "absolute inset-0 bg-gradient-to-t from-background/80 via-transparent to-transparent",
            "transition-opacity duration-300",
            isHovered ? "opacity-60" : "opacity-40"
          )} />
        </div>
      )}
      <div className="p-5 relative">
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
