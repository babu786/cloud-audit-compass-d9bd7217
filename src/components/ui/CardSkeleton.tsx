import { cn } from '@/lib/utils';

interface CardSkeletonProps {
  className?: string;
  variant?: 'control' | 'awareness' | 'glossary';
}

export function CardSkeleton({ className, variant = 'control' }: CardSkeletonProps) {
  if (variant === 'awareness') {
    return (
      <div className={cn(
        "rounded-xl border border-border/50 bg-card/50 overflow-hidden",
        className
      )}>
        {/* Image skeleton */}
        <div className="w-full h-40 bg-muted shimmer" />
        
        {/* Content */}
        <div className="p-5">
          <div className="flex items-start gap-4">
            {/* Icon skeleton */}
            <div className="w-10 h-10 rounded-lg bg-muted shimmer" />
            
            <div className="flex-1 space-y-3">
              {/* Category & date */}
              <div className="flex items-center gap-2">
                <div className="h-5 w-24 rounded-full bg-muted shimmer" />
                <div className="h-4 w-16 rounded bg-muted shimmer" />
              </div>
              
              {/* Title */}
              <div className="h-5 w-3/4 rounded bg-muted shimmer" />
              
              {/* Summary */}
              <div className="space-y-1.5">
                <div className="h-3 w-full rounded bg-muted shimmer" />
                <div className="h-3 w-2/3 rounded bg-muted shimmer" />
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (variant === 'glossary') {
    return (
      <div className={cn(
        "rounded-xl border border-border/50 bg-card/50 p-5",
        className
      )}>
        <div className="flex items-start gap-4">
          {/* Icon skeleton */}
          <div className="w-10 h-10 rounded-lg bg-muted shimmer flex-shrink-0" />
          
          <div className="flex-1 space-y-3">
            {/* Title & acronym */}
            <div className="flex items-center gap-2">
              <div className="h-5 w-32 rounded bg-muted shimmer" />
              <div className="h-4 w-12 rounded-full bg-muted shimmer" />
            </div>
            
            {/* Definition */}
            <div className="space-y-1.5">
              <div className="h-3 w-full rounded bg-muted shimmer" />
              <div className="h-3 w-full rounded bg-muted shimmer" />
              <div className="h-3 w-1/2 rounded bg-muted shimmer" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Default: control card
  return (
    <div className={cn(
      "rounded-xl border border-border/50 bg-card/50 p-5",
      className
    )}>
      <div className="flex items-start gap-4">
        {/* Left column */}
        <div className="space-y-3 flex-shrink-0">
          {/* ID badge */}
          <div className="h-6 w-20 rounded bg-muted shimmer" />
          {/* Severity badge */}
          <div className="h-5 w-16 rounded-full bg-muted shimmer" />
        </div>
        
        {/* Main content */}
        <div className="flex-1 space-y-3">
          {/* Title */}
          <div className="h-5 w-3/4 rounded bg-muted shimmer" />
          
          {/* Description */}
          <div className="space-y-1.5">
            <div className="h-3 w-full rounded bg-muted shimmer" />
            <div className="h-3 w-5/6 rounded bg-muted shimmer" />
          </div>
          
          {/* Tags */}
          <div className="flex items-center gap-2 pt-1">
            <div className="h-5 w-14 rounded-full bg-muted shimmer" />
            <div className="h-5 w-20 rounded-full bg-muted shimmer" />
            <div className="h-5 w-16 rounded-full bg-muted shimmer" />
          </div>
        </div>
        
        {/* Right arrow */}
        <div className="w-5 h-5 rounded bg-muted shimmer flex-shrink-0" />
      </div>
    </div>
  );
}

interface SkeletonGridProps {
  count?: number;
  variant?: 'control' | 'awareness' | 'glossary';
  className?: string;
}

export function SkeletonGrid({ count = 6, variant = 'control', className }: SkeletonGridProps) {
  return (
    <div className={cn(
      variant === 'awareness' || variant === 'glossary' 
        ? 'grid gap-4 md:grid-cols-2 lg:grid-cols-3' 
        : 'space-y-3',
      className
    )}>
      {Array.from({ length: count }).map((_, i) => (
        <CardSkeleton 
          key={i} 
          variant={variant}
          className="animate-pulse"
        />
      ))}
    </div>
  );
}
