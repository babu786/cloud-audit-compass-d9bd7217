import { Link, useParams } from 'react-router-dom';
import { Check, Circle, Play } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useLanguage } from '@/i18n/LanguageContext';
import type { Lesson, LessonProgress } from '@/hooks/useCourses';

interface LessonListProps {
  lessons: Lesson[];
  lessonProgress: LessonProgress[];
  currentLessonId?: string;
}

export function LessonList({ lessons, lessonProgress, currentLessonId }: LessonListProps) {
  const { t } = useLanguage();
  const { id: courseId } = useParams();

  const completedLessonIds = new Set(
    lessonProgress.filter((lp) => lp.is_completed).map((lp) => lp.lesson_id)
  );

  return (
    <div className="rounded-lg border bg-card">
      <div className="border-b p-4">
        <h3 className="font-semibold">{t.courses?.lessons || 'Lessons'}</h3>
        <p className="text-sm text-muted-foreground">
          {completedLessonIds.size} / {lessons.length} {t.courses?.completed || 'completed'}
        </p>
      </div>
      <ScrollArea className="h-[calc(100vh-300px)] min-h-[200px]">
        <div className="p-2">
          {lessons.map((lesson, index) => {
            const isCompleted = completedLessonIds.has(lesson.id);
            const isCurrent = lesson.id === currentLessonId;

            return (
              <Link
                key={lesson.id}
                to={`/courses/${courseId}/lesson/${lesson.id}`}
                className={cn(
                  'flex items-start gap-3 rounded-md p-3 transition-colors',
                  isCurrent
                    ? 'bg-primary/10 text-primary'
                    : 'hover:bg-muted'
                )}
              >
                <div className="mt-0.5 flex-shrink-0">
                  {isCompleted ? (
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-green-500 text-white">
                      <Check className="h-4 w-4" />
                    </div>
                  ) : isCurrent ? (
                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-primary text-primary-foreground">
                      <Play className="h-3 w-3" />
                    </div>
                  ) : (
                    <div className="flex h-6 w-6 items-center justify-center rounded-full border-2 text-xs text-muted-foreground">
                      {index + 1}
                    </div>
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <p className={cn(
                    'text-sm font-medium',
                    isCompleted && !isCurrent && 'text-muted-foreground'
                  )}>
                    {lesson.title}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {lesson.duration_minutes} {t.courses?.minutes || 'min'}
                  </p>
                </div>
              </Link>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}
