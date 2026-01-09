import { useParams, Link, useNavigate } from 'react-router-dom';
import { ArrowLeft, ArrowRight, CheckCircle, Loader2 } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { LessonList } from '@/components/courses/LessonList';
import {
  useCourse,
  useLessons,
  useEnrollment,
  useLessonProgress,
  useMarkLessonComplete,
} from '@/hooks/useCourses';
import { useLanguage } from '@/i18n/LanguageContext';
import { toast } from 'sonner';

export default function LessonView() {
  const { courseId, lessonId } = useParams<{ courseId: string; lessonId: string }>();
  const navigate = useNavigate();
  const { t } = useLanguage();

  const { data: course, isLoading: courseLoading } = useCourse(courseId!);
  const { data: lessons, isLoading: lessonsLoading } = useLessons(courseId!);
  const { data: enrollment } = useEnrollment(courseId!);
  const { data: lessonProgress } = useLessonProgress(enrollment?.id || '');
  const markComplete = useMarkLessonComplete();

  const isLoading = courseLoading || lessonsLoading;

  const currentLesson = lessons?.find((l) => l.id === lessonId);
  const currentIndex = lessons?.findIndex((l) => l.id === lessonId) ?? -1;
  const prevLesson = currentIndex > 0 ? lessons?.[currentIndex - 1] : null;
  const nextLesson = currentIndex < (lessons?.length || 0) - 1 ? lessons?.[currentIndex + 1] : null;

  const isCompleted = lessonProgress?.some(
    (lp) => lp.lesson_id === lessonId && lp.is_completed
  );

  const handleMarkComplete = async () => {
    if (!enrollment || !lessonId || !lessons) return;

    try {
      await markComplete.mutateAsync({
        enrollmentId: enrollment.id,
        lessonId,
        courseId: courseId!,
        totalLessons: lessons.length,
      });
      toast.success(t.courses?.lessonCompleted || 'Lesson marked as complete!');

      if (nextLesson) {
        navigate(`/courses/${courseId}/lesson/${nextLesson.id}`);
      }
    } catch (error) {
      toast.error(t.courses?.lessonCompleteError || 'Failed to mark lesson as complete');
    }
  };

  if (isLoading) {
    return (
      <AppLayout>
        <div className="flex min-h-[50vh] items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </AppLayout>
    );
  }

  if (!course || !currentLesson) {
    return (
      <AppLayout>
        <div className="container mx-auto px-4 py-20 text-center">
          <h2 className="text-2xl font-bold">{t.courses?.lessonNotFound || 'Lesson not found'}</h2>
          <Link to={`/courses/${courseId}`}>
            <Button className="mt-4">{t.courses?.backToCourse || 'Back to Course'}</Button>
          </Link>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="container mx-auto px-4 py-8">
        {/* Breadcrumb */}
        <div className="mb-6 flex items-center gap-2 text-sm text-muted-foreground">
          <Link to="/courses" className="hover:text-foreground">
            {t.courses?.courses || 'Courses'}
          </Link>
          <span>/</span>
          <Link to={`/courses/${courseId}`} className="hover:text-foreground">
            {course.title}
          </Link>
          <span>/</span>
          <span className="text-foreground">{currentLesson.title}</span>
        </div>

        <div className="grid gap-8 lg:grid-cols-4">
          {/* Sidebar */}
          <div className="hidden lg:block">
            <LessonList
              lessons={lessons || []}
              lessonProgress={lessonProgress || []}
              currentLessonId={lessonId}
            />
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            <div className="rounded-lg border bg-card">
              {/* Lesson Header */}
              <div className="border-b p-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-muted-foreground">
                      {t.courses?.lesson || 'Lesson'} {currentIndex + 1} {t.courses?.of || 'of'} {lessons?.length}
                    </p>
                    <h1 className="mt-1 text-2xl font-bold">{currentLesson.title}</h1>
                  </div>
                  {isCompleted && (
                    <div className="flex items-center gap-2 rounded-full bg-green-500/10 px-3 py-1 text-sm text-green-600 dark:text-green-400">
                      <CheckCircle className="h-4 w-4" />
                      {t.courses?.completed || 'Completed'}
                    </div>
                  )}
                </div>
              </div>

              {/* Lesson Content */}
              <div className="p-6">
                <div className="prose prose-neutral dark:prose-invert max-w-none">
                  {currentLesson.content?.split('\n').map((paragraph, index) => {
                    if (paragraph.startsWith('# ')) {
                      return <h1 key={index} className="text-2xl font-bold mt-6 mb-4">{paragraph.slice(2)}</h1>;
                    }
                    if (paragraph.startsWith('## ')) {
                      return <h2 key={index} className="text-xl font-semibold mt-5 mb-3">{paragraph.slice(3)}</h2>;
                    }
                    if (paragraph.startsWith('### ')) {
                      return <h3 key={index} className="text-lg font-semibold mt-4 mb-2">{paragraph.slice(4)}</h3>;
                    }
                    if (paragraph.startsWith('- ')) {
                      return <li key={index} className="ml-4">{paragraph.slice(2)}</li>;
                    }
                    if (paragraph.startsWith('```')) {
                      return null;
                    }
                    if (paragraph.trim() === '') {
                      return <br key={index} />;
                    }
                    // Handle bold text
                    const formattedText = paragraph.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
                    return <p key={index} className="mb-3" dangerouslySetInnerHTML={{ __html: formattedText }} />;
                  })}
                </div>
              </div>

              {/* Navigation */}
              <div className="border-t p-6">
                <div className="flex items-center justify-between">
                  {prevLesson ? (
                    <Link to={`/courses/${courseId}/lesson/${prevLesson.id}`}>
                      <Button variant="outline" className="gap-2">
                        <ArrowLeft className="h-4 w-4" />
                        {t.courses?.previous || 'Previous'}
                      </Button>
                    </Link>
                  ) : (
                    <div />
                  )}

                  <div className="flex items-center gap-3">
                    {!isCompleted && (
                      <Button
                        onClick={handleMarkComplete}
                        disabled={markComplete.isPending}
                        variant="outline"
                        className="gap-2"
                      >
                        {markComplete.isPending ? (
                          <Loader2 className="h-4 w-4 animate-spin" />
                        ) : (
                          <CheckCircle className="h-4 w-4" />
                        )}
                        {t.courses?.markComplete || 'Mark Complete'}
                      </Button>
                    )}

                    {nextLesson ? (
                      <Link to={`/courses/${courseId}/lesson/${nextLesson.id}`}>
                        <Button className="gap-2">
                          {t.courses?.next || 'Next'}
                          <ArrowRight className="h-4 w-4" />
                        </Button>
                      </Link>
                    ) : (
                      <Link to={`/courses/${courseId}`}>
                        <Button className="gap-2">
                          {t.courses?.finishCourse || 'Finish Course'}
                          <CheckCircle className="h-4 w-4" />
                        </Button>
                      </Link>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
