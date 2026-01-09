import { useParams, Link } from 'react-router-dom';
import {
  Clock,
  BookOpen,
  Award,
  Play,
  CheckCircle,
  ArrowRight,
  Loader2,
  Lock,
} from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import {
  useCourse,
  useLessons,
  useEnrollment,
  useLessonProgress,
  useEnrollMutation,
} from '@/hooks/useCourses';
import { useQuiz, useCertificate, useQuizAttempts } from '@/hooks/useQuiz';
import { useLanguage } from '@/i18n/LanguageContext';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';
import { toast } from 'sonner';

export default function CourseDetail() {
  const { id } = useParams<{ id: string }>();
  const { t } = useLanguage();
  const { user } = useFirebaseAuth();
  const isGuest = !user;

  const { data: course, isLoading: courseLoading } = useCourse(id!);
  const { data: lessons, isLoading: lessonsLoading } = useLessons(id!);
  const { data: enrollment, isLoading: enrollmentLoading } = useEnrollment(id!);
  const { data: lessonProgress } = useLessonProgress(enrollment?.id || '');
  const { data: quiz } = useQuiz(id!);
  const { data: certificate } = useCertificate(enrollment?.id || '');
  const { data: quizAttempts } = useQuizAttempts(enrollment?.id || '', quiz?.id || '');
  const enrollMutation = useEnrollMutation();

  const isLoading = courseLoading || lessonsLoading || enrollmentLoading;

  if (isLoading) {
    return (
      <AppLayout>
        <div className="flex min-h-[50vh] items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </AppLayout>
    );
  }

  if (!course) {
    return (
      <AppLayout>
        <div className="container mx-auto px-4 py-20 text-center">
          <h2 className="text-2xl font-bold">{t.courses?.courseNotFound || 'Course not found'}</h2>
          <Link to="/courses">
            <Button className="mt-4">{t.courses?.backToCourses || 'Back to Courses'}</Button>
          </Link>
        </div>
      </AppLayout>
    );
  }

  const completedLessons = lessonProgress?.filter((lp) => lp.is_completed).length || 0;
  const totalLessons = lessons?.length || 0;
  const progress = enrollment?.progress_percent || 0;
  const allLessonsCompleted = completedLessons === totalLessons && totalLessons > 0;
  const hasPassedQuiz = quizAttempts?.some((a) => a.passed);
  const attemptsUsed = quizAttempts?.length || 0;
  const canTakeQuiz = allLessonsCompleted && !hasPassedQuiz && attemptsUsed < (quiz?.max_attempts || 3);

  const handleEnroll = async () => {
    try {
      await enrollMutation.mutateAsync(id!);
      toast.success(t.courses?.enrolledSuccess || 'Successfully enrolled!');
    } catch (error) {
      toast.error(t.courses?.enrolledError || 'Failed to enroll');
    }
  };

  const getFirstIncompleteLesson = () => {
    if (!lessons || !lessonProgress) return lessons?.[0];
    const completedIds = new Set(lessonProgress.filter((lp) => lp.is_completed).map((lp) => lp.lesson_id));
    return lessons.find((l) => !completedIds.has(l.id)) || lessons[0];
  };

  const nextLesson = getFirstIncompleteLesson();

  return (
    <AppLayout>
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="outline">{course.category}</Badge>
            <Badge variant="secondary">{course.difficulty}</Badge>
          </div>

          <h1 className="text-3xl font-bold md:text-4xl">{course.title}</h1>
          <p className="text-lg text-muted-foreground">{course.description}</p>

          <div className="flex flex-wrap items-center gap-6 text-sm text-muted-foreground">
            <span className="flex items-center gap-2">
              <Clock className="h-4 w-4" />
              {course.duration_minutes} {t.courses?.minutes || 'minutes'}
            </span>
            <span className="flex items-center gap-2">
              <BookOpen className="h-4 w-4" />
              {totalLessons} {t.courses?.lessons || 'lessons'}
            </span>
            <span className="flex items-center gap-2">
              <Award className="h-4 w-4" />
              {t.courses?.freeCertificate || 'Free Certificate'}
            </span>
          </div>
        </div>

        <div className="grid gap-8 lg:grid-cols-3">
          {/* Main Content */}
          <div className="lg:col-span-2">
            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <h2 className="text-xl font-semibold">{t.courses?.curriculum || 'Curriculum'}</h2>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {lessons?.map((lesson, index) => {
                    const isCompleted = lessonProgress?.some(
                      (lp) => lp.lesson_id === lesson.id && lp.is_completed
                    );
                    const canAccess = !isGuest && enrollment;

                    return (
                      <Link
                        key={lesson.id}
                        to={canAccess ? `/courses/${id}/lesson/${lesson.id}` : '#'}
                        className={`flex items-center gap-4 rounded-lg border p-4 transition-colors ${
                          canAccess
                            ? 'hover:bg-muted/50'
                            : 'cursor-not-allowed opacity-60'
                        }`}
                        onClick={(e) => !canAccess && e.preventDefault()}
                      >
                        <div className="flex-shrink-0">
                          {isGuest ? (
                            <Lock className="h-5 w-5 text-muted-foreground" />
                          ) : isCompleted ? (
                            <CheckCircle className="h-6 w-6 text-green-500" />
                          ) : (
                            <div className="flex h-6 w-6 items-center justify-center rounded-full border-2 text-xs">
                              {index + 1}
                            </div>
                          )}
                        </div>
                        <div className="flex-1">
                          <p className="font-medium">{lesson.title}</p>
                          <p className="text-sm text-muted-foreground">
                            {lesson.duration_minutes} {t.courses?.minutes || 'min'}
                          </p>
                        </div>
                        {canAccess && (
                          <ArrowRight className="h-4 w-4 text-muted-foreground" />
                        )}
                      </Link>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Progress Card */}
            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
              <CardContent className="pt-6">
                {isGuest ? (
                  <div className="space-y-4 text-center">
                    <div className="p-4 bg-primary/5 rounded-lg border border-primary/20">
                      <Lock className="h-8 w-8 mx-auto text-primary mb-2" />
                      <p className="font-medium">Create a free account to enroll</p>
                      <p className="text-sm text-muted-foreground mt-1">
                        Track progress and earn certificates
                      </p>
                    </div>
                    <Link to={`/login?redirect=/courses/${id}`}>
                      <Button className="w-full gap-2" size="lg">
                        <Play className="h-4 w-4" />
                        Login to Enroll
                      </Button>
                    </Link>
                    <p className="text-xs text-muted-foreground">
                      Don't have an account?{' '}
                      <Link to="/signup" className="text-primary hover:underline">
                        Sign up free
                      </Link>
                    </p>
                  </div>
                ) : enrollment ? (
                  <div className="space-y-4">
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>{t.courses?.progress || 'Progress'}</span>
                        <span className="font-medium">{progress}%</span>
                      </div>
                      <Progress value={progress} className="h-2" />
                      <p className="text-sm text-muted-foreground">
                        {completedLessons} / {totalLessons} {t.courses?.lessonsCompleted || 'lessons completed'}
                      </p>
                    </div>

                    {certificate ? (
                      <Link to={`/certificate/${certificate.id}`}>
                        <Button className="w-full gap-2">
                          <Award className="h-4 w-4" />
                          {t.courses?.viewCertificate || 'View Certificate'}
                        </Button>
                      </Link>
                    ) : canTakeQuiz ? (
                      <Link to={`/courses/${id}/quiz`}>
                        <Button className="w-full gap-2">
                          <Award className="h-4 w-4" />
                          {t.courses?.takeQuiz || 'Take Quiz'}
                        </Button>
                      </Link>
                    ) : allLessonsCompleted && !hasPassedQuiz ? (
                      <div className="text-center text-sm text-muted-foreground">
                        {t.courses?.noAttemptsLeft || 'No quiz attempts remaining'}
                      </div>
                    ) : nextLesson ? (
                      <Link to={`/courses/${id}/lesson/${nextLesson.id}`}>
                        <Button className="w-full gap-2">
                          <Play className="h-4 w-4" />
                          {t.courses?.continueLearning || 'Continue Learning'}
                        </Button>
                      </Link>
                    ) : null}
                  </div>
                ) : (
                  <div className="space-y-4 text-center">
                    <p className="text-sm text-muted-foreground">
                      {t.courses?.enrollToStart || 'Enroll to start learning'}
                    </p>
                    <Button
                      onClick={handleEnroll}
                      disabled={enrollMutation.isPending}
                      className="w-full gap-2"
                      size="lg"
                    >
                      {enrollMutation.isPending ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <Play className="h-4 w-4" />
                      )}
                      {t.courses?.enrollNow || 'Enroll Now - Free'}
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Course Info */}
            <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
              <CardContent className="pt-6">
                <h3 className="mb-4 font-semibold">{t.courses?.includes || 'This course includes'}</h3>
                <ul className="space-y-3 text-sm">
                  <li className="flex items-center gap-2">
                    <BookOpen className="h-4 w-4 text-primary" />
                    {totalLessons} {t.courses?.lessons || 'lessons'}
                  </li>
                  <li className="flex items-center gap-2">
                    <Clock className="h-4 w-4 text-primary" />
                    {course.duration_minutes} {t.courses?.minutesOfContent || 'minutes of content'}
                  </li>
                  <li className="flex items-center gap-2">
                    <Award className="h-4 w-4 text-primary" />
                    {t.courses?.certificateOnCompletion || 'Certificate on completion'}
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-primary" />
                    {t.courses?.quizWithQuestions || 'Quiz to test your knowledge'}
                  </li>
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </AppLayout>
  );
}
