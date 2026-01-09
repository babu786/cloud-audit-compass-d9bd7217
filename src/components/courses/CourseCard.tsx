import { Link } from 'react-router-dom';
import { Clock, BookOpen, Award, ArrowRight, Lock } from 'lucide-react';
import { Card, CardContent, CardFooter, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useLanguage } from '@/i18n/LanguageContext';
import type { Course, Enrollment } from '@/hooks/useCourses';

interface CourseCardProps {
  course: Course;
  enrollment?: Enrollment | null;
  isLoggedIn?: boolean;
}

const categoryColors: Record<string, string> = {
  AWS: 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/20',
  Azure: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/20',
  GCP: 'bg-red-500/10 text-red-600 dark:text-red-400 border-red-500/20',
  General: 'bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20',
};

const difficultyColors: Record<string, string> = {
  Beginner: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400',
  Intermediate: 'bg-amber-500/10 text-amber-600 dark:text-amber-400',
  Advanced: 'bg-rose-500/10 text-rose-600 dark:text-rose-400',
};

export function CourseCard({ course, enrollment, isLoggedIn = true }: CourseCardProps) {
  const { t } = useLanguage();
  const isEnrolled = !!enrollment;
  const progress = enrollment?.progress_percent || 0;

  return (
    <Card className="group flex flex-col overflow-hidden border-border/50 bg-card/50 backdrop-blur-sm transition-all duration-300 hover:border-primary/30 hover:shadow-lg hover:shadow-primary/5">
      <CardHeader className="space-y-3 pb-3">
        <div className="flex items-center justify-between">
          <Badge variant="outline" className={categoryColors[course.category]}>
            {course.category}
          </Badge>
          <Badge variant="secondary" className={difficultyColors[course.difficulty]}>
            {course.difficulty}
          </Badge>
        </div>
        <h3 className="line-clamp-2 text-lg font-semibold leading-tight transition-colors group-hover:text-primary">
          {course.title}
        </h3>
      </CardHeader>

      <CardContent className="flex-1 space-y-4">
        <p className="line-clamp-3 text-sm text-muted-foreground">
          {course.description}
        </p>

        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <span className="flex items-center gap-1">
            <Clock className="h-4 w-4" />
            {course.duration_minutes} {t.courses?.minutes || 'min'}
          </span>
          <span className="flex items-center gap-1">
            <Award className="h-4 w-4" />
            {t.courses?.freeCertificate || 'Free Certificate'}
          </span>
        </div>

        {isEnrolled && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{t.courses?.progress || 'Progress'}</span>
              <span className="font-medium">{progress}%</span>
            </div>
            <Progress value={progress} className="h-2" />
          </div>
        )}
      </CardContent>

      <CardFooter className="pt-4">
        {!isLoggedIn ? (
          <Link to={`/login?redirect=/courses/${course.id}`} className="w-full">
            <Button className="w-full gap-2" variant="default">
              <Lock className="h-4 w-4" />
              Login to Enroll
            </Button>
          </Link>
        ) : (
          <Link to={`/courses/${course.id}`} className="w-full">
            <Button className="w-full gap-2" variant={isEnrolled ? 'default' : 'outline'}>
              {isEnrolled ? (
                <>
                  <BookOpen className="h-4 w-4" />
                  {t.courses?.continueLearning || 'Continue Learning'}
                </>
              ) : (
                <>
                  {t.courses?.viewCourse || 'View Course'}
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
                </>
              )}
            </Button>
          </Link>
        )}
      </CardFooter>
    </Card>
  );
}
