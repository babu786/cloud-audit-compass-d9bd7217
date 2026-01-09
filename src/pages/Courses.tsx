import { useState } from 'react';
import { GraduationCap, Loader2 } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { CourseCard } from '@/components/courses/CourseCard';
import { CourseFilters } from '@/components/courses/CourseFilters';
import { useCourses, useEnrollments } from '@/hooks/useCourses';
import { useLanguage } from '@/i18n/LanguageContext';

export default function Courses() {
  const { t } = useLanguage();
  const [category, setCategory] = useState('all');
  const [difficulty, setDifficulty] = useState('all');

  const { data: courses, isLoading: coursesLoading } = useCourses(category, difficulty);
  const { data: enrollments, isLoading: enrollmentsLoading } = useEnrollments();

  const isLoading = coursesLoading || enrollmentsLoading;

  const enrollmentMap = new Map(
    enrollments?.map((e) => [e.course_id, e]) || []
  );

  const resetFilters = () => {
    setCategory('all');
    setDifficulty('all');
  };

  return (
    <AppLayout>
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8 space-y-4">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
              <GraduationCap className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">
                {t.courses?.title || 'Self-Learning Courses'}
              </h1>
              <p className="text-muted-foreground">
                {t.courses?.subtitle || 'Learn cloud security at your own pace and earn free certificates'}
              </p>
            </div>
          </div>

          <CourseFilters
            category={category}
            difficulty={difficulty}
            onCategoryChange={setCategory}
            onDifficultyChange={setDifficulty}
            onReset={resetFilters}
          />
        </div>

        {/* Content */}
        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : courses?.length === 0 ? (
          <div className="py-20 text-center">
            <GraduationCap className="mx-auto h-12 w-12 text-muted-foreground" />
            <h3 className="mt-4 text-lg font-medium">
              {t.courses?.noCourses || 'No courses found'}
            </h3>
            <p className="mt-2 text-muted-foreground">
              {t.courses?.tryDifferentFilters || 'Try adjusting your filters'}
            </p>
          </div>
        ) : (
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {courses?.map((course) => (
              <CourseCard
                key={course.id}
                course={course}
                enrollment={enrollmentMap.get(course.id)}
              />
            ))}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
