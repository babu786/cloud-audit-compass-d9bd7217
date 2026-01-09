import { Link } from 'react-router-dom';
import { BookOpen, Award, Clock, Loader2, ArrowRight } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useEnrollments } from '@/hooks/useCourses';
import { useCertificates } from '@/hooks/useQuiz';
import { useLanguage } from '@/i18n/LanguageContext';

export default function MyLearning() {
  const { t } = useLanguage();
  const { data: enrollments, isLoading: enrollmentsLoading } = useEnrollments();
  const { data: certificates, isLoading: certificatesLoading } = useCertificates();

  const isLoading = enrollmentsLoading || certificatesLoading;

  const inProgressEnrollments = enrollments?.filter(
    (e) => e.status !== 'completed'
  );
  const completedEnrollments = enrollments?.filter(
    (e) => e.status === 'completed'
  );

  return (
    <AppLayout>
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8 space-y-2">
          <h1 className="text-3xl font-bold">{t.myLearning?.title || 'My Learning'}</h1>
          <p className="text-muted-foreground">
            {t.myLearning?.subtitle || 'Track your progress and access your certificates'}
          </p>
        </div>

        {/* Stats */}
        <div className="mb-8 grid gap-4 sm:grid-cols-3">
          <Card className="border-border/50 bg-card/50">
            <CardContent className="flex items-center gap-4 pt-6">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
                <BookOpen className="h-6 w-6 text-primary" />
              </div>
              <div>
                <p className="text-2xl font-bold">{enrollments?.length || 0}</p>
                <p className="text-sm text-muted-foreground">
                  {t.myLearning?.coursesEnrolled || 'Courses Enrolled'}
                </p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-border/50 bg-card/50">
            <CardContent className="flex items-center gap-4 pt-6">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-green-500/10">
                <Award className="h-6 w-6 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{certificates?.length || 0}</p>
                <p className="text-sm text-muted-foreground">
                  {t.myLearning?.certificatesEarned || 'Certificates Earned'}
                </p>
              </div>
            </CardContent>
          </Card>
          <Card className="border-border/50 bg-card/50">
            <CardContent className="flex items-center gap-4 pt-6">
              <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-amber-500/10">
                <Clock className="h-6 w-6 text-amber-500" />
              </div>
              <div>
                <p className="text-2xl font-bold">{inProgressEnrollments?.length || 0}</p>
                <p className="text-sm text-muted-foreground">
                  {t.myLearning?.inProgress || 'In Progress'}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : (
          <Tabs defaultValue="in-progress" className="space-y-6">
            <TabsList>
              <TabsTrigger value="in-progress">
                {t.myLearning?.inProgressTab || 'In Progress'} ({inProgressEnrollments?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="completed">
                {t.myLearning?.completedTab || 'Completed'} ({completedEnrollments?.length || 0})
              </TabsTrigger>
              <TabsTrigger value="certificates">
                {t.myLearning?.certificatesTab || 'Certificates'} ({certificates?.length || 0})
              </TabsTrigger>
            </TabsList>

            <TabsContent value="in-progress" className="space-y-4">
              {inProgressEnrollments?.length === 0 ? (
                <Card className="border-border/50 bg-card/50">
                  <CardContent className="py-12 text-center">
                    <BookOpen className="mx-auto h-12 w-12 text-muted-foreground" />
                    <h3 className="mt-4 text-lg font-medium">
                      {t.myLearning?.noCoursesInProgress || 'No courses in progress'}
                    </h3>
                    <p className="mt-2 text-muted-foreground">
                      {t.myLearning?.startLearning || 'Start learning something new today!'}
                    </p>
                    <Link to="/courses">
                      <Button className="mt-4">
                        {t.myLearning?.browseCourses || 'Browse Courses'}
                      </Button>
                    </Link>
                  </CardContent>
                </Card>
              ) : (
                inProgressEnrollments?.map((enrollment) => (
                  <Card key={enrollment.id} className="border-border/50 bg-card/50">
                    <CardContent className="flex items-center gap-6 py-6">
                      <div className="flex-1 space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="font-semibold">{enrollment.courses.title}</h3>
                          <Badge variant="outline">{enrollment.courses.category}</Badge>
                        </div>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between text-sm">
                            <span className="text-muted-foreground">
                              {t.courses?.progress || 'Progress'}
                            </span>
                            <span className="font-medium">{enrollment.progress_percent}%</span>
                          </div>
                          <Progress value={enrollment.progress_percent} className="h-2" />
                        </div>
                      </div>
                      <Link to={`/courses/${enrollment.course_id}`}>
                        <Button className="gap-2">
                          {t.courses?.continue || 'Continue'}
                          <ArrowRight className="h-4 w-4" />
                        </Button>
                      </Link>
                    </CardContent>
                  </Card>
                ))
              )}
            </TabsContent>

            <TabsContent value="completed" className="space-y-4">
              {completedEnrollments?.length === 0 ? (
                <Card className="border-border/50 bg-card/50">
                  <CardContent className="py-12 text-center">
                    <Award className="mx-auto h-12 w-12 text-muted-foreground" />
                    <h3 className="mt-4 text-lg font-medium">
                      {t.myLearning?.noCompletedCourses || 'No completed courses yet'}
                    </h3>
                    <p className="mt-2 text-muted-foreground">
                      {t.myLearning?.keepLearning || 'Keep learning to complete your first course!'}
                    </p>
                  </CardContent>
                </Card>
              ) : (
                completedEnrollments?.map((enrollment) => (
                  <Card key={enrollment.id} className="border-border/50 bg-card/50">
                    <CardContent className="flex items-center gap-6 py-6">
                      <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-green-500/10">
                        <Award className="h-6 w-6 text-green-500" />
                      </div>
                      <div className="flex-1">
                        <h3 className="font-semibold">{enrollment.courses.title}</h3>
                        <p className="text-sm text-muted-foreground">
                          {t.myLearning?.completedOn || 'Completed on'}{' '}
                          {new Date(enrollment.completed_at!).toLocaleDateString()}
                        </p>
                      </div>
                      <Link to={`/courses/${enrollment.course_id}`}>
                        <Button variant="outline">
                          {t.myLearning?.viewCourse || 'View Course'}
                        </Button>
                      </Link>
                    </CardContent>
                  </Card>
                ))
              )}
            </TabsContent>

            <TabsContent value="certificates" className="space-y-4">
              {certificates?.length === 0 ? (
                <Card className="border-border/50 bg-card/50">
                  <CardContent className="py-12 text-center">
                    <Award className="mx-auto h-12 w-12 text-muted-foreground" />
                    <h3 className="mt-4 text-lg font-medium">
                      {t.myLearning?.noCertificates || 'No certificates yet'}
                    </h3>
                    <p className="mt-2 text-muted-foreground">
                      {t.myLearning?.earnCertificates || 'Complete courses and pass quizzes to earn certificates!'}
                    </p>
                  </CardContent>
                </Card>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
                  {certificates?.map((cert: any) => (
                    <Card key={cert.id} className="border-border/50 bg-card/50">
                      <CardContent className="pt-6">
                        <div className="flex items-start gap-4">
                          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10">
                            <Award className="h-6 w-6 text-primary" />
                          </div>
                          <div className="flex-1">
                            <h3 className="font-semibold">{cert.courses?.title}</h3>
                            <p className="text-sm text-muted-foreground">
                              {t.certificate?.issuedOn || 'Issued on'}{' '}
                              {new Date(cert.issued_at).toLocaleDateString()}
                            </p>
                            {cert.quiz_score && (
                              <p className="text-sm text-muted-foreground">
                                {t.quiz?.score || 'Score'}: {cert.quiz_score}%
                              </p>
                            )}
                          </div>
                        </div>
                        <Link to={`/certificate/${cert.id}`} className="mt-4 block">
                          <Button variant="outline" className="w-full">
                            {t.certificate?.view || 'View Certificate'}
                          </Button>
                        </Link>
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>
          </Tabs>
        )}
      </div>
    </AppLayout>
  );
}
