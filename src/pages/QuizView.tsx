import { useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Loader2, Clock } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { QuizQuestion } from '@/components/quiz/QuizQuestion';
import { QuizResults } from '@/components/quiz/QuizResults';
import { useCourse, useEnrollment } from '@/hooks/useCourses';
import { useQuiz, useQuizQuestions, useQuizAttempts, useSubmitQuiz } from '@/hooks/useQuiz';
import { useLanguage } from '@/i18n/LanguageContext';
import { toast } from 'sonner';

export default function QuizView() {
  const { courseId } = useParams<{ courseId: string }>();
  const navigate = useNavigate();
  const { t } = useLanguage();

  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const [showResults, setShowResults] = useState(false);
  const [results, setResults] = useState<{
    score: number;
    maxScore: number;
    percentage: number;
    passed: boolean;
    certificateId?: string;
  } | null>(null);

  const { data: course, isLoading: courseLoading } = useCourse(courseId!);
  const { data: enrollment } = useEnrollment(courseId!);
  const { data: quiz, isLoading: quizLoading } = useQuiz(courseId!);
  const { data: questions, isLoading: questionsLoading } = useQuizQuestions(quiz?.id || '');
  const { data: attempts } = useQuizAttempts(enrollment?.id || '', quiz?.id || '');
  const submitQuiz = useSubmitQuiz();

  const isLoading = courseLoading || quizLoading || questionsLoading;

  if (isLoading) {
    return (
      <AppLayout>
        <div className="flex min-h-[50vh] items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </AppLayout>
    );
  }

  if (!course || !quiz || !questions || questions.length === 0) {
    return (
      <AppLayout>
        <div className="container mx-auto px-4 py-20 text-center">
          <h2 className="text-2xl font-bold">{t.quiz?.notFound || 'Quiz not found'}</h2>
          <Link to={`/courses/${courseId}`}>
            <Button className="mt-4">{t.courses?.backToCourse || 'Back to Course'}</Button>
          </Link>
        </div>
      </AppLayout>
    );
  }

  const currentQuestion = questions[currentQuestionIndex];
  const progressPercent = ((currentQuestionIndex + 1) / questions.length) * 100;
  const attemptsUsed = attempts?.length || 0;

  const handleAnswer = (answer: string) => {
    setAnswers((prev) => ({ ...prev, [currentQuestion.id]: answer }));
  };

  const handleNext = () => {
    if (currentQuestionIndex < questions.length - 1) {
      setCurrentQuestionIndex((prev) => prev + 1);
    }
  };

  const handlePrevious = () => {
    if (currentQuestionIndex > 0) {
      setCurrentQuestionIndex((prev) => prev - 1);
    }
  };

  const handleSubmit = async () => {
    if (!enrollment) {
      toast.error('Not enrolled in this course');
      return;
    }

    try {
      const result = await submitQuiz.mutateAsync({
        enrollmentId: enrollment.id,
        quizId: quiz.id,
        courseId: courseId!,
        answers,
        questions,
        passingScore: course.passing_score,
      });

      setResults({
        score: result.score,
        maxScore: result.maxScore,
        percentage: result.percentage,
        passed: result.passed,
        certificateId: result.certificate?.id,
      });
      setShowResults(true);
    } catch (error) {
      toast.error(t.quiz?.submitError || 'Failed to submit quiz');
    }
  };

  const handleRetry = () => {
    setAnswers({});
    setCurrentQuestionIndex(0);
    setShowResults(false);
    setResults(null);
  };

  if (showResults && results) {
    return (
      <AppLayout>
        <div className="container mx-auto px-4 py-12">
          <QuizResults
            score={results.score}
            maxScore={results.maxScore}
            percentage={results.percentage}
            passed={results.passed}
            passingScore={course.passing_score}
            attemptsUsed={attemptsUsed + 1}
            maxAttempts={quiz.max_attempts}
            certificateId={results.certificateId}
            courseId={courseId!}
            onRetry={handleRetry}
          />
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="container mx-auto max-w-3xl px-4 py-8">
        {/* Header */}
        <div className="mb-6 space-y-4">
          <Link
            to={`/courses/${courseId}`}
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" />
            {t.courses?.backToCourse || 'Back to Course'}
          </Link>

          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold">{quiz.title}</h1>
              <p className="text-muted-foreground">{course.title}</p>
            </div>
            {quiz.time_limit_minutes && (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Clock className="h-4 w-4" />
                {quiz.time_limit_minutes} {t.courses?.minutes || 'min'}
              </div>
            )}
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">
                {t.quiz?.question || 'Question'} {currentQuestionIndex + 1} {t.courses?.of || 'of'} {questions.length}
              </span>
              <span className="text-muted-foreground">
                {Object.keys(answers).length} / {questions.length} {t.quiz?.answered || 'answered'}
              </span>
            </div>
            <Progress value={progressPercent} className="h-2" />
          </div>
        </div>

        {/* Question */}
        <QuizQuestion
          question={currentQuestion}
          questionNumber={currentQuestionIndex + 1}
          totalQuestions={questions.length}
          selectedAnswer={answers[currentQuestion.id] || null}
          onAnswerChange={handleAnswer}
        />

        {/* Navigation */}
        <div className="mt-6 flex items-center justify-between">
          <Button
            variant="outline"
            onClick={handlePrevious}
            disabled={currentQuestionIndex === 0}
            className="gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            {t.quiz?.previous || 'Previous'}
          </Button>

          {currentQuestionIndex === questions.length - 1 ? (
            <Button
              onClick={handleSubmit}
              disabled={submitQuiz.isPending || Object.keys(answers).length !== questions.length}
              className="gap-2"
            >
              {submitQuiz.isPending ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : null}
              {t.quiz?.submit || 'Submit Quiz'}
            </Button>
          ) : (
            <Button
              onClick={handleNext}
              disabled={!answers[currentQuestion.id]}
              className="gap-2"
            >
              {t.quiz?.next || 'Next'}
              <ArrowRight className="h-4 w-4" />
            </Button>
          )}
        </div>

        {/* Question Navigator */}
        <div className="mt-8 flex flex-wrap justify-center gap-2">
          {questions.map((q, index) => {
            const isAnswered = !!answers[q.id];
            const isCurrent = index === currentQuestionIndex;

            return (
              <button
                key={q.id}
                onClick={() => setCurrentQuestionIndex(index)}
                className={`flex h-8 w-8 items-center justify-center rounded-full text-sm font-medium transition-colors ${
                  isCurrent
                    ? 'bg-primary text-primary-foreground'
                    : isAnswered
                    ? 'bg-green-500 text-white'
                    : 'bg-muted hover:bg-muted/80'
                }`}
              >
                {index + 1}
              </button>
            );
          })}
        </div>
      </div>
    </AppLayout>
  );
}
