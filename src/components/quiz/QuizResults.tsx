import { Link } from 'react-router-dom';
import { Award, CheckCircle, XCircle, RotateCcw, Download } from 'lucide-react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { useLanguage } from '@/i18n/LanguageContext';

interface QuizResultsProps {
  score: number;
  maxScore: number;
  percentage: number;
  passed: boolean;
  passingScore: number;
  attemptsUsed: number;
  maxAttempts: number;
  certificateId?: string | null;
  courseId: string;
  onRetry?: () => void;
}

export function QuizResults({
  score,
  maxScore,
  percentage,
  passed,
  passingScore,
  attemptsUsed,
  maxAttempts,
  certificateId,
  courseId,
  onRetry,
}: QuizResultsProps) {
  const { t } = useLanguage();
  const canRetry = !passed && attemptsUsed < maxAttempts;

  return (
    <Card className="mx-auto max-w-lg border-border/50 bg-card/50 backdrop-blur-sm">
      <CardHeader className="text-center">
        <div className={`mx-auto mb-4 flex h-20 w-20 items-center justify-center rounded-full ${
          passed ? 'bg-green-500/10' : 'bg-red-500/10'
        }`}>
          {passed ? (
            <CheckCircle className="h-10 w-10 text-green-500" />
          ) : (
            <XCircle className="h-10 w-10 text-red-500" />
          )}
        </div>
        <h2 className="text-2xl font-bold">
          {passed
            ? t.quiz?.passed || 'Congratulations! You Passed!'
            : t.quiz?.failed || 'You Did Not Pass'}
        </h2>
        <p className="text-muted-foreground">
          {passed
            ? t.quiz?.passedMessage || 'You have successfully completed the quiz.'
            : t.quiz?.failedMessage || 'Keep learning and try again.'}
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">{t.quiz?.yourScore || 'Your Score'}</span>
            <span className="font-semibold">{percentage}%</span>
          </div>
          <Progress
            value={percentage}
            className={`h-3 ${passed ? '[&>div]:bg-green-500' : '[&>div]:bg-red-500'}`}
          />
          <div className="flex items-center justify-between text-sm text-muted-foreground">
            <span>{score} / {maxScore} {t.quiz?.points || 'points'}</span>
            <span>{t.quiz?.passingScore || 'Passing'}: {passingScore}%</span>
          </div>
        </div>

        {!passed && (
          <div className="rounded-lg bg-muted/50 p-4 text-center text-sm">
            <p className="text-muted-foreground">
              {t.quiz?.attemptsRemaining || 'Attempts remaining'}:{' '}
              <span className="font-medium text-foreground">
                {maxAttempts - attemptsUsed} / {maxAttempts}
              </span>
            </p>
          </div>
        )}

        <div className="flex flex-col gap-3">
          {passed && certificateId && (
            <Link to={`/certificate/${certificateId}`}>
              <Button className="w-full gap-2" size="lg">
                <Award className="h-5 w-5" />
                {t.quiz?.viewCertificate || 'View Certificate'}
              </Button>
            </Link>
          )}

          {canRetry && onRetry && (
            <Button onClick={onRetry} variant="outline" className="w-full gap-2" size="lg">
              <RotateCcw className="h-5 w-5" />
              {t.quiz?.retryQuiz || 'Retry Quiz'}
            </Button>
          )}

          <Link to={`/courses/${courseId}`}>
            <Button variant="ghost" className="w-full">
              {t.quiz?.backToCourse || 'Back to Course'}
            </Button>
          </Link>
        </div>
      </CardContent>
    </Card>
  );
}
