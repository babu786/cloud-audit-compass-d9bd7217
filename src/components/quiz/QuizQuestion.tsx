import { cn } from '@/lib/utils';
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import type { QuizQuestion as QuizQuestionType } from '@/hooks/useQuiz';

interface QuizQuestionProps {
  question: QuizQuestionType;
  questionNumber: number;
  totalQuestions: number;
  selectedAnswer: string | null;
  onAnswerChange: (answer: string) => void;
  showResult?: boolean;
}

export function QuizQuestion({
  question,
  questionNumber,
  totalQuestions,
  selectedAnswer,
  onAnswerChange,
  showResult = false,
}: QuizQuestionProps) {
  const options = question.options as string[];
  const correctAnswer = question.correct_answer;
  const isCorrect = selectedAnswer === correctAnswer;

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">
            Question {questionNumber} of {totalQuestions}
          </span>
          <span className="text-sm font-medium">
            {question.points} {question.points === 1 ? 'point' : 'points'}
          </span>
        </div>
        <h3 className="text-lg font-semibold leading-tight">
          {question.question_text}
        </h3>
      </CardHeader>
      <CardContent>
        <RadioGroup
          value={selectedAnswer || ''}
          onValueChange={onAnswerChange}
          disabled={showResult}
          className="space-y-3"
        >
          {options.map((option, index) => {
            const value = index.toString();
            const isSelected = selectedAnswer === value;
            const isCorrectOption = value === correctAnswer;

            return (
              <div
                key={index}
                className={cn(
                  'flex items-center space-x-3 rounded-lg border p-4 transition-colors',
                  showResult && isCorrectOption && 'border-green-500 bg-green-500/10',
                  showResult && isSelected && !isCorrectOption && 'border-red-500 bg-red-500/10',
                  !showResult && isSelected && 'border-primary bg-primary/5',
                  !showResult && !isSelected && 'hover:border-muted-foreground/30 hover:bg-muted/50'
                )}
              >
                <RadioGroupItem value={value} id={`option-${index}`} />
                <Label
                  htmlFor={`option-${index}`}
                  className="flex-1 cursor-pointer text-sm font-medium"
                >
                  {option}
                </Label>
              </div>
            );
          })}
        </RadioGroup>

        {showResult && question.explanation && (
          <div
            className={cn(
              'mt-4 rounded-lg p-4',
              isCorrect ? 'bg-green-500/10' : 'bg-amber-500/10'
            )}
          >
            <p className="text-sm font-medium">
              {isCorrect ? '✓ Correct!' : '✗ Incorrect'}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {question.explanation}
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
