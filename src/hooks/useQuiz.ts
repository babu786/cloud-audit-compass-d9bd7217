import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';

export interface Quiz {
  id: string;
  course_id: string;
  title: string;
  description: string | null;
  time_limit_minutes: number | null;
  max_attempts: number;
  created_at: string;
}

export interface QuizQuestion {
  id: string;
  quiz_id: string;
  question_text: string;
  question_type: string;
  options: string[];
  correct_answer: string;
  explanation: string | null;
  points: number;
  order_index: number;
}

export interface QuizAttempt {
  id: string;
  enrollment_id: string;
  quiz_id: string;
  score: number;
  max_score: number;
  percentage: number;
  passed: boolean;
  answers: Record<string, string> | null;
  started_at: string;
  completed_at: string;
}

export interface Certificate {
  id: string;
  enrollment_id: string;
  user_id: string;
  course_id: string;
  certificate_number: string;
  quiz_score: number | null;
  issued_at: string;
}

export function useQuiz(courseId: string) {
  return useQuery({
    queryKey: ['quiz', courseId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('quizzes')
        .select('*')
        .eq('course_id', courseId)
        .maybeSingle();

      if (error) throw error;
      return data as Quiz | null;
    },
    enabled: !!courseId,
  });
}

export function useQuizQuestions(quizId: string) {
  return useQuery({
    queryKey: ['quiz_questions', quizId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('quiz_questions')
        .select('*')
        .eq('quiz_id', quizId)
        .order('order_index', { ascending: true });

      if (error) throw error;
      return data as QuizQuestion[];
    },
    enabled: !!quizId,
  });
}

export function useQuizAttempts(enrollmentId: string, quizId: string) {
  return useQuery({
    queryKey: ['quiz_attempts', enrollmentId, quizId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('quiz_attempts')
        .select('*')
        .eq('enrollment_id', enrollmentId)
        .eq('quiz_id', quizId)
        .order('completed_at', { ascending: false });

      if (error) throw error;
      return data as QuizAttempt[];
    },
    enabled: !!enrollmentId && !!quizId,
  });
}

export function useCertificate(enrollmentId: string) {
  return useQuery({
    queryKey: ['certificate', enrollmentId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('certificates')
        .select('*')
        .eq('enrollment_id', enrollmentId)
        .maybeSingle();

      if (error) throw error;
      return data as Certificate | null;
    },
    enabled: !!enrollmentId,
  });
}

export function useCertificates() {
  const { user } = useFirebaseAuth();

  return useQuery({
    queryKey: ['certificates', user?.uid],
    queryFn: async () => {
      if (!user) return [];

      const { data, error } = await supabase
        .from('certificates')
        .select('*, courses(*)')
        .eq('user_id', user.uid)
        .order('issued_at', { ascending: false });

      if (error) throw error;
      return data;
    },
    enabled: !!user,
  });
}

export function useCertificateByNumber(certificateNumber: string) {
  return useQuery({
    queryKey: ['certificate_verify', certificateNumber],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('certificates')
        .select('*, courses(*), profiles!certificates_user_id_fkey(*)')
        .eq('certificate_number', certificateNumber)
        .maybeSingle();

      if (error) throw error;
      return data;
    },
    enabled: !!certificateNumber,
  });
}

export function useSubmitQuiz() {
  const queryClient = useQueryClient();
  const { user } = useFirebaseAuth();

  return useMutation({
    mutationFn: async ({
      enrollmentId,
      quizId,
      courseId,
      answers,
      questions,
      passingScore,
    }: {
      enrollmentId: string;
      quizId: string;
      courseId: string;
      answers: Record<string, string>;
      questions: QuizQuestion[];
      passingScore: number;
    }) => {
      if (!user) throw new Error('Not authenticated');

      // Calculate score
      let score = 0;
      let maxScore = 0;

      questions.forEach((question) => {
        maxScore += question.points;
        if (answers[question.id] === question.correct_answer) {
          score += question.points;
        }
      });

      const percentage = Math.round((score / maxScore) * 100);
      const passed = percentage >= passingScore;

      // Insert quiz attempt
      const { data: attempt, error: attemptError } = await supabase
        .from('quiz_attempts')
        .insert({
          enrollment_id: enrollmentId,
          quiz_id: quizId,
          score,
          max_score: maxScore,
          percentage,
          passed,
          answers,
        })
        .select()
        .single();

      if (attemptError) throw attemptError;

      // If passed, create certificate
      let certificate = null;
      if (passed) {
        // Generate unique certificate number
        const certNumber = `CERT-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`;

        const { data: cert, error: certError } = await supabase
          .from('certificates')
          .insert({
            enrollment_id: enrollmentId,
            user_id: user.uid,
            course_id: courseId,
            certificate_number: certNumber,
            quiz_score: percentage,
          })
          .select()
          .single();

        if (certError && !certError.message.includes('duplicate')) {
          throw certError;
        }

        certificate = cert;

        // Update enrollment status
        await supabase
          .from('enrollments')
          .update({
            status: 'completed',
            completed_at: new Date().toISOString(),
          })
          .eq('id', enrollmentId);
      }

      return { attempt, certificate, passed, percentage, score, maxScore };
    },
    onSuccess: (_, { enrollmentId, quizId, courseId }) => {
      queryClient.invalidateQueries({ queryKey: ['quiz_attempts', enrollmentId, quizId] });
      queryClient.invalidateQueries({ queryKey: ['certificate', enrollmentId] });
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
      queryClient.invalidateQueries({ queryKey: ['enrollment', courseId] });
      queryClient.invalidateQueries({ queryKey: ['enrollments'] });
    },
  });
}
