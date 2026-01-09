-- Create courses table
CREATE TABLE public.courses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  description TEXT,
  category TEXT NOT NULL CHECK (category IN ('AWS', 'Azure', 'GCP', 'General')),
  difficulty TEXT NOT NULL CHECK (difficulty IN ('Beginner', 'Intermediate', 'Advanced')),
  thumbnail_url TEXT,
  duration_minutes INTEGER DEFAULT 0,
  is_published BOOLEAN DEFAULT true,
  passing_score INTEGER DEFAULT 70,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Create lessons table
CREATE TABLE public.lessons (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id UUID REFERENCES public.courses(id) ON DELETE CASCADE NOT NULL,
  title TEXT NOT NULL,
  content TEXT,
  order_index INTEGER NOT NULL,
  duration_minutes INTEGER DEFAULT 5,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Create enrollments table
CREATE TABLE public.enrollments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  course_id UUID REFERENCES public.courses(id) ON DELETE CASCADE NOT NULL,
  progress_percent INTEGER DEFAULT 0,
  status TEXT DEFAULT 'enrolled' CHECK (status IN ('enrolled', 'in_progress', 'completed')),
  enrolled_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ,
  UNIQUE(user_id, course_id)
);

-- Create lesson_progress table
CREATE TABLE public.lesson_progress (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enrollment_id UUID REFERENCES public.enrollments(id) ON DELETE CASCADE NOT NULL,
  lesson_id UUID REFERENCES public.lessons(id) ON DELETE CASCADE NOT NULL,
  is_completed BOOLEAN DEFAULT false,
  completed_at TIMESTAMPTZ,
  UNIQUE(enrollment_id, lesson_id)
);

-- Create quizzes table
CREATE TABLE public.quizzes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id UUID REFERENCES public.courses(id) ON DELETE CASCADE NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT,
  time_limit_minutes INTEGER,
  max_attempts INTEGER DEFAULT 3,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Create quiz_questions table
CREATE TABLE public.quiz_questions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  quiz_id UUID REFERENCES public.quizzes(id) ON DELETE CASCADE NOT NULL,
  question_text TEXT NOT NULL,
  question_type TEXT DEFAULT 'multiple_choice' CHECK (question_type IN ('multiple_choice', 'true_false')),
  options JSONB NOT NULL,
  correct_answer TEXT NOT NULL,
  explanation TEXT,
  points INTEGER DEFAULT 1,
  order_index INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Create quiz_attempts table
CREATE TABLE public.quiz_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enrollment_id UUID REFERENCES public.enrollments(id) ON DELETE CASCADE NOT NULL,
  quiz_id UUID REFERENCES public.quizzes(id) ON DELETE CASCADE NOT NULL,
  score INTEGER NOT NULL,
  max_score INTEGER NOT NULL,
  percentage INTEGER NOT NULL,
  passed BOOLEAN NOT NULL,
  answers JSONB,
  started_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ DEFAULT now()
);

-- Create certificates table
CREATE TABLE public.certificates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  enrollment_id UUID REFERENCES public.enrollments(id) ON DELETE CASCADE NOT NULL UNIQUE,
  user_id UUID NOT NULL,
  course_id UUID REFERENCES public.courses(id) ON DELETE CASCADE NOT NULL,
  certificate_number TEXT UNIQUE NOT NULL,
  quiz_score INTEGER,
  issued_at TIMESTAMPTZ DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE public.courses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lessons ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lesson_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quizzes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quiz_questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quiz_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificates ENABLE ROW LEVEL SECURITY;

-- RLS Policies for courses (public read for authenticated users)
CREATE POLICY "Authenticated users can view published courses"
ON public.courses FOR SELECT
TO authenticated
USING (is_published = true);

-- RLS Policies for lessons (public read for authenticated users)
CREATE POLICY "Authenticated users can view lessons"
ON public.lessons FOR SELECT
TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.courses 
  WHERE courses.id = lessons.course_id 
  AND courses.is_published = true
));

-- RLS Policies for enrollments
CREATE POLICY "Users can view their own enrollments"
ON public.enrollments FOR SELECT
TO authenticated
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own enrollments"
ON public.enrollments FOR INSERT
TO authenticated
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update their own enrollments"
ON public.enrollments FOR UPDATE
TO authenticated
USING (auth.uid() = user_id);

-- RLS Policies for lesson_progress
CREATE POLICY "Users can view their own lesson progress"
ON public.lesson_progress FOR SELECT
TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.enrollments 
  WHERE enrollments.id = lesson_progress.enrollment_id 
  AND enrollments.user_id = auth.uid()
));

CREATE POLICY "Users can create their own lesson progress"
ON public.lesson_progress FOR INSERT
TO authenticated
WITH CHECK (EXISTS (
  SELECT 1 FROM public.enrollments 
  WHERE enrollments.id = lesson_progress.enrollment_id 
  AND enrollments.user_id = auth.uid()
));

CREATE POLICY "Users can update their own lesson progress"
ON public.lesson_progress FOR UPDATE
TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.enrollments 
  WHERE enrollments.id = lesson_progress.enrollment_id 
  AND enrollments.user_id = auth.uid()
));

-- RLS Policies for quizzes (public read for authenticated users)
CREATE POLICY "Authenticated users can view quizzes"
ON public.quizzes FOR SELECT
TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.courses 
  WHERE courses.id = quizzes.course_id 
  AND courses.is_published = true
));

-- RLS Policies for quiz_questions (public read for authenticated users)
CREATE POLICY "Authenticated users can view quiz questions"
ON public.quiz_questions FOR SELECT
TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.quizzes 
  JOIN public.courses ON courses.id = quizzes.course_id
  WHERE quizzes.id = quiz_questions.quiz_id 
  AND courses.is_published = true
));

-- RLS Policies for quiz_attempts
CREATE POLICY "Users can view their own quiz attempts"
ON public.quiz_attempts FOR SELECT
TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.enrollments 
  WHERE enrollments.id = quiz_attempts.enrollment_id 
  AND enrollments.user_id = auth.uid()
));

CREATE POLICY "Users can create their own quiz attempts"
ON public.quiz_attempts FOR INSERT
TO authenticated
WITH CHECK (EXISTS (
  SELECT 1 FROM public.enrollments 
  WHERE enrollments.id = quiz_attempts.enrollment_id 
  AND enrollments.user_id = auth.uid()
));

-- RLS Policies for certificates
CREATE POLICY "Users can view their own certificates"
ON public.certificates FOR SELECT
TO authenticated
USING (auth.uid() = user_id);

CREATE POLICY "Users can create their own certificates"
ON public.certificates FOR INSERT
TO authenticated
WITH CHECK (auth.uid() = user_id);

-- Public can view certificates for verification
CREATE POLICY "Anyone can view certificates by number"
ON public.certificates FOR SELECT
USING (true);

-- Create updated_at trigger for courses
CREATE TRIGGER update_courses_updated_at
BEFORE UPDATE ON public.courses
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Create indexes for better performance
CREATE INDEX idx_lessons_course_id ON public.lessons(course_id);
CREATE INDEX idx_enrollments_user_id ON public.enrollments(user_id);
CREATE INDEX idx_enrollments_course_id ON public.enrollments(course_id);
CREATE INDEX idx_lesson_progress_enrollment_id ON public.lesson_progress(enrollment_id);
CREATE INDEX idx_quiz_questions_quiz_id ON public.quiz_questions(quiz_id);
CREATE INDEX idx_quiz_attempts_enrollment_id ON public.quiz_attempts(enrollment_id);
CREATE INDEX idx_certificates_user_id ON public.certificates(user_id);
CREATE INDEX idx_certificates_certificate_number ON public.certificates(certificate_number);