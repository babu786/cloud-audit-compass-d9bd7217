-- =============================================
-- BUGNBULL - CLOUD SECURITY TRAINING PLATFORM
-- COMPLETE DATABASE SETUP
-- =============================================
-- Version: 1.0.0
-- Last Updated: 2025-01-09
-- 
-- INSTRUCTIONS:
-- 1. Create a new Supabase project at https://supabase.com
-- 2. Go to SQL Editor in your Supabase dashboard
-- 3. Run this entire file first
-- 4. Then run database-seed.sql to populate with sample data
-- 5. Copy your Project URL and anon key to your .env file
-- =============================================

-- =============================================
-- SECTION 1: CUSTOM TYPES (ENUMS)
-- =============================================

-- Create enum for user roles
DO $$ BEGIN
    CREATE TYPE public.app_role AS ENUM ('admin', 'user');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- =============================================
-- SECTION 2: UTILITY FUNCTIONS
-- =============================================

-- Function to automatically update 'updated_at' timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Security definer function to check user roles
-- This prevents infinite recursion in RLS policies
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role app_role)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.user_roles
        WHERE user_id = _user_id
          AND role = _role
    )
$$;

-- =============================================
-- SECTION 3: TABLES
-- =============================================

-- ---------------------------------------------
-- 3.1 PROFILES TABLE
-- Stores user profile information
-- Note: id is TEXT to store Firebase UIDs
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id TEXT PRIMARY KEY,
    email TEXT,
    full_name TEXT,
    avatar_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.profiles IS 'User profile information synced from Firebase Auth';
COMMENT ON COLUMN public.profiles.id IS 'Firebase UID (stored as TEXT)';

-- ---------------------------------------------
-- 3.2 USER ROLES TABLE
-- Stores user role assignments
-- Note: user_id is TEXT to store Firebase UIDs
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    role app_role NOT NULL DEFAULT 'user',
    UNIQUE (user_id, role)
);

COMMENT ON TABLE public.user_roles IS 'User role assignments for access control';
COMMENT ON COLUMN public.user_roles.role IS 'User role: admin or user';

-- ---------------------------------------------
-- 3.3 COURSES TABLE
-- Stores training course information
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.courses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title TEXT NOT NULL,
    description TEXT,
    category TEXT NOT NULL,
    difficulty TEXT NOT NULL,
    duration_minutes INTEGER DEFAULT 0,
    thumbnail_url TEXT,
    passing_score INTEGER DEFAULT 70,
    is_published BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

COMMENT ON TABLE public.courses IS 'Cloud security training courses';
COMMENT ON COLUMN public.courses.difficulty IS 'Course difficulty: Beginner, Intermediate, Advanced';
COMMENT ON COLUMN public.courses.passing_score IS 'Minimum percentage score to pass the course quiz';

-- ---------------------------------------------
-- 3.4 LESSONS TABLE
-- Stores course lesson content
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.lessons (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    content TEXT,
    order_index INTEGER NOT NULL,
    duration_minutes INTEGER DEFAULT 5,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

COMMENT ON TABLE public.lessons IS 'Individual lessons within courses';
COMMENT ON COLUMN public.lessons.order_index IS 'Display order of lesson within course';
COMMENT ON COLUMN public.lessons.content IS 'Lesson content in Markdown format';

-- ---------------------------------------------
-- 3.5 ENROLLMENTS TABLE
-- Tracks user course enrollments
-- Note: user_id is TEXT to store Firebase UIDs
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.enrollments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'enrolled',
    progress_percent INTEGER DEFAULT 0,
    enrolled_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (user_id, course_id)
);

COMMENT ON TABLE public.enrollments IS 'User course enrollments and progress';
COMMENT ON COLUMN public.enrollments.status IS 'Enrollment status: enrolled, in_progress, completed';
COMMENT ON COLUMN public.enrollments.progress_percent IS 'Course completion percentage (0-100)';

-- ---------------------------------------------
-- 3.6 LESSON PROGRESS TABLE
-- Tracks individual lesson completion
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.lesson_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enrollment_id UUID NOT NULL REFERENCES public.enrollments(id) ON DELETE CASCADE,
    lesson_id UUID NOT NULL REFERENCES public.lessons(id) ON DELETE CASCADE,
    is_completed BOOLEAN DEFAULT false,
    completed_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (enrollment_id, lesson_id)
);

COMMENT ON TABLE public.lesson_progress IS 'Individual lesson completion tracking';

-- ---------------------------------------------
-- 3.7 QUIZZES TABLE
-- Stores quiz metadata for courses
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.quizzes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    description TEXT,
    time_limit_minutes INTEGER,
    max_attempts INTEGER DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

COMMENT ON TABLE public.quizzes IS 'Course assessment quizzes';
COMMENT ON COLUMN public.quizzes.time_limit_minutes IS 'Time limit in minutes (NULL = no limit)';
COMMENT ON COLUMN public.quizzes.max_attempts IS 'Maximum number of quiz attempts allowed';

-- ---------------------------------------------
-- 3.8 QUIZ QUESTIONS TABLE
-- Stores individual quiz questions
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.quiz_questions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    quiz_id UUID NOT NULL REFERENCES public.quizzes(id) ON DELETE CASCADE,
    question_text TEXT NOT NULL,
    question_type TEXT DEFAULT 'multiple_choice',
    options JSONB NOT NULL,
    correct_answer TEXT NOT NULL,
    explanation TEXT,
    points INTEGER DEFAULT 1,
    order_index INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

COMMENT ON TABLE public.quiz_questions IS 'Individual quiz questions';
COMMENT ON COLUMN public.quiz_questions.options IS 'JSON array of answer options';
COMMENT ON COLUMN public.quiz_questions.correct_answer IS 'The correct answer text';
COMMENT ON COLUMN public.quiz_questions.explanation IS 'Explanation shown after answering';

-- ---------------------------------------------
-- 3.9 QUIZ ATTEMPTS TABLE
-- Records user quiz attempts
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.quiz_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enrollment_id UUID NOT NULL REFERENCES public.enrollments(id) ON DELETE CASCADE,
    quiz_id UUID NOT NULL REFERENCES public.quizzes(id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    max_score INTEGER NOT NULL,
    percentage INTEGER NOT NULL,
    passed BOOLEAN NOT NULL,
    answers JSONB,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

COMMENT ON TABLE public.quiz_attempts IS 'User quiz attempt records';
COMMENT ON COLUMN public.quiz_attempts.answers IS 'JSON object of question_id: user_answer';
COMMENT ON COLUMN public.quiz_attempts.passed IS 'Whether the user passed the quiz';

-- ---------------------------------------------
-- 3.10 CERTIFICATES TABLE
-- Stores issued course certificates
-- Note: user_id is TEXT to store Firebase UIDs
-- ---------------------------------------------
CREATE TABLE IF NOT EXISTS public.certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    course_id UUID NOT NULL REFERENCES public.courses(id) ON DELETE CASCADE,
    enrollment_id UUID NOT NULL REFERENCES public.enrollments(id) ON DELETE CASCADE,
    certificate_number TEXT NOT NULL UNIQUE,
    quiz_score INTEGER,
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

COMMENT ON TABLE public.certificates IS 'Issued course completion certificates';
COMMENT ON COLUMN public.certificates.certificate_number IS 'Unique certificate identifier for verification';

-- =============================================
-- SECTION 4: ENABLE ROW LEVEL SECURITY
-- =============================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.courses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lessons ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.enrollments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.lesson_progress ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quizzes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quiz_questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.quiz_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.certificates ENABLE ROW LEVEL SECURITY;

-- =============================================
-- SECTION 5: ROW LEVEL SECURITY POLICIES
-- =============================================

-- Note: These policies use permissive access because 
-- Firebase Auth handles authentication, not Supabase Auth.
-- The application validates Firebase tokens before making requests.

-- ---------------------------------------------
-- 5.1 PROFILES POLICIES
-- ---------------------------------------------
CREATE POLICY "Allow select profiles" ON public.profiles
    FOR SELECT USING (true);

CREATE POLICY "Allow insert profiles" ON public.profiles
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow update profiles" ON public.profiles
    FOR UPDATE USING (true);

-- ---------------------------------------------
-- 5.2 USER ROLES POLICIES
-- ---------------------------------------------
CREATE POLICY "Allow select user_roles" ON public.user_roles
    FOR SELECT USING (true);

CREATE POLICY "Allow insert user_roles" ON public.user_roles
    FOR INSERT WITH CHECK (true);

-- ---------------------------------------------
-- 5.3 COURSES POLICIES
-- ---------------------------------------------
CREATE POLICY "Anyone can view published courses" ON public.courses
    FOR SELECT USING (is_published = true);

-- ---------------------------------------------
-- 5.4 LESSONS POLICIES
-- ---------------------------------------------
CREATE POLICY "Anyone can view lessons" ON public.lessons
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM public.courses 
            WHERE courses.id = lessons.course_id 
            AND courses.is_published = true
        )
    );

-- ---------------------------------------------
-- 5.5 ENROLLMENTS POLICIES
-- ---------------------------------------------
CREATE POLICY "Allow select enrollments" ON public.enrollments
    FOR SELECT USING (true);

CREATE POLICY "Allow insert enrollments" ON public.enrollments
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow update enrollments" ON public.enrollments
    FOR UPDATE USING (true);

-- ---------------------------------------------
-- 5.6 LESSON PROGRESS POLICIES
-- ---------------------------------------------
CREATE POLICY "Allow select lesson_progress" ON public.lesson_progress
    FOR SELECT USING (true);

CREATE POLICY "Allow insert lesson_progress" ON public.lesson_progress
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Allow update lesson_progress" ON public.lesson_progress
    FOR UPDATE USING (true);

-- ---------------------------------------------
-- 5.7 QUIZZES POLICIES
-- ---------------------------------------------
CREATE POLICY "Anyone can view quizzes" ON public.quizzes
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM public.courses 
            WHERE courses.id = quizzes.course_id 
            AND courses.is_published = true
        )
    );

-- ---------------------------------------------
-- 5.8 QUIZ QUESTIONS POLICIES
-- ---------------------------------------------
CREATE POLICY "Anyone can view quiz questions" ON public.quiz_questions
    FOR SELECT USING (
        EXISTS (
            SELECT 1 FROM public.quizzes
            JOIN public.courses ON courses.id = quizzes.course_id
            WHERE quizzes.id = quiz_questions.quiz_id 
            AND courses.is_published = true
        )
    );

-- ---------------------------------------------
-- 5.9 QUIZ ATTEMPTS POLICIES
-- ---------------------------------------------
CREATE POLICY "Allow select quiz_attempts" ON public.quiz_attempts
    FOR SELECT USING (true);

CREATE POLICY "Allow insert quiz_attempts" ON public.quiz_attempts
    FOR INSERT WITH CHECK (true);

-- ---------------------------------------------
-- 5.10 CERTIFICATES POLICIES
-- ---------------------------------------------
CREATE POLICY "Allow select certificates" ON public.certificates
    FOR SELECT USING (true);

CREATE POLICY "Allow insert certificates" ON public.certificates
    FOR INSERT WITH CHECK (true);

-- =============================================
-- SECTION 6: PERFORMANCE INDEXES
-- =============================================

-- Lessons indexes
CREATE INDEX IF NOT EXISTS idx_lessons_course_id ON public.lessons(course_id);
CREATE INDEX IF NOT EXISTS idx_lessons_order ON public.lessons(course_id, order_index);

-- Enrollments indexes
CREATE INDEX IF NOT EXISTS idx_enrollments_user_id ON public.enrollments(user_id);
CREATE INDEX IF NOT EXISTS idx_enrollments_course_id ON public.enrollments(course_id);
CREATE INDEX IF NOT EXISTS idx_enrollments_status ON public.enrollments(status);

-- Lesson progress indexes
CREATE INDEX IF NOT EXISTS idx_lesson_progress_enrollment_id ON public.lesson_progress(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_lesson_progress_lesson_id ON public.lesson_progress(lesson_id);

-- Quizzes indexes
CREATE INDEX IF NOT EXISTS idx_quizzes_course_id ON public.quizzes(course_id);

-- Quiz questions indexes
CREATE INDEX IF NOT EXISTS idx_quiz_questions_quiz_id ON public.quiz_questions(quiz_id);
CREATE INDEX IF NOT EXISTS idx_quiz_questions_order ON public.quiz_questions(quiz_id, order_index);

-- Quiz attempts indexes
CREATE INDEX IF NOT EXISTS idx_quiz_attempts_enrollment_id ON public.quiz_attempts(enrollment_id);
CREATE INDEX IF NOT EXISTS idx_quiz_attempts_quiz_id ON public.quiz_attempts(quiz_id);

-- Certificates indexes
CREATE INDEX IF NOT EXISTS idx_certificates_user_id ON public.certificates(user_id);
CREATE INDEX IF NOT EXISTS idx_certificates_course_id ON public.certificates(course_id);
CREATE INDEX IF NOT EXISTS idx_certificates_number ON public.certificates(certificate_number);

-- User roles indexes
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON public.user_roles(user_id);

-- =============================================
-- SECTION 7: TRIGGERS
-- =============================================

-- Trigger to auto-update 'updated_at' on profiles
DROP TRIGGER IF EXISTS update_profiles_updated_at ON public.profiles;
CREATE TRIGGER update_profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

-- Trigger to auto-update 'updated_at' on courses
DROP TRIGGER IF EXISTS update_courses_updated_at ON public.courses;
CREATE TRIGGER update_courses_updated_at
    BEFORE UPDATE ON public.courses
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

-- =============================================
-- SECTION 8: ADMIN USER SETUP
-- =============================================

-- To create an admin user, run this after a user signs up:
-- Replace 'FIREBASE_USER_ID' with the actual Firebase UID

-- UPDATE public.user_roles 
-- SET role = 'admin' 
-- WHERE user_id = 'FIREBASE_USER_ID';

-- Or insert a new admin role:
-- INSERT INTO public.user_roles (user_id, role) 
-- VALUES ('FIREBASE_USER_ID', 'admin')
-- ON CONFLICT (user_id, role) DO NOTHING;

-- =============================================
-- SETUP COMPLETE!
-- =============================================
-- 
-- Next steps:
-- 1. Run database-seed.sql to populate courses, lessons, and quizzes
-- 2. Update your .env file with Supabase credentials
-- 3. Update src/lib/firebase.ts with your Firebase config
-- 4. Start the development server: npm run dev
--
-- =============================================
