-- STEP 1: Drop ALL policies that reference user_id or auth.uid() first

-- Certificates
DROP POLICY IF EXISTS "Anyone can view certificates by number" ON certificates;
DROP POLICY IF EXISTS "Users can create their own certificates" ON certificates;
DROP POLICY IF EXISTS "Users can view their own certificates" ON certificates;

-- Enrollments
DROP POLICY IF EXISTS "Users can create their own enrollments" ON enrollments;
DROP POLICY IF EXISTS "Users can update their own enrollments" ON enrollments;
DROP POLICY IF EXISTS "Users can view their own enrollments" ON enrollments;

-- Lesson progress
DROP POLICY IF EXISTS "Users can create their own lesson progress" ON lesson_progress;
DROP POLICY IF EXISTS "Users can update their own lesson progress" ON lesson_progress;
DROP POLICY IF EXISTS "Users can view their own lesson progress" ON lesson_progress;

-- Profiles
DROP POLICY IF EXISTS "Users can insert their own profile" ON profiles;
DROP POLICY IF EXISTS "Users can update their own profile" ON profiles;
DROP POLICY IF EXISTS "Users can view their own profile" ON profiles;

-- Quiz attempts
DROP POLICY IF EXISTS "Users can create their own quiz attempts" ON quiz_attempts;
DROP POLICY IF EXISTS "Users can view their own quiz attempts" ON quiz_attempts;

-- User roles
DROP POLICY IF EXISTS "System can insert roles" ON user_roles;
DROP POLICY IF EXISTS "Users can view their own roles" ON user_roles;

-- Courses, lessons, quizzes, quiz_questions
DROP POLICY IF EXISTS "Authenticated users can view published courses" ON courses;
DROP POLICY IF EXISTS "Authenticated users can view lessons" ON lessons;
DROP POLICY IF EXISTS "Authenticated users can view quizzes" ON quizzes;
DROP POLICY IF EXISTS "Authenticated users can view quiz questions" ON quiz_questions;