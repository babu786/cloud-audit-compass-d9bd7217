-- STEP 3: Create new permissive RLS policies for Firebase Auth

-- Courses - anyone can view published courses
CREATE POLICY "Anyone can view published courses" ON courses FOR SELECT USING (is_published = true);

-- Lessons - anyone can view lessons for published courses
CREATE POLICY "Anyone can view lessons" ON lessons FOR SELECT USING (
  EXISTS (SELECT 1 FROM courses WHERE courses.id = lessons.course_id AND courses.is_published = true)
);

-- Quizzes - anyone can view quizzes for published courses
CREATE POLICY "Anyone can view quizzes" ON quizzes FOR SELECT USING (
  EXISTS (SELECT 1 FROM courses WHERE courses.id = quizzes.course_id AND courses.is_published = true)
);

-- Quiz questions - anyone can view quiz questions for published courses
CREATE POLICY "Anyone can view quiz questions" ON quiz_questions FOR SELECT USING (
  EXISTS (
    SELECT 1 FROM quizzes 
    JOIN courses ON courses.id = quizzes.course_id 
    WHERE quizzes.id = quiz_questions.quiz_id AND courses.is_published = true
  )
);

-- Enrollments - permissive policies (user ownership checked in app)
CREATE POLICY "Allow select enrollments" ON enrollments FOR SELECT USING (true);
CREATE POLICY "Allow insert enrollments" ON enrollments FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow update enrollments" ON enrollments FOR UPDATE USING (true);

-- Lesson progress - permissive policies
CREATE POLICY "Allow select lesson_progress" ON lesson_progress FOR SELECT USING (true);
CREATE POLICY "Allow insert lesson_progress" ON lesson_progress FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow update lesson_progress" ON lesson_progress FOR UPDATE USING (true);

-- Quiz attempts - permissive policies
CREATE POLICY "Allow select quiz_attempts" ON quiz_attempts FOR SELECT USING (true);
CREATE POLICY "Allow insert quiz_attempts" ON quiz_attempts FOR INSERT WITH CHECK (true);

-- Certificates - permissive policies
CREATE POLICY "Allow select certificates" ON certificates FOR SELECT USING (true);
CREATE POLICY "Allow insert certificates" ON certificates FOR INSERT WITH CHECK (true);

-- Profiles - permissive policies
CREATE POLICY "Allow select profiles" ON profiles FOR SELECT USING (true);
CREATE POLICY "Allow insert profiles" ON profiles FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow update profiles" ON profiles FOR UPDATE USING (true);

-- User roles - permissive policies
CREATE POLICY "Allow select user_roles" ON user_roles FOR SELECT USING (true);
CREATE POLICY "Allow insert user_roles" ON user_roles FOR INSERT WITH CHECK (true);