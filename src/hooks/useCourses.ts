import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';

export interface Course {
  id: string;
  title: string;
  description: string | null;
  category: string;
  difficulty: string;
  thumbnail_url: string | null;
  duration_minutes: number;
  is_published: boolean;
  passing_score: number;
  created_at: string;
  updated_at: string;
}

export interface Lesson {
  id: string;
  course_id: string;
  title: string;
  content: string | null;
  order_index: number;
  duration_minutes: number;
  created_at: string;
}

export interface Enrollment {
  id: string;
  user_id: string;
  course_id: string;
  progress_percent: number;
  status: string;
  enrolled_at: string;
  completed_at: string | null;
}

export interface LessonProgress {
  id: string;
  enrollment_id: string;
  lesson_id: string;
  is_completed: boolean;
  completed_at: string | null;
}

export function useCourses(category?: string, difficulty?: string) {
  return useQuery({
    queryKey: ['courses', category, difficulty],
    queryFn: async () => {
      let query = supabase
        .from('courses')
        .select('*')
        .eq('is_published', true)
        .order('created_at', { ascending: false });

      if (category && category !== 'all') {
        query = query.eq('category', category);
      }
      if (difficulty && difficulty !== 'all') {
        query = query.eq('difficulty', difficulty);
      }

      const { data, error } = await query;
      if (error) throw error;
      return data as Course[];
    },
  });
}

export function useCourse(courseId: string) {
  return useQuery({
    queryKey: ['course', courseId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('courses')
        .select('*')
        .eq('id', courseId)
        .maybeSingle();

      if (error) throw error;
      return data as Course | null;
    },
    enabled: !!courseId,
  });
}

export function useLessons(courseId: string) {
  return useQuery({
    queryKey: ['lessons', courseId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('lessons')
        .select('*')
        .eq('course_id', courseId)
        .order('order_index', { ascending: true });

      if (error) throw error;
      return data as Lesson[];
    },
    enabled: !!courseId,
  });
}

export function useEnrollment(courseId: string) {
  const { user } = useFirebaseAuth();

  return useQuery({
    queryKey: ['enrollment', courseId, user?.uid],
    queryFn: async () => {
      if (!user) return null;

      const { data, error } = await supabase
        .from('enrollments')
        .select('*')
        .eq('course_id', courseId)
        .eq('user_id', user.uid)
        .maybeSingle();

      if (error) throw error;
      return data as Enrollment | null;
    },
    enabled: !!courseId && !!user,
  });
}

export function useEnrollments() {
  const { user } = useFirebaseAuth();

  return useQuery({
    queryKey: ['enrollments', user?.uid],
    queryFn: async () => {
      if (!user) return [];

      const { data, error } = await supabase
        .from('enrollments')
        .select('*, courses(*)')
        .eq('user_id', user.uid)
        .order('enrolled_at', { ascending: false });

      if (error) throw error;
      return data as (Enrollment & { courses: Course })[];
    },
    enabled: !!user,
  });
}

export function useLessonProgress(enrollmentId: string) {
  return useQuery({
    queryKey: ['lesson_progress', enrollmentId],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('lesson_progress')
        .select('*')
        .eq('enrollment_id', enrollmentId);

      if (error) throw error;
      return data as LessonProgress[];
    },
    enabled: !!enrollmentId,
  });
}

export function useEnrollMutation() {
  const queryClient = useQueryClient();
  const { user } = useFirebaseAuth();

  return useMutation({
    mutationFn: async (courseId: string) => {
      if (!user) throw new Error('Not authenticated');

      const { data, error } = await supabase
        .from('enrollments')
        .insert({
          user_id: user.uid,
          course_id: courseId,
        })
        .select()
        .single();

      if (error) throw error;
      return data;
    },
    onSuccess: (_, courseId) => {
      queryClient.invalidateQueries({ queryKey: ['enrollment', courseId] });
      queryClient.invalidateQueries({ queryKey: ['enrollments'] });
    },
  });
}

export function useMarkLessonComplete() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async ({
      enrollmentId,
      lessonId,
      courseId,
      totalLessons,
    }: {
      enrollmentId: string;
      lessonId: string;
      courseId: string;
      totalLessons: number;
    }) => {
      // Insert or update lesson progress
      const { error: progressError } = await supabase
        .from('lesson_progress')
        .upsert({
          enrollment_id: enrollmentId,
          lesson_id: lessonId,
          is_completed: true,
          completed_at: new Date().toISOString(),
        });

      if (progressError) throw progressError;

      // Get completed lessons count
      const { data: completedLessons, error: countError } = await supabase
        .from('lesson_progress')
        .select('id')
        .eq('enrollment_id', enrollmentId)
        .eq('is_completed', true);

      if (countError) throw countError;

      // Calculate progress percentage
      const progressPercent = Math.round(
        ((completedLessons?.length || 0) / totalLessons) * 100
      );

      // Update enrollment progress
      const { error: enrollmentError } = await supabase
        .from('enrollments')
        .update({
          progress_percent: progressPercent,
          status: progressPercent === 100 ? 'completed' : 'in_progress',
        })
        .eq('id', enrollmentId);

      if (enrollmentError) throw enrollmentError;

      return { progressPercent };
    },
    onSuccess: (_, { enrollmentId, courseId }) => {
      queryClient.invalidateQueries({ queryKey: ['lesson_progress', enrollmentId] });
      queryClient.invalidateQueries({ queryKey: ['enrollment', courseId] });
      queryClient.invalidateQueries({ queryKey: ['enrollments'] });
    },
  });
}
