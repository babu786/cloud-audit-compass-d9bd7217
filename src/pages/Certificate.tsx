import { useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Download, Share2, ArrowLeft, Loader2 } from 'lucide-react';
import { AppLayout } from '@/components/layout/AppLayout';
import { Button } from '@/components/ui/button';
import { CertificateView } from '@/components/certificate/CertificateView';
import { useCourse } from '@/hooks/useCourses';
import { useLanguage } from '@/i18n/LanguageContext';
import { supabase } from '@/integrations/supabase/client';
import { useQuery } from '@tanstack/react-query';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';
import { toast } from 'sonner';

export default function Certificate() {
  const { id } = useParams<{ id: string }>();
  const { t } = useLanguage();
  const { user } = useFirebaseAuth();
  const certificateRef = useRef<HTMLDivElement>(null);

  // Fetch certificate
  const { data: certificate, isLoading: certLoading } = useQuery({
    queryKey: ['certificate-detail', id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('certificates')
        .select('*')
        .eq('id', id!)
        .maybeSingle();

      if (error) throw error;
      return data;
    },
    enabled: !!id,
  });

  // Fetch user profile
  const { data: profile } = useQuery({
    queryKey: ['profile', certificate?.user_id],
    queryFn: async () => {
      const { data, error } = await supabase
        .from('profiles')
        .select('*')
        .eq('id', certificate!.user_id)
        .maybeSingle();

      if (error) throw error;
      return data;
    },
    enabled: !!certificate?.user_id,
  });

  const { data: course, isLoading: courseLoading } = useCourse(certificate?.course_id || '');

  const isLoading = certLoading || courseLoading;

  const handlePrint = () => {
    window.print();
  };

  const handleShare = async () => {
    const url = `${window.location.origin}/certificate/${certificate?.certificate_number}`;
    
    if (navigator.share) {
      try {
        await navigator.share({
          title: `${course?.title} Certificate`,
          text: `I earned a certificate for completing ${course?.title}!`,
          url,
        });
      } catch (error) {
        // User cancelled or error
      }
    } else {
      await navigator.clipboard.writeText(url);
      toast.success(t.certificate?.linkCopied || 'Certificate link copied to clipboard!');
    }
  };

  if (isLoading) {
    return (
      <AppLayout>
        <div className="flex min-h-[50vh] items-center justify-center">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
      </AppLayout>
    );
  }

  if (!certificate || !course) {
    return (
      <AppLayout>
        <div className="container mx-auto px-4 py-20 text-center">
          <h2 className="text-2xl font-bold">
            {t.certificate?.notFound || 'Certificate not found'}
          </h2>
          <Link to="/my-learning">
            <Button className="mt-4">
              {t.myLearning?.backToLearning || 'Back to My Learning'}
            </Button>
          </Link>
        </div>
      </AppLayout>
    );
  }

  const userName = profile?.full_name || profile?.email || user?.displayName || user?.email || 'Student';

  return (
    <AppLayout>
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
          <Link
            to="/my-learning"
            className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" />
            {t.myLearning?.backToLearning || 'Back to My Learning'}
          </Link>

          <div className="flex items-center gap-3">
            <Button variant="outline" onClick={handleShare} className="gap-2">
              <Share2 className="h-4 w-4" />
              {t.certificate?.share || 'Share'}
            </Button>
            <Button onClick={handlePrint} className="gap-2">
              <Download className="h-4 w-4" />
              {t.certificate?.download || 'Download'}
            </Button>
          </div>
        </div>

        {/* Certificate */}
        <div className="mx-auto max-w-4xl">
          <CertificateView
            ref={certificateRef}
            userName={userName}
            courseName={course.title}
            certificateNumber={certificate.certificate_number}
            issuedAt={certificate.issued_at}
            quizScore={certificate.quiz_score}
          />
        </div>

        {/* Verification Info */}
        <div className="mx-auto mt-8 max-w-lg text-center">
          <p className="text-sm text-muted-foreground">
            {t.certificate?.verificationNote ||
              'This certificate can be verified by sharing the URL or certificate number.'}
          </p>
        </div>
      </div>
    </AppLayout>
  );
}
