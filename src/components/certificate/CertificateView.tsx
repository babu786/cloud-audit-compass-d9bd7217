import { forwardRef, useState, useEffect } from 'react';
import { Award, CheckCircle } from 'lucide-react';
import { useLanguage } from '@/i18n/LanguageContext';
import { useTheme } from 'next-themes';
import logoLight from '@/assets/logo-light.png';
import logoDark from '@/assets/logo-dark.png';

interface CertificateViewProps {
  userName: string;
  courseName: string;
  certificateNumber: string;
  issuedAt: string;
  quizScore?: number | null;
}

export const CertificateView = forwardRef<HTMLDivElement, CertificateViewProps>(
  ({ userName, courseName, certificateNumber, issuedAt, quizScore }, ref) => {
    const { t } = useLanguage();
    const { resolvedTheme } = useTheme();
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
      setMounted(true);
    }, []);

    const currentLogo = mounted
      ? resolvedTheme === 'dark'
        ? logoDark
        : logoLight
      : logoLight;

    const formattedDate = new Date(issuedAt).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });

    return (
      <div
        ref={ref}
        className="relative aspect-[1.414] w-full overflow-hidden rounded-lg border-4 border-primary/20 bg-gradient-to-br from-background via-background to-muted p-8 shadow-2xl print:border-0 print:shadow-none"
        style={{ minHeight: '500px' }}
      >
        {/* Decorative elements */}
        <div className="absolute left-0 top-0 h-32 w-32 rounded-br-full bg-primary/5" />
        <div className="absolute bottom-0 right-0 h-32 w-32 rounded-tl-full bg-primary/5" />
        <div className="absolute left-1/2 top-0 h-1 w-1/3 -translate-x-1/2 bg-gradient-to-r from-transparent via-primary to-transparent" />
        <div className="absolute bottom-0 left-1/2 h-1 w-1/3 -translate-x-1/2 bg-gradient-to-r from-transparent via-primary to-transparent" />

        <div className="relative z-10 flex h-full flex-col items-center justify-between py-4 text-center">
          {/* Header */}
          <div className="flex items-center gap-3">
            <img src={currentLogo} alt="Logo" className="h-10" />
            <span className="text-xl font-bold">Cloud Security Hub</span>
          </div>

          {/* Title */}
          <div className="space-y-2">
            <div className="flex items-center justify-center gap-2">
              <Award className="h-8 w-8 text-primary" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight md:text-4xl">
              {t.certificate?.title || 'Certificate of Completion'}
            </h1>
            <p className="text-muted-foreground">
              {t.certificate?.subtitle || 'This is to certify that'}
            </p>
          </div>

          {/* Recipient */}
          <div className="space-y-4">
            <h2 className="text-3xl font-bold text-primary md:text-4xl">
              {userName || 'Student'}
            </h2>
            <p className="max-w-md text-muted-foreground">
              {t.certificate?.hasCompleted || 'has successfully completed the course'}
            </p>
            <h3 className="text-xl font-semibold md:text-2xl">{courseName}</h3>
            {quizScore && (
              <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground">
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span>Quiz Score: {quizScore}%</span>
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="w-full space-y-4">
            <div className="flex items-center justify-center gap-8 text-sm text-muted-foreground">
              <div>
                <p className="font-medium text-foreground">{formattedDate}</p>
                <p>{t.certificate?.dateIssued || 'Date Issued'}</p>
              </div>
              <div className="h-8 w-px bg-border" />
              <div>
                <p className="font-mono text-xs font-medium text-foreground">
                  {certificateNumber}
                </p>
                <p>{t.certificate?.certificateId || 'Certificate ID'}</p>
              </div>
            </div>
            <p className="text-xs text-muted-foreground">
              {t.certificate?.verifyAt || 'Verify at'}:{' '}
              <span className="font-mono">
                {window.location.origin}/certificate/{certificateNumber}
              </span>
            </p>
          </div>
        </div>
      </div>
    );
  }
);

CertificateView.displayName = 'CertificateView';
