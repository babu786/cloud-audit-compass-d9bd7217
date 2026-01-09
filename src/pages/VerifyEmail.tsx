import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AppLayout } from '@/components/layout/AppLayout';
import { Loader2, Mail, CheckCircle, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';

export default function VerifyEmail() {
  const { user, loading, resendVerificationEmail } = useFirebaseAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && !user) {
      navigate('/login');
    }
  }, [user, loading, navigate]);

  useEffect(() => {
    if (user?.emailVerified) {
      navigate('/');
    }
  }, [user?.emailVerified, navigate]);

  // Periodic check for email verification
  useEffect(() => {
    if (!user || user.emailVerified) return;

    const interval = setInterval(async () => {
      await user.reload();
      if (user.emailVerified) {
        toast.success('Email verified successfully!');
        navigate('/');
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [user, navigate]);

  const handleResend = async () => {
    try {
      await resendVerificationEmail();
      toast.success('Verification email sent!');
    } catch (error) {
      toast.error('Failed to send verification email');
    }
  };

  if (loading) {
    return (
      <AppLayout>
        <div className="flex items-center justify-center min-h-[60vh]">
          <Loader2 className="w-8 h-8 animate-spin text-primary" />
        </div>
      </AppLayout>
    );
  }

  if (!user) {
    return null;
  }

  return (
    <AppLayout>
      <div className="flex items-center justify-center min-h-[60vh] px-4">
        <Card className="w-full max-w-md">
          <CardHeader className="text-center">
            <div className="mx-auto w-12 h-12 bg-primary/10 rounded-full flex items-center justify-center mb-4">
              <Mail className="w-6 h-6 text-primary" />
            </div>
            <CardTitle className="text-2xl">Verify Your Email</CardTitle>
            <CardDescription>
              We've sent a verification link to your email
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="text-center space-y-2">
              <p className="text-sm text-muted-foreground">
                Please check your inbox at:
              </p>
              <p className="font-medium">{user.email}</p>
            </div>

            <div className="flex items-center gap-2 p-3 bg-muted/50 rounded-lg">
              <RefreshCw className="w-4 h-4 text-muted-foreground animate-spin" />
              <span className="text-sm text-muted-foreground">
                Waiting for verification...
              </span>
            </div>

            <div className="space-y-2">
              <Button
                variant="outline"
                className="w-full"
                onClick={handleResend}
              >
                Resend Verification Email
              </Button>
              <Button
                variant="ghost"
                className="w-full"
                onClick={() => navigate('/')}
              >
                Continue without verifying
              </Button>
            </div>

            <p className="text-xs text-muted-foreground text-center">
              Didn't receive the email? Check your spam folder or click resend.
            </p>
          </CardContent>
        </Card>
      </div>
    </AppLayout>
  );
}
