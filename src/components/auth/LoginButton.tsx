import { Button } from '@/components/ui/button';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';
import { LogIn } from 'lucide-react';
import { toast } from 'sonner';

export function LoginButton() {
  const { signInWithGoogle, loading } = useFirebaseAuth();

  const handleLogin = async () => {
    try {
      await signInWithGoogle();
    } catch (error) {
      toast.error('Login failed. Please try again.');
      console.error('Login error:', error);
    }
  };

  return (
    <Button
      onClick={handleLogin}
      disabled={loading}
      variant="outline"
      size="sm"
      className="gap-2"
    >
      <LogIn className="h-4 w-4" />
      <span className="hidden sm:inline">Login with Google</span>
      <span className="sm:hidden">Login</span>
    </Button>
  );
}
