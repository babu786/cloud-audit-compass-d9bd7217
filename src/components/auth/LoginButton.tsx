import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';
import { LogIn } from 'lucide-react';

export function LoginButton() {
  const navigate = useNavigate();

  return (
    <Button
      onClick={() => navigate('/login')}
      variant="outline"
      size="sm"
      className="gap-2"
    >
      <LogIn className="h-4 w-4" />
      <span className="hidden sm:inline">Login</span>
    </Button>
  );
}
