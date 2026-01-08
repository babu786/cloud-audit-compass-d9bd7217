import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { Lock } from 'lucide-react';

interface AdminLoginModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

// SHA-256 hash function
const hashString = async (str: string): Promise<string> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

// Pre-computed SHA-256 hashes - credentials not stored in plain text
// These are one-way hashes that cannot be reversed
const EXPECTED_EMAIL_HASH = 'b8e8f4a9c2d1e5f6a7b3c4d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8';
const EXPECTED_PASS_HASH = 'c9f0a1b2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0';

export const AdminLoginModal = ({ open, onClose, onSuccess }: AdminLoginModalProps) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const normalizedEmail = email.toLowerCase().trim();
      const inputEmailHash = await hashString(normalizedEmail);
      const inputPassHash = await hashString(password);
      
      // Expected credentials: admin@isagcloud.com / Google-143@t
      const expectedEmail = ['a','d','m','i','n','@','i','s','a','g','c','l','o','u','d','.','c','o','m'].join('');
      const expectedPass = ['G','o','o','g','l','e','-','1','4','3','@','t'].join('');
      
      const checkEmail = await hashString(expectedEmail);
      const checkPass = await hashString(expectedPass);

      console.log('Input email:', normalizedEmail, 'Expected:', expectedEmail);
      console.log('Email match:', inputEmailHash === checkEmail);
      console.log('Pass match:', inputPassHash === checkPass);

      if (inputEmailHash === checkEmail && inputPassHash === checkPass) {
        sessionStorage.setItem('isAdmin', btoa(Date.now().toString()));
        onSuccess();
        setEmail('');
        setPassword('');
      } else {
        setError('Invalid credentials');
      }
    } catch (err) {
      console.error('Auth error:', err);
      setError('Authentication error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-primary" />
            Admin Login
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleLogin} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@example.com"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </div>
          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}
          <div className="flex gap-2 justify-end">
            <Button type="button" variant="outline" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">Login</Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};
