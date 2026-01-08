import { useTheme } from 'next-themes';
import { Button } from '@/components/ui/button';
import { useEffect, useState } from 'react';

export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [isAnimating, setIsAnimating] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <Button variant="ghost" size="icon" className="h-9 w-9 relative overflow-hidden">
        <div className="w-4 h-4 rounded-full bg-muted-foreground" />
      </Button>
    );
  }

  const handleThemeChange = () => {
    setIsAnimating(true);
    setTimeout(() => {
      setTheme(theme === 'dark' ? 'light' : 'dark');
    }, 150);
    setTimeout(() => setIsAnimating(false), 500);
  };

  const isDark = theme === 'dark';

  return (
    <Button
      variant="ghost"
      size="icon"
      className="h-9 w-9 relative overflow-hidden group"
      onClick={handleThemeChange}
    >
      {/* Sun */}
      <div
        className={`absolute inset-0 flex items-center justify-center transition-all duration-500 ${
          isDark 
            ? 'opacity-100 rotate-0 scale-100' 
            : 'opacity-0 -rotate-90 scale-50'
        }`}
      >
        <div className="relative">
          {/* Sun rays */}
          <div className={`absolute inset-0 ${isAnimating ? 'animate-spin' : ''}`} style={{ animationDuration: '0.5s' }}>
            {[...Array(8)].map((_, i) => (
              <div
                key={i}
                className="absolute w-0.5 h-1 bg-amber-400 rounded-full"
                style={{
                  top: '50%',
                  left: '50%',
                  transformOrigin: '0 0',
                  transform: `rotate(${i * 45}deg) translateY(-8px) translateX(-1px)`,
                }}
              />
            ))}
          </div>
          {/* Sun center */}
          <div className="w-4 h-4 rounded-full bg-amber-400 shadow-[0_0_12px_rgba(251,191,36,0.6)] group-hover:shadow-[0_0_16px_rgba(251,191,36,0.8)] transition-shadow" />
        </div>
      </div>

      {/* Moon */}
      <div
        className={`absolute inset-0 flex items-center justify-center transition-all duration-500 ${
          isDark 
            ? 'opacity-0 rotate-90 scale-50' 
            : 'opacity-100 rotate-0 scale-100'
        }`}
      >
        <div className="relative">
          {/* Moon */}
          <div className="w-4 h-4 rounded-full bg-slate-300 shadow-[0_0_12px_rgba(148,163,184,0.6)] group-hover:shadow-[0_0_16px_rgba(148,163,184,0.8)] transition-shadow relative overflow-hidden">
            {/* Moon crater */}
            <div className="absolute top-0.5 right-0 w-3 h-3 rounded-full bg-slate-800/90" />
          </div>
          {/* Stars */}
          <div className={`absolute -top-1 -right-1 w-1 h-1 rounded-full bg-slate-300 ${isDark ? 'opacity-0' : 'opacity-100 animate-pulse'}`} style={{ animationDuration: '2s' }} />
          <div className={`absolute -bottom-0.5 -left-1.5 w-0.5 h-0.5 rounded-full bg-slate-300 ${isDark ? 'opacity-0' : 'opacity-100 animate-pulse'}`} style={{ animationDuration: '1.5s', animationDelay: '0.5s' }} />
          <div className={`absolute top-0 -left-2 w-0.5 h-0.5 rounded-full bg-slate-300 ${isDark ? 'opacity-0' : 'opacity-100 animate-pulse'}`} style={{ animationDuration: '2.5s', animationDelay: '1s' }} />
        </div>
      </div>

      <span className="sr-only">Toggle theme</span>
    </Button>
  );
}
