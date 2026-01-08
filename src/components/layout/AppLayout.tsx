import { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, BookOpen, Compass } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ThemeToggle } from '@/components/ThemeToggle';

interface AppLayoutProps {
  children: ReactNode;
}

const navigation = [
  { name: 'Audit Controls', href: '/', icon: Shield },
  { name: 'Guided Mode', href: '/guided', icon: Compass },
  { name: 'Awareness', href: '/awareness', icon: BookOpen },
];

export function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 glass border-b border-border/50">
        <div className="container flex h-16 items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full group-hover:bg-primary/30 transition-colors" />
              <Shield className="h-8 w-8 text-primary relative" />
            </div>
            <div className="flex flex-col">
              <span className="text-lg font-semibold tracking-tight">Cloud Security</span>
              <span className="text-xs text-muted-foreground -mt-0.5">Audit Guidance Portal</span>
            </div>
          </Link>

          <div className="flex items-center gap-2">
            <nav className="flex items-center gap-1">
              {navigation.map((item) => {
                const isActive = location.pathname === item.href;
                return (
                  <Link
                    key={item.name}
                    to={item.href}
                    className={cn(
                      "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200",
                      isActive
                        ? "bg-primary/10 text-primary glow-sm"
                        : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                    )}
                  >
                    <item.icon className="h-4 w-4" />
                    {item.name}
                  </Link>
                );
              })}
            </nav>
            <ThemeToggle />
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative">
        {/* Background glow effect */}
        <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] pointer-events-none" 
             style={{ background: 'var(--gradient-glow)' }} />
        
        <div className="relative">
          {children}
        </div>
      </main>
    </div>
  );
}
