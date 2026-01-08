import { ReactNode } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, BookOpen, Compass, HelpCircle, Terminal } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ThemeToggle } from '@/components/ThemeToggle';
import { LanguageToggle } from '@/components/LanguageToggle';
import { useLanguage } from '@/i18n/LanguageContext';

interface AppLayoutProps {
  children: ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();
  const { t } = useLanguage();

  const navigation = [
    { name: t.nav.auditControls, href: '/', icon: Shield },
    { name: t.nav.guidedMode, href: '/guided', icon: Compass },
    { name: t.nav.awareness, href: '/awareness', icon: BookOpen },
    { name: t.nav.faq, href: '/faq', icon: HelpCircle },
    { name: t.nav.cliCommands, href: '/cli', icon: Terminal },
  ];

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
              <span className="text-lg font-semibold tracking-tight">{t.nav.cloudSecurity}</span>
              <span className="text-xs text-muted-foreground -mt-0.5">{t.nav.auditGuidancePortal}</span>
            </div>
          </Link>

          <div className="flex items-center gap-2">
            <nav className="flex items-center gap-1">
              {navigation.map((item) => {
                const isActive = location.pathname === item.href;
                return (
                  <Link
                    key={item.href}
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
            <LanguageToggle />
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
