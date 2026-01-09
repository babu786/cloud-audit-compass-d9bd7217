import { ReactNode, useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, BookOpen, Compass, HelpCircle, Terminal, BookText, Upload, LayoutDashboard, Home, GraduationCap, BookMarked } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ThemeToggle } from '@/components/ThemeToggle';
import { LanguageToggle } from '@/components/LanguageToggle';
import { MobileNav } from '@/components/layout/MobileNav';
import { useLanguage } from '@/i18n/LanguageContext';
import { useTheme } from 'next-themes';
import { useAdminAuth } from '@/hooks/useAdminAuth';
import { useFirebaseAuth } from '@/contexts/FirebaseAuthContext';
import { LoginButton } from '@/components/auth/LoginButton';
import { UserMenu } from '@/components/auth/UserMenu';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import logoLight from '@/assets/logo-light.png';
import logoDark from '@/assets/logo-dark.png';

interface AppLayoutProps {
  children: ReactNode;
}

export function AppLayout({ children }: AppLayoutProps) {
  const location = useLocation();
  const { t } = useLanguage();
  const { resolvedTheme } = useTheme();
  const { isAdmin } = useAdminAuth();
  const { user, loading: userLoading } = useFirebaseAuth();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Use correct logo based on theme - dark theme needs dark logo (white version), light theme needs light logo (black version)
  const currentLogo = mounted ? (resolvedTheme === 'dark' ? logoDark : logoLight) : logoLight;

  const navigation = user
    ? [
        { name: t.nav.home, href: '/', icon: Home },
        { name: t.nav.auditControls, href: '/audit', icon: Shield },
        { name: t.nav.guidedMode, href: '/guided', icon: Compass },
        { name: t.nav.cliCommands, href: '/cli', icon: Terminal },
        { name: t.nav.courses, href: '/courses', icon: GraduationCap },
        { name: t.nav.myLearning, href: '/my-learning', icon: BookMarked },
        { name: t.nav.awareness, href: '/awareness', icon: BookOpen },
        { name: t.nav.faq, href: '/faq', icon: HelpCircle },
        { name: t.nav.glossary, href: '/glossary', icon: BookText },
        ...(isAdmin ? [{ name: t.nav.admin, href: '/admin', icon: LayoutDashboard }] : []),
      ]
    : [
        { name: t.nav.home, href: '/', icon: Home },
        { name: t.nav.awareness, href: '/awareness', icon: BookOpen },
        { name: t.nav.faq, href: '/faq', icon: HelpCircle },
        { name: t.nav.glossary, href: '/glossary', icon: BookText },
      ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 glass border-b border-border/50">
        <div className="container flex h-16 items-center justify-between">
          <Link to="/" className="flex items-center gap-2 group min-w-fit">
            <div className="relative flex-shrink-0">
              <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full group-hover:bg-primary/30 transition-colors" />
              <img 
                src={currentLogo} 
                alt="BUGnBULL Logo" 
                className="h-10 w-10 relative object-cover scale-150"
              />
            </div>
            <div className="flex flex-col min-w-fit">
              <span className="text-base font-semibold tracking-tight whitespace-nowrap">{t.nav.cloudSecurity}</span>
              <span className="text-xs text-muted-foreground -mt-0.5 hidden xl:block whitespace-nowrap">{t.nav.auditGuidancePortal}</span>
            </div>
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden lg:flex items-center gap-1">
            <nav className="flex items-center gap-0.5">
              {navigation.map((item) => {
                const isActive = location.pathname === item.href;
                return (
                  <Tooltip key={item.href}>
                    <TooltipTrigger asChild>
                      <Link
                        to={item.href}
                        className={cn(
                          "relative flex items-center gap-1.5 px-2 py-1.5 rounded-lg text-sm font-medium transition-all duration-200 group",
                          isActive
                            ? "bg-primary/10 text-primary glow-sm"
                            : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                        )}
                      >
                        <item.icon className={cn(
                          "h-4 w-4 flex-shrink-0 transition-transform duration-200",
                          !isActive && "group-hover:scale-110 group-hover:rotate-3"
                        )} />
                        <span className="relative hidden xl:inline whitespace-nowrap">
                          {item.name}
                          {!isActive && (
                            <span className="absolute -bottom-0.5 left-0 w-0 h-0.5 bg-primary transition-all duration-200 group-hover:w-full" />
                          )}
                        </span>
                      </Link>
                    </TooltipTrigger>
                    <TooltipContent className="xl:hidden">
                      {item.name}
                    </TooltipContent>
                  </Tooltip>
                );
              })}
            </nav>
            <LanguageToggle />
            <ThemeToggle />
            {!userLoading && (user ? <UserMenu /> : <LoginButton />)}
          </div>

          {/* Mobile Navigation */}
          <MobileNav />
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
