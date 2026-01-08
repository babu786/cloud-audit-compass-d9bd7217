import { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Menu, X, Shield, BookOpen, FileText, HelpCircle, Terminal, ClipboardCheck } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ThemeToggle } from '@/components/ThemeToggle';
import { LanguageToggle } from '@/components/LanguageToggle';
import { useLanguage } from '@/i18n/LanguageContext';

export function MobileNav() {
  const [isOpen, setIsOpen] = useState(false);
  const location = useLocation();
  const { t } = useLanguage();

  const navItems = [
    { path: '/', label: t.nav.auditControls, icon: Shield },
    { path: '/guided', label: t.nav.guidedMode, icon: ClipboardCheck },
    { path: '/awareness', label: t.nav.awareness, icon: BookOpen },
    { path: '/glossary', label: t.nav.glossary, icon: FileText },
    { path: '/faq', label: t.nav.faq, icon: HelpCircle },
    { path: '/cli', label: t.nav.cliCommands, icon: Terminal },
  ];

  return (
    <div className="md:hidden">
      <button
        onClick={() => setIsOpen(true)}
        className="p-2 rounded-lg hover:bg-secondary/50 transition-colors"
        aria-label="Open menu"
      >
        <Menu className="h-6 w-6" />
      </button>

      {/* Backdrop */}
      <div
        className={cn(
          "fixed inset-0 bg-background/80 backdrop-blur-sm z-50 transition-opacity duration-300",
          isOpen ? "opacity-100" : "opacity-0 pointer-events-none"
        )}
        onClick={() => setIsOpen(false)}
      />

      {/* Drawer */}
      <div
        className={cn(
          "fixed top-0 left-0 h-full w-[280px] bg-card border-r border-border z-50 transition-transform duration-300 ease-out",
          isOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        <div className="flex flex-col h-full">
          {/* Header */}
          <div className="flex items-center justify-between p-4 border-b border-border">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-primary/10">
                <Shield className="h-5 w-5 text-primary" />
              </div>
              <span className="font-semibold">Cloud Security</span>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="p-2 rounded-lg hover:bg-secondary/50 transition-colors"
              aria-label="Close menu"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
            {navItems.map((item, index) => {
              const isActive = location.pathname === item.path;
              const Icon = item.icon;
              
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setIsOpen(false)}
                  className={cn(
                    "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200",
                    "transform",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "hover:bg-secondary/50 text-muted-foreground hover:text-foreground"
                  )}
                  style={{
                    animation: isOpen ? `slide-in-left 0.3s ease-out ${index * 50}ms forwards` : 'none',
                    opacity: isOpen ? 1 : 0,
                  }}
                >
                  <Icon className={cn("h-5 w-5", isActive && "text-primary")} />
                  <span className="font-medium">{item.label}</span>
                  {isActive && (
                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-primary" />
                  )}
                </Link>
              );
            })}
          </nav>

          {/* Footer */}
          <div className="p-4 border-t border-border">
            <div className="flex items-center justify-center gap-4">
              <ThemeToggle />
              <LanguageToggle />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
