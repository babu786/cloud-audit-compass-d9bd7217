import { useEffect, useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Keyboard, Search, X, Home, BookOpen, HelpCircle, Terminal } from 'lucide-react';

interface ShortcutGroup {
  title: string;
  icon: React.ElementType;
  shortcuts: { keys: string[]; description: string }[];
}

const shortcutGroups: ShortcutGroup[] = [
  {
    title: 'Navigation',
    icon: Home,
    shortcuts: [
      { keys: ['g', 'h'], description: 'Go to Home' },
      { keys: ['g', 'a'], description: 'Go to Awareness' },
      { keys: ['g', 'g'], description: 'Go to Glossary' },
      { keys: ['g', 'f'], description: 'Go to FAQ' },
      { keys: ['g', 'c'], description: 'Go to CLI Commands' },
    ],
  },
  {
    title: 'Actions',
    icon: Search,
    shortcuts: [
      { keys: ['/'], description: 'Focus search' },
      { keys: ['Esc'], description: 'Close modal / Clear search' },
      { keys: ['?'], description: 'Show this help' },
    ],
  },
];

export function KeyboardShortcutsModal() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    let pendingKey: string | null = null;
    let pendingTimeout: NodeJS.Timeout | null = null;

    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if typing in an input
      const target = e.target as HTMLElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) {
        return;
      }

      // Show shortcuts modal
      if (e.key === '?') {
        e.preventDefault();
        setOpen(true);
        return;
      }

      // Close modal with Escape
      if (e.key === 'Escape') {
        setOpen(false);
        return;
      }

      // Focus search with /
      if (e.key === '/') {
        e.preventDefault();
        const searchInput = document.querySelector('input[type="text"], input[type="search"]') as HTMLInputElement;
        if (searchInput) {
          searchInput.focus();
        }
        return;
      }

      // Two-key shortcuts (g + letter)
      if (e.key === 'g' && !pendingKey) {
        pendingKey = 'g';
        pendingTimeout = setTimeout(() => {
          pendingKey = null;
        }, 1000);
        return;
      }

      if (pendingKey === 'g') {
        if (pendingTimeout) clearTimeout(pendingTimeout);
        pendingKey = null;

        const routes: Record<string, string> = {
          'h': '/',
          'a': '/awareness',
          'g': '/glossary',
          'f': '/faq',
          'c': '/cli',
        };

        const route = routes[e.key];
        if (route) {
          e.preventDefault();
          window.location.href = route;
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      if (pendingTimeout) clearTimeout(pendingTimeout);
    };
  }, []);

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogContent className="sm:max-w-md glass border-primary/20">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <Keyboard className="h-5 w-5 text-primary" />
            Keyboard Shortcuts
          </DialogTitle>
        </DialogHeader>
        
        <div className="space-y-6 py-4">
          {shortcutGroups.map((group) => {
            const Icon = group.icon;
            return (
              <div key={group.title}>
                <h3 className="flex items-center gap-2 text-sm font-medium text-muted-foreground mb-3">
                  <Icon className="h-4 w-4" />
                  {group.title}
                </h3>
                <div className="space-y-2">
                  {group.shortcuts.map((shortcut) => (
                    <div 
                      key={shortcut.description}
                      className="flex items-center justify-between py-1.5"
                    >
                      <span className="text-sm text-foreground">{shortcut.description}</span>
                      <div className="flex items-center gap-1">
                        {shortcut.keys.map((key, i) => (
                          <span key={i} className="flex items-center gap-1">
                            <kbd className="px-2 py-1 text-xs font-mono bg-muted border border-border rounded-md shadow-sm min-w-[24px] text-center">
                              {key}
                            </kbd>
                            {i < shortcut.keys.length - 1 && (
                              <span className="text-muted-foreground text-xs">then</span>
                            )}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        <div className="pt-4 border-t border-border/50">
          <p className="text-xs text-muted-foreground text-center">
            Press <kbd className="px-1.5 py-0.5 text-xs font-mono bg-muted border border-border rounded">?</kbd> anywhere to show this help
          </p>
        </div>
      </DialogContent>
    </Dialog>
  );
}
