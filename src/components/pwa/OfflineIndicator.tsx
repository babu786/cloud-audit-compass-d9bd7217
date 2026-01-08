import { useState, useEffect, useContext } from 'react';
import { WifiOff, X } from 'lucide-react';
import { LanguageContext } from '@/i18n/LanguageContext';

export const OfflineIndicator = () => {
  const [isOffline, setIsOffline] = useState(!navigator.onLine);
  const [isDismissed, setIsDismissed] = useState(false);
  const context = useContext(LanguageContext);
  
  // Fallback translations if context not available (during hot reload)
  const pwa = context?.t?.pwa ?? {
    offlineMode: "You're offline",
    contentAvailable: 'All content is available offline',
    dismiss: 'Dismiss',
  };

  useEffect(() => {
    const handleOnline = () => setIsOffline(false);
    const handleOffline = () => {
      setIsOffline(true);
      setIsDismissed(false);
    };

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, []);

  if (!isOffline || isDismissed) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 md:left-auto md:right-4 md:w-auto z-50 animate-fade-in">
      <div className="bg-amber-500/90 dark:bg-amber-600/90 backdrop-blur-sm text-white px-4 py-3 rounded-lg shadow-lg flex items-center gap-3">
        <WifiOff className="h-5 w-5 flex-shrink-0" />
        <div className="flex-1">
          <p className="font-medium text-sm">{pwa.offlineMode}</p>
          <p className="text-xs opacity-90">{pwa.contentAvailable}</p>
        </div>
        <button
          onClick={() => setIsDismissed(true)}
          className="p-1 hover:bg-white/20 rounded-full transition-colors"
          aria-label={pwa.dismiss}
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
};
