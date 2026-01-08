import { useState, useEffect } from 'react';
import { WifiOff, X } from 'lucide-react';
import { useLanguage } from '@/i18n/LanguageContext';

export const OfflineIndicator = () => {
  const [isOffline, setIsOffline] = useState(!navigator.onLine);
  const [isDismissed, setIsDismissed] = useState(false);
  const { t } = useLanguage();

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
          <p className="font-medium text-sm">{t.pwa.offlineMode}</p>
          <p className="text-xs opacity-90">{t.pwa.contentAvailable}</p>
        </div>
        <button
          onClick={() => setIsDismissed(true)}
          className="p-1 hover:bg-white/20 rounded-full transition-colors"
          aria-label={t.pwa.dismiss}
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
};
