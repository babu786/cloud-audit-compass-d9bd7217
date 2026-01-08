import { useEffect, useState, useContext } from 'react';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { LanguageContext } from '@/i18n/LanguageContext';
import { useRegisterSW } from 'virtual:pwa-register/react';

export const PWAUpdatePrompt = () => {
  const context = useContext(LanguageContext);
  const [showReload, setShowReload] = useState(false);
  
  // Fallback translations if context not available (during hot reload)
  const pwa = context?.t?.pwa ?? {
    updateAvailable: 'Update available',
    updateNow: 'Update now',
    dismiss: 'Dismiss',
  };

  const {
    needRefresh: [needRefresh, setNeedRefresh],
    updateServiceWorker,
  } = useRegisterSW({
    onRegisteredSW(swUrl, r) {
      console.log('SW Registered:', swUrl);
      // Check for updates every hour
      if (r) {
        setInterval(() => {
          r.update();
        }, 60 * 60 * 1000);
      }
    },
    onRegisterError(error) {
      console.log('SW registration error', error);
    },
  });

  useEffect(() => {
    setShowReload(needRefresh);
  }, [needRefresh]);

  const handleUpdate = () => {
    updateServiceWorker(true);
  };

  const handleDismiss = () => {
    setShowReload(false);
    setNeedRefresh(false);
  };

  if (!showReload) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 animate-fade-in">
      <div className="bg-primary text-primary-foreground px-4 py-3 rounded-lg shadow-lg flex items-center gap-3">
        <RefreshCw className="h-5 w-5" />
        <div className="flex-1">
          <p className="font-medium text-sm">{pwa.updateAvailable}</p>
        </div>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="secondary"
            onClick={handleUpdate}
            className="text-xs"
          >
            {pwa.updateNow}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            onClick={handleDismiss}
            className="text-xs hover:bg-primary-foreground/20"
          >
            {pwa.dismiss}
          </Button>
        </div>
      </div>
    </div>
  );
};
