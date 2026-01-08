import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { en, Translations } from './translations/en';
import { hi } from './translations/hi';

type Language = 'en' | 'hi';

interface LanguageContextType {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: Translations;
}

const translations: Record<Language, Translations> = {
  en,
  hi,
};

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

interface LanguageProviderProps {
  children: ReactNode;
}

const SUPPORTED_LANGUAGES: Language[] = ['en', 'hi'];

function detectBrowserLanguage(): Language {
  if (typeof window === 'undefined') return 'en';
  
  // Check navigator.languages first (array of preferred languages)
  const browserLanguages = navigator.languages || [navigator.language];
  
  for (const lang of browserLanguages) {
    const shortLang = lang.split('-')[0].toLowerCase();
    if (shortLang === 'hi') return 'hi';
    if (shortLang === 'en') return 'en';
  }
  
  return 'en'; // Default fallback
}

function getInitialLanguage(): Language {
  if (typeof window === 'undefined') return 'en';
  
  // First check if user has a saved preference
  const saved = localStorage.getItem('language') as Language | null;
  if (saved && SUPPORTED_LANGUAGES.includes(saved)) {
    return saved;
  }
  
  // Auto-detect from browser on first visit
  const detected = detectBrowserLanguage();
  localStorage.setItem('language', detected); // Save detected preference
  return detected;
}

export function LanguageProvider({ children }: LanguageProviderProps) {
  const [language, setLanguageState] = useState<Language>(getInitialLanguage);

  const setLanguage = (lang: Language) => {
    setLanguageState(lang);
    localStorage.setItem('language', lang);
  };

  const t = translations[language];

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLanguage() {
  const context = useContext(LanguageContext);
  if (context === undefined) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
}
