import { useState, useEffect, useCallback } from 'react';
import { AuditControl, auditControls as builtInControls } from '@/data/auditContent';

const STORAGE_KEY = 'imported-audit-controls';

export function useImportedControls() {
  const [importedControls, setImportedControls] = useState<AuditControl[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Load from localStorage on mount
  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setImportedControls(JSON.parse(stored));
      }
    } catch (error) {
      console.error('Failed to load imported controls:', error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Save to localStorage whenever importedControls changes
  useEffect(() => {
    if (!isLoading) {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(importedControls));
      } catch (error) {
        console.error('Failed to save imported controls:', error);
      }
    }
  }, [importedControls, isLoading]);

  const addControls = useCallback((newControls: Partial<AuditControl>[]) => {
    setImportedControls(prev => {
      const existingIds = new Set(prev.map(c => c.id));
      const validControls = newControls
        .filter(c => c.id && !existingIds.has(c.id))
        .map(c => c as AuditControl);
      return [...prev, ...validControls];
    });
  }, []);

  const removeControl = useCallback((id: string) => {
    setImportedControls(prev => prev.filter(c => c.id !== id));
  }, []);

  const clearAllImported = useCallback(() => {
    setImportedControls([]);
  }, []);

  // Merge built-in and imported controls
  const allControls = [...builtInControls, ...importedControls];

  return {
    importedControls,
    allControls,
    builtInControls,
    addControls,
    removeControl,
    clearAllImported,
    isLoading,
    importedCount: importedControls.length,
  };
}
