import { createContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { AdminLoginModal } from '@/components/admin/AdminLoginModal';

interface AdminAuthContextType {
  isAdmin: boolean;
  isLoading: boolean;
  showLoginModal: boolean;
  openLoginModal: () => void;
  closeLoginModal: () => void;
  login: () => void;
  logout: () => void;
}

export const AdminAuthContext = createContext<AdminAuthContextType | null>(null);

interface AdminAuthProviderProps {
  children: ReactNode;
}

export function AdminAuthProvider({ children }: AdminAuthProviderProps) {
  const [isAdmin, setIsAdmin] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [showLoginModal, setShowLoginModal] = useState(false);

  // Check session on mount
  useEffect(() => {
    const adminToken = sessionStorage.getItem('isAdmin');
    setIsAdmin(!!adminToken);
    setIsLoading(false);
  }, []);

  const openLoginModal = useCallback(() => {
    setShowLoginModal(true);
  }, []);

  const closeLoginModal = useCallback(() => {
    setShowLoginModal(false);
  }, []);

  const login = useCallback(() => {
    setIsAdmin(true);
    setShowLoginModal(false);
  }, []);

  const logout = useCallback(() => {
    sessionStorage.removeItem('isAdmin');
    setIsAdmin(false);
  }, []);

  return (
    <AdminAuthContext.Provider
      value={{
        isAdmin,
        isLoading,
        showLoginModal,
        openLoginModal,
        closeLoginModal,
        login,
        logout,
      }}
    >
      {children}
      <AdminLoginModal
        open={showLoginModal}
        onClose={closeLoginModal}
        onSuccess={login}
      />
    </AdminAuthContext.Provider>
  );
}
