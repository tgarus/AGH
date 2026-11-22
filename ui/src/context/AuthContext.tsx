/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

import {
  apiClient,
  formatApiError,
  refreshSessionOnce,
  setAccessToken,
  type AuthUser,
  type Permission,
} from '@/api/client';

interface AuthContextValue {
  user: AuthUser | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (permission: Permission) => boolean;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const tryRefresh = useCallback(async (): Promise<boolean> => {
    // Single-flight: równoczesne wywołania współdzielą jedno żądanie refresh
    // (rotacja tokena w API jest atomowa — dwa równoległe refresh'e unieważniłyby sesję).
    const refreshedUser = await refreshSessionOnce();
    if (!refreshedUser) {
      setAccessToken(null);
      setUser(null);
      return false;
    }
    setUser(refreshedUser);
    return true;
  }, []);

  useEffect(() => {
    let active = true;
    void (async () => {
      await tryRefresh();
      if (active) {
        setIsLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [tryRefresh]);

  useEffect(() => {
    if (!user) {
      return;
    }
    const timer = window.setInterval(() => {
      void tryRefresh();
    }, 12 * 60 * 1000);
    return () => window.clearInterval(timer);
  }, [user, tryRefresh]);

  const login = useCallback(async (username: string, password: string) => {
    const { data, error } = await apiClient.POST('/api/v1/auth/login', {
      body: { username, password },
    });
    if (error || !data) {
      throw new Error(formatApiError(error, 'Authentication failed.'));
    }
    setAccessToken(data.access_token);
    setUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    try {
      await apiClient.POST('/api/v1/auth/logout');
    } finally {
      setAccessToken(null);
      setUser(null);
    }
  }, []);

  const hasPermission = useCallback(
    (permission: Permission) => {
      if (!user) {
        return false;
      }
      return user.permissions.includes(permission);
    },
    [user],
  );

  return (
    <AuthContext.Provider value={{ user, isLoading, login, logout, hasPermission }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used inside AuthProvider');
  }
  return ctx;
}
