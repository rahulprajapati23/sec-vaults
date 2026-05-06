import React, { createContext, useContext, useState, useEffect } from 'react';
import { api, type ApiResponse } from '../../services/api';
import type { AuthUser } from '../../types/auth';

interface AuthContextType {
  user: AuthUser | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    (api.get('/auth/me') as unknown as Promise<ApiResponse<AuthUser>>)
      .then(res => {
        if (res.success) setUser(res.data);
      })
      .catch(() => setUser(null))
      .finally(() => setIsLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const formData = new URLSearchParams();
    formData.append('email', email);
    formData.append('password', password);

    const res = await (api.post('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }) as unknown as Promise<ApiResponse<any>>);
    
    if (res.success) {
      setUser(res.data.user);
    } else {
      throw new Error(res.error || 'Login failed');
    }
  };

  const logout = () => {
    api.post('/auth/logout').finally(() => {
      setUser(null);
    });
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used within an AuthProvider");
  return context;
};
