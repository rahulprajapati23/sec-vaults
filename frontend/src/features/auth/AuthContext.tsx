import React, { createContext, useContext, useState, useEffect } from 'react';
import { api } from '../../services/api';

interface AuthContextType {
  user: any;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [user, setUser] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check if we are authenticated by trying to fetch the user profile
    // Axios will automatically send the HttpOnly cookie if it exists
    api.get('/auth/me')
      .then(res => setUser(res.data))
      .catch(() => setUser(null))
      .finally(() => setIsLoading(false));
  }, []);

  const login = async (email: string, password: string) => {
    const formData = new URLSearchParams();
    formData.append('email', email);
    formData.append('password', password);

    // Call the JSON-compatible login endpoint (sets HttpOnly cookie + returns user JSON)
    const res = await api.post('/auth/api-login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    setUser(res.data);
  };

  const logout = () => {
    api.post('/auth/api-logout').finally(() => {
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
