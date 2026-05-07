import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { DashboardLayout } from './components/layout/DashboardLayout';
import { VaultPage } from './features/vault/VaultPage';
import { AlertsPage } from './features/alerts/AlertsPage';
import { PoliciesPage } from './features/policies/PoliciesPage';
import { SettingsPage } from './features/settings/SettingsPage';
import { AuthProvider, useAuth } from './features/auth/AuthContext';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import DashboardPage from './pages/DashboardPage';
import SharePage from './features/share/SharePage';
import { useEffect } from 'react';
import { initGlobalLogger } from './services/logger';


const queryClient = new QueryClient();

// Protected Route Wrapper
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { user, isLoading } = useAuth();
  if (isLoading) return <div className="h-screen bg-slate-900 text-slate-400 flex items-center justify-center">Loading session...</div>;
  if (!user) return <Navigate to="/login" />;
  return <>{children}</>;
};


function App() {
  useEffect(() => {
    initGlobalLogger();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/share/:token" element={<SharePage />} />
            <Route path="/" element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>}>
              <Route index element={<DashboardPage />} />
              <Route path="vault" element={<VaultPage />} />
              <Route path="alerts" element={<AlertsPage />} />
              <Route path="policies" element={<PoliciesPage />} />
              <Route path="settings" element={<SettingsPage />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
