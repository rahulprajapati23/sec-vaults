import { Outlet, Link, useLocation } from 'react-router-dom';
import { 
  FolderIcon, 
  ShieldExclamationIcon, 
  ChartBarIcon, 
  Cog6ToothIcon,
  DocumentTextIcon,
  ArrowLeftOnRectangleIcon
} from '@heroicons/react/24/outline';
import { cn } from '../common/Button';
import { ErrorBoundary } from '../common/ErrorBoundary';
import { useAuth } from '../../features/auth/AuthContext';

export const DashboardLayout = () => {
  const location = useLocation();
  const { logout, user } = useAuth();

  const navigation = [
    { name: 'Dashboard', href: '/', icon: ChartBarIcon },
    { name: 'Secure Vault', href: '/vault', icon: FolderIcon },
    { name: 'Threat Alerts', href: '/alerts', icon: ShieldExclamationIcon },
    { name: 'Log Policies', href: '/policies', icon: DocumentTextIcon },
    { name: 'Settings', href: '/settings', icon: Cog6ToothIcon },
  ];

  return (
    <div className="min-h-screen bg-slate-900 flex">
      {/* Sidebar */}
      <div className="w-64 bg-slate-850 border-r border-slate-800 flex flex-col">
        <div className="h-16 flex items-center px-6 border-b border-slate-800">
          <ShieldExclamationIcon className="w-8 h-8 text-blue-500 mr-2" />
          <h1 className="text-xl font-bold text-white tracking-wider">SEC_VAULT</h1>
        </div>
        
        <nav className="flex-1 px-4 py-6 space-y-2">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <Link
                key={item.name}
                to={item.href}
                className={cn(
                  "flex items-center px-4 py-3 text-sm font-medium rounded-lg transition-colors",
                  isActive 
                    ? "bg-blue-600/10 text-blue-400" 
                    : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                )}
              >
                <item.icon className={cn("w-5 h-5 mr-3", isActive ? "text-blue-400" : "text-slate-500")} />
                {item.name}
              </Link>
            )
          })}
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="h-16 bg-slate-850 border-b border-slate-800 flex items-center px-8 justify-between">
          <h2 className="text-lg font-medium text-slate-200">System Monitoring Active</h2>
          <div className="flex items-center space-x-6">
            <span className="flex items-center text-xs font-medium text-emerald-400 bg-emerald-400/10 px-3 py-1 rounded-full border border-emerald-500/20">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse"></span>
              All Systems Operational
            </span>
            
            <div className="h-6 w-px bg-slate-800"></div>

            <div className="flex items-center gap-3">
              <div className="text-right hidden sm:block">
                <p className="text-sm font-medium text-slate-200">{user?.email}</p>
                <p className="text-[10px] font-bold text-slate-500 uppercase tracking-tight">{user?.role}</p>
              </div>
              <button 
                onClick={logout}
                className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-400/10 rounded-lg transition-all group"
                title="Sign Out"
              >
                <ArrowLeftOnRectangleIcon className="w-5 h-5 group-hover:-translate-x-0.5 transition-transform" />
              </button>
            </div>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-8">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
};
