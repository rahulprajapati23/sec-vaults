import os
from pathlib import Path

BASE_DIR = Path("d:/DSSPrjct/frontend")

def ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True)

def write_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content.strip() + "\n")

def scaffold():
    # 1. Update Tailwind config
    tailwind_config = """
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          850: '#141d2e',
          900: '#0B0F19',
          950: '#070a11',
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['Roboto Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
"""
    write_file(BASE_DIR / "tailwind.config.js", tailwind_config)
    
    # 2. Add postcss config (since npx init failed)
    postcss_config = """
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
}
"""
    write_file(BASE_DIR / "postcss.config.js", postcss_config)

    # 3. Update index.css
    index_css = """
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  body {
    @apply bg-slate-900 text-slate-300 font-sans antialiased;
  }
  h1, h2, h3, h4, h5, h6 {
    @apply text-white font-semibold tracking-tight;
  }
}
"""
    write_file(BASE_DIR / "src" / "index.css", index_css)

    # 4. Create Folder Structure
    dirs = [
        "src/components/common",
        "src/components/layout",
        "src/components/security",
        "src/features/auth",
        "src/features/vault",
        "src/features/alerts",
        "src/store",
        "src/hooks"
    ]
    for d in dirs:
        ensure_dir(BASE_DIR / d)

    # 5. Create common Button component
    button_tsx = """
import React from 'react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', ...props }, ref) => {
    const baseStyles = "inline-flex items-center justify-center rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 disabled:pointer-events-none disabled:opacity-50 cursor-pointer";
    
    const variants = {
      primary: "bg-blue-600 text-white hover:bg-blue-700 shadow-sm",
      secondary: "bg-slate-800 text-slate-200 hover:bg-slate-700 border border-slate-700",
      danger: "bg-red-600 text-white hover:bg-red-700 shadow-sm",
      ghost: "hover:bg-slate-800 text-slate-300 hover:text-white"
    };
    
    const sizes = {
      sm: "h-8 px-3 text-xs",
      md: "h-10 px-4 py-2 text-sm",
      lg: "h-12 px-8 text-base"
    };

    return (
      <button
        ref={ref}
        className={cn(baseStyles, variants[variant], sizes[size], className)}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
"""
    write_file(BASE_DIR / "src/components/common/Button.tsx", button_tsx)

    # 6. Create Layout Component
    layout_tsx = """
import { Outlet, Link, useLocation } from 'react-router-dom';
import { 
  FolderIcon, 
  ShieldExclamationIcon, 
  ChartBarIcon, 
  Cog6ToothIcon 
} from '@heroicons/react/24/outline';
import { cn } from '../common/Button';

export const DashboardLayout = () => {
  const location = useLocation();

  const navigation = [
    { name: 'Dashboard', href: '/', icon: ChartBarIcon },
    { name: 'Secure Vault', href: '/vault', icon: FolderIcon },
    { name: 'Threat Alerts', href: '/alerts', icon: ShieldExclamationIcon },
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
          <div className="flex items-center space-x-4">
            <span className="flex items-center text-xs font-medium text-emerald-400 bg-emerald-400/10 px-3 py-1 rounded-full border border-emerald-500/20">
              <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse"></span>
              All Systems Operational
            </span>
          </div>
        </header>
        <main className="flex-1 overflow-y-auto p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
"""
    write_file(BASE_DIR / "src/components/layout/DashboardLayout.tsx", layout_tsx)

    # 7. Setup Main App component
    app_tsx = """
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { DashboardLayout } from './components/layout/DashboardLayout';

function DashboardHome() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6 text-white">Security Dashboard</h1>
      <div className="grid grid-cols-3 gap-6">
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg">
          <h3 className="text-slate-400 text-sm font-medium mb-2 uppercase tracking-wide">Monitored Files</h3>
          <p className="text-4xl font-mono text-white mt-4">1,204</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg">
          <h3 className="text-slate-400 text-sm font-medium mb-2 uppercase tracking-wide">Active Threats</h3>
          <p className="text-4xl font-mono text-red-500 mt-4">0</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 p-6 rounded-xl shadow-lg">
          <h3 className="text-slate-400 text-sm font-medium mb-2 uppercase tracking-wide">Clean Scans (24h)</h3>
          <p className="text-4xl font-mono text-emerald-400 mt-4">892</p>
        </div>
      </div>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<DashboardLayout />}>
          <Route index element={<DashboardHome />} />
          <Route path="vault" element={<div className="text-slate-400 text-lg">Vault Component (Coming Soon)</div>} />
          <Route path="alerts" element={<div className="text-slate-400 text-lg">Alerts Feed (Coming Soon)</div>} />
          <Route path="settings" element={<div className="text-slate-400 text-lg">Settings Panel (Coming Soon)</div>} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

export default App;
"""
    write_file(BASE_DIR / "src/App.tsx", app_tsx)

    print("Successfully scaffolded Secure Vault React Frontend!")

if __name__ == "__main__":
    scaffold()
