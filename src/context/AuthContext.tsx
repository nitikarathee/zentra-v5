import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, RoleType } from '../types';
import { apiService } from '../services/api';

interface AuthContextType {
  user: User | null;
  token: string | null;
  role: RoleType;
  permissions: string[];
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, passwordOrRole?: string | RoleType, role?: RoleType) => Promise<void>;
  register: (name: string, email: string, passwordOrRole?: string | RoleType, role?: RoleType, department?: string) => Promise<void>;
  logout: () => void;
  switchRole: (role: RoleType) => Promise<void>;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('zentra_token'));
  const [permissions, setPermissions] = useState<string[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function initAuth() {
      try {
        const data = await apiService.getMe();
        setUser(data.user);
        setPermissions(data.permissions);
      } catch (err) {
        console.warn('Session verification fallback to demo admin:', err);
        // Default seed user
        const demoUser: User = {
          id: 'usr-admin-1',
          name: 'Alex Vance',
          email: 'admin@zentra.sec',
          role: 'ADMIN',
          department: 'Enterprise Security Architecture',
          createdAt: '2026-01-10T08:00:00Z',
        };
        setUser(demoUser);
        setPermissions([
          'api:create', 'api:edit', 'api:delete', 'api:scan',
          'finding:view', 'finding:status_update', 'finding:accept_risk',
          'compliance:view', 'compliance:assess', 'compliance:edit',
          'ai:analyze', 'ai:sanitize',
          'knowledge:view', 'knowledge:manage',
          'reports:view', 'reports:create', 'reports:export',
          'audit:view', 'audit:verify',
          'rbac:manage', 'settings:edit'
        ]);
      } finally {
        setIsLoading(false);
      }
    }
    initAuth();
  }, [token]);

  const login = async (email: string, passwordOrRole?: string | RoleType, role?: RoleType) => {
    setIsLoading(true);
    try {
      let pwd = typeof passwordOrRole === 'string' && !['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(passwordOrRole) ? passwordOrRole : undefined;
      let targetRole = typeof passwordOrRole === 'string' && ['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(passwordOrRole) 
        ? (passwordOrRole as RoleType) 
        : role;
      const data = await apiService.login(email, pwd, targetRole);
      setToken(data.token);
      localStorage.setItem('zentra_token', data.token);
      setUser(data.user);
      setPermissions(data.permissions);
    } finally {
      setIsLoading(false);
    }
  };

  const register = async (name: string, email: string, passwordOrRole?: string | RoleType, role?: RoleType, department?: string) => {
    setIsLoading(true);
    try {
      let pwd = typeof passwordOrRole === 'string' && !['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(passwordOrRole) ? passwordOrRole : 'zentra2026!';
      let targetRole = typeof passwordOrRole === 'string' && ['ADMIN', 'SECURITY_ANALYST', 'DEVELOPER'].includes(passwordOrRole)
        ? (passwordOrRole as RoleType)
        : (role || 'DEVELOPER');
      const data = await apiService.register(name, email, pwd, targetRole, department);
      setToken(data.token);
      localStorage.setItem('zentra_token', data.token);
      setUser(data.user);
      setPermissions(data.permissions);
    } finally {
      setIsLoading(false);
    }
  };

  const switchRole = async (newRole: RoleType) => {
    setIsLoading(true);
    try {
      const data = await apiService.switchRole(newRole);
      setToken(data.token);
      localStorage.setItem('zentra_token', data.token);
      setUser(data.user);
      setPermissions(data.permissions);
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('zentra_token');
    setToken(null);
    setUser(null);
    setPermissions([]);
  };

  const hasPermission = (permission: string) => {
    if (!user) return false;
    if (user.role === 'ADMIN') return true;
    return permissions.includes(permission);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        role: user?.role || 'DEVELOPER',
        permissions,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
        switchRole,
        hasPermission,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
