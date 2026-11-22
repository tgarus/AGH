import {
  Activity,
  Ban,
  Bell,
  Blocks,
  FileCode2,
  GitCompare,
  Layers,
  LogOut,
  Network,
  RefreshCw,
  Server,
  Shield,
  Users,
} from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { AdminView } from '@/components/AdminView';
import { AssetGroupsView } from '@/components/AssetGroupsView';
import { ClustersView } from '@/components/ClustersView';
import { DashboardView } from '@/components/DashboardView';
import { DiffsView } from '@/components/DiffsView';
import { HostsView } from '@/components/HostsView';
import { IgnoredTargetsView } from '@/components/IgnoredTargetsView';
import { IntegrationsView } from '@/components/IntegrationsView';
import { LoginView } from '@/components/LoginView';
import { NotificationsView } from '@/components/NotificationsView';
import { ScansView } from '@/components/ScansView';
import { SignaturesView } from '@/components/SignaturesView';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/context/AuthContext';
import { useLiveEvents } from '@/hooks/useLiveEvents';

type NavKey =
  | 'dashboard'
  | 'assetGroups'
  | 'ignoredTargets'
  | 'scans'
  | 'hosts'
  | 'diffs'
  | 'clusters'
  | 'signatures'
  | 'notifications'
  | 'integrations'
  | 'admin';

const NAV_ITEMS: Array<{ key: NavKey; icon: typeof Activity; adminOnly?: boolean }> = [
  { key: 'dashboard', icon: Activity },
  { key: 'assetGroups', icon: Network },
  { key: 'ignoredTargets', icon: Ban },
  { key: 'scans', icon: RefreshCw },
  { key: 'hosts', icon: Server },
  { key: 'diffs', icon: GitCompare },
  { key: 'clusters', icon: Layers },
  { key: 'signatures', icon: FileCode2 },
  { key: 'notifications', icon: Bell },
  { key: 'integrations', icon: Blocks },
  { key: 'admin', icon: Users, adminOnly: true },
];

export default function App() {
  const { t, i18n } = useTranslation();
  const { user, isLoading, logout, hasPermission } = useAuth();
  const [activeNav, setActiveNav] = useState<NavKey>('dashboard');
  const sseStatus = useLiveEvents(Boolean(user));

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        {t('auth.checkingSession')}
      </div>
    );
  }

  if (!user) {
    return <LoginView />;
  }

  const currentLang = i18n.language.startsWith('en') ? 'en' : 'pl';
  const showAdmin = hasPermission('manage_users_and_audit') || hasPermission('manage_workers');

  const switchLanguage = (lng: 'pl' | 'en') => {
    void i18n.changeLanguage(lng);
  };

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="flex w-60 flex-col border-r border-border bg-card p-3">
        <div className="mb-4 flex items-center gap-2.5 border-b border-border px-1 pb-3">
          <div className="flex h-8 w-8 items-center justify-center border border-border bg-background text-foreground">
            <Shield className="h-4 w-4" />
          </div>
          <div>
            <div className="font-mono text-sm font-bold">{t('app.shortName')}</div>
            <div className="text-[11px] text-muted-foreground">{t('app.subtitle')}</div>
          </div>
        </div>

        <nav className="flex-1 space-y-0.5">
          {NAV_ITEMS.filter((item) => !item.adminOnly || showAdmin).map(({ key, icon: Icon }) => {
            const isActive = activeNav === key;
            return (
              <button
                key={key}
                type="button"
                onClick={() => setActiveNav(key)}
                className={`flex w-full items-center gap-2.5 border-l-2 px-2.5 py-1.5 text-left text-[13px] transition-colors ${
                  isActive
                    ? 'border-l-primary bg-secondary font-medium text-foreground'
                    : 'border-l-transparent text-muted-foreground hover:bg-secondary hover:text-foreground'
                }`}
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{t(`nav.${key}`)}</span>
              </button>
            );
          })}
        </nav>

        <div className="space-y-3 border-t border-border pt-3">
          <div className="flex items-center justify-between gap-2 text-xs">
            <div>
              <div className="font-semibold text-foreground">{user.username}</div>
              <Badge variant="outline" className="mt-1">
                {user.role}
              </Badge>
            </div>
            <Button variant="ghost" size="sm" onClick={() => void logout()} title={t('auth.logout')}>
              <LogOut className="h-4 w-4" />
            </Button>
          </div>

          <div>
            <div className="mb-2 text-xs font-medium text-muted-foreground">{t('language.label')}</div>
            <div className="flex gap-2">
              <Button
                size="sm"
                variant={currentLang === 'pl' ? 'default' : 'outline'}
                onClick={() => switchLanguage('pl')}
                className="flex-1"
              >
                {t('language.pl')}
              </Button>
              <Button
                size="sm"
                variant={currentLang === 'en' ? 'default' : 'outline'}
                onClick={() => switchLanguage('en')}
                className="flex-1"
              >
                {t('language.en')}
              </Button>
            </div>
          </div>
        </div>
      </aside>

      <main className="flex-1 p-4 lg:p-6">
        <header className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
          <div>
            <h1 className="font-mono text-lg font-bold">{t(`nav.${activeNav}`)}</h1>
            <p className="font-mono text-[11px] text-muted-foreground">
              {t('app.name')} · {t('app.phaseBadge')}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge
              variant={
                sseStatus === 'connected'
                  ? 'success'
                  : sseStatus === 'reconnecting'
                    ? 'warning'
                    : 'outline'
              }
            >
              SSE: {t(`sse.${sseStatus}`)}
            </Badge>
          </div>
        </header>

        {activeNav === 'dashboard' ? (
          <DashboardView onNavigate={(nav) => setActiveNav(nav)} />
        ) : activeNav === 'assetGroups' ? (
          <AssetGroupsView />
        ) : activeNav === 'ignoredTargets' ? (
          <IgnoredTargetsView />
        ) : activeNav === 'scans' ? (
          <ScansView />
        ) : activeNav === 'hosts' ? (
          <HostsView />
        ) : activeNav === 'diffs' ? (
          <DiffsView />
        ) : activeNav === 'clusters' ? (
          <ClustersView />
        ) : activeNav === 'signatures' ? (
          <SignaturesView />
        ) : activeNav === 'notifications' ? (
          <NotificationsView />
        ) : activeNav === 'integrations' ? (
          <IntegrationsView />
        ) : (
          <AdminView />
        )}
      </main>
    </div>
  );
}
