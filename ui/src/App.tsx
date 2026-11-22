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
  Search,
  Server,
  Shield,
  SlidersHorizontal,
  Users,
} from 'lucide-react';
import { useState, type FormEvent } from 'react';
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

type NavSection = 'analytics' | 'config';
type WorkspaceMode = 'analyst' | 'config';

const NAV_ITEMS: Array<{
  key: NavKey;
  icon: typeof Activity;
  section: NavSection;
  adminOnly?: boolean;
}> = [
  { key: 'dashboard', icon: Activity, section: 'analytics' },
  { key: 'hosts', icon: Server, section: 'analytics' },
  { key: 'diffs', icon: GitCompare, section: 'analytics' },
  { key: 'clusters', icon: Layers, section: 'analytics' },
  { key: 'scans', icon: RefreshCw, section: 'analytics' },
  { key: 'assetGroups', icon: Network, section: 'config' },
  { key: 'ignoredTargets', icon: Ban, section: 'config' },
  { key: 'signatures', icon: FileCode2, section: 'config' },
  { key: 'notifications', icon: Bell, section: 'config' },
  { key: 'integrations', icon: Blocks, section: 'config' },
  { key: 'admin', icon: Users, section: 'config', adminOnly: true },
];

export default function App() {
  const { t, i18n } = useTranslation();
  const { user, isLoading, logout, hasPermission } = useAuth();
  const [activeNav, setActiveNav] = useState<NavKey>('dashboard');
  const [modeOverride, setModeOverride] = useState<WorkspaceMode | null>(() => {
    const saved = localStorage.getItem('asi_workspace_mode');
    return saved === 'analyst' || saved === 'config' ? saved : null;
  });
  const [headerSearch, setHeaderSearch] = useState('');
  const [submittedSearch, setSubmittedSearch] = useState('');
  const [searchVersion, setSearchVersion] = useState(0);
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
  const roleDefaultMode: WorkspaceMode =
    user.role === 'Admin' || user.role === 'ReadWriteDelete' ? 'config' : 'analyst';
  const workspaceMode: WorkspaceMode = modeOverride ?? roleDefaultMode;

  const switchLanguage = (lng: 'pl' | 'en') => {
    void i18n.changeLanguage(lng);
  };

  const selectWorkspaceMode = (mode: WorkspaceMode) => {
    setModeOverride(mode);
    localStorage.setItem('asi_workspace_mode', mode);
    if (mode === 'analyst') {
      const currentItem = NAV_ITEMS.find((item) => item.key === activeNav);
      if (currentItem?.section === 'config') {
        setActiveNav('hosts');
      }
    }
  };

  const handleGlobalSearch = (e: FormEvent) => {
    e.preventDefault();
    setSubmittedSearch(headerSearch.trim());
    setSearchVersion((v) => v + 1);
    setActiveNav('hosts');
  };

  const visibleNavItems = NAV_ITEMS.filter((item) => {
    if (item.adminOnly && !showAdmin) return false;
    if (workspaceMode === 'analyst') return item.section === 'analytics';
    return true;
  });

  const analyticsItems = visibleNavItems.filter((item) => item.section === 'analytics');
  const configItems = visibleNavItems.filter((item) => item.section === 'config');

  const renderNavBtn = ({ key, icon: Icon }: (typeof NAV_ITEMS)[number]) => {
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
  };

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <aside className="flex w-64 shrink-0 flex-col border-r border-border bg-card p-3">
        <div className="mb-3 flex items-center gap-2.5 border-b border-border px-1 pb-3">
          <div className="flex h-8 w-8 items-center justify-center border border-border bg-background text-foreground">
            <Shield className="h-4 w-4" />
          </div>
          <div>
            <div className="font-mono text-sm font-bold">{t('app.shortName')}</div>
            <div className="text-[11px] text-muted-foreground">{t('app.subtitle')}</div>
          </div>
        </div>

        <div className="mb-3 space-y-1">
          <div className="px-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            {t('workspace.modeLabel')}
          </div>
          <div className="grid grid-cols-2 gap-1 rounded-md border border-border bg-background p-1">
            <button
              type="button"
              onClick={() => selectWorkspaceMode('analyst')}
              className={`rounded px-2 py-1 text-[11px] font-medium transition-colors ${
                workspaceMode === 'analyst'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {t('workspace.modeAnalystShort')}
            </button>
            <button
              type="button"
              onClick={() => selectWorkspaceMode('config')}
              className={`rounded px-2 py-1 text-[11px] font-medium transition-colors ${
                workspaceMode === 'config'
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {t('workspace.modeConfigShort')}
            </button>
          </div>
        </div>

        <nav className="flex-1 space-y-3 overflow-y-auto">
          <div className="space-y-0.5">
            <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {t('workspace.sectionAnalytics')}
            </div>
            {analyticsItems.map(renderNavBtn)}
          </div>

          {workspaceMode === 'config' ? (
            <div className="space-y-0.5 border-t border-border/60 pt-2">
              <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                {t('workspace.sectionConfig')}
              </div>
              {configItems.map(renderNavBtn)}
            </div>
          ) : (
            <div className="border-t border-border/60 pt-2">
              <button
                type="button"
                onClick={() => selectWorkspaceMode('config')}
                className="flex w-full items-center justify-between rounded border border-border/70 bg-background/60 px-2.5 py-2 text-left text-xs text-muted-foreground hover:border-primary/60 hover:text-foreground"
              >
                <span className="flex items-center gap-1.5">
                  <SlidersHorizontal className="h-3.5 w-3.5" />
                  {t('workspace.openConfigTools')}
                </span>
                <span>→</span>
              </button>
            </div>
          )}
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

      <main className="flex-1 overflow-x-hidden p-4 lg:p-6">
        <header className="mb-4 flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
          <div>
            <h1 className="font-mono text-lg font-bold">{t(`nav.${activeNav}`)}</h1>
            <p className="font-mono text-[11px] text-muted-foreground">
              {t('app.name')} ·{' '}
              {workspaceMode === 'analyst'
                ? t('workspace.modeAnalystBadge')
                : t('workspace.modeConfigBadge')}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <form onSubmit={handleGlobalSearch} className="relative flex items-center gap-1.5">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-muted-foreground" />
                <input
                  type="text"
                  value={headerSearch}
                  onChange={(e) => setHeaderSearch(e.target.value)}
                  placeholder={t('workspace.globalSearchPlaceholder')}
                  className="w-56 rounded-md border border-border bg-background py-1.5 pl-8 pr-2.5 text-xs sm:w-72"
                />
              </div>
              <Button type="submit" size="sm" variant="outline">
                {t('workspace.searchBtn')}
              </Button>
            </form>
            <div className="hidden items-center rounded-md border border-border bg-background p-0.5 sm:flex">
              <button
                type="button"
                onClick={() => selectWorkspaceMode('analyst')}
                className={`rounded px-2 py-1 text-[11px] font-medium ${
                  workspaceMode === 'analyst'
                    ? 'bg-secondary text-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {t('workspace.modeAnalystShort')}
              </button>
              <button
                type="button"
                onClick={() => selectWorkspaceMode('config')}
                className={`rounded px-2 py-1 text-[11px] font-medium ${
                  workspaceMode === 'config'
                    ? 'bg-secondary text-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {t('workspace.modeConfigShort')}
              </button>
            </div>
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
          <HostsView
            key={`hosts-${searchVersion}`}
            initialSearch={submittedSearch}
            workspaceMode={workspaceMode}
          />
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
