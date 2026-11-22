import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, BarChart3, OctagonX, Pause, Play, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';
import { formatBullet } from '@/utils/formatBullet';

export function DashboardView({
  onNavigate,
}: {
  onNavigate: (nav: 'scans' | 'hosts' | 'diffs' | 'clusters') => void;
}) {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const summaryQuery = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/dashboard/summary');
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load dashboard summary.'));
      }
      return data;
    },
    refetchInterval: 10_000,
  });

  const analyticsQuery = useQuery({
    queryKey: ['dashboard-analytics'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/dashboard/analytics');
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load dashboard analytics.'));
      }
      return data;
    },
    refetchInterval: 15_000,
  });

  const scansQuery = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/scans', {
        params: { query: { page: 1, per_page: 5 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load scans.'));
      }
      return data;
    },
  });

  const diffsQuery = useQuery({
    queryKey: ['diffs'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/diffs', {
        params: { query: { page: 1, per_page: 5 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load diffs.'));
      }
      return data;
    },
  });

  const healthQuery = useQuery({
    queryKey: ['system-health'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/healthz');
      if (error || !data) {
        throw new Error('healthz_unavailable');
      }
      return data;
    },
    refetchInterval: 15_000,
  });

  const scanActionMutation = useMutation({
    mutationFn: async ({ id, action }: { id: string; action: 'pause' | 'resume' | 'stop' }) => {
      const resp =
        action === 'pause'
          ? await apiClient.POST('/api/v1/scans/{id}/pause', { params: { path: { id } } })
          : action === 'resume'
            ? await apiClient.POST('/api/v1/scans/{id}/resume', { params: { path: { id } } })
            : await apiClient.POST('/api/v1/scans/{id}/stop', { params: { path: { id } } });
      if (resp.error || !resp.data) {
        throw new Error(formatApiError(resp.error, `Failed to ${action} scan.`));
      }
      return resp.data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
      void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const canControlScans = hasPermission('run_or_stop_scans');
  const s = summaryQuery.data;
  const analytics = analyticsQuery.data;
  const maxScanTargets = Math.max(1, ...(analytics?.recent_scans ?? []).map((p) => p.total_targets));
  const maxScanDuration = Math.max(
    1,
    ...(analytics?.recent_scans ?? []).map((p) => p.duration_seconds ?? 0),
  );
  const maxPortHosts = Math.max(1, ...(analytics?.top_open_ports ?? []).map((p) => p.host_count));
  const totalSeverityDiffs = Math.max(
    1,
    Object.values(analytics?.diffs_by_severity ?? {}).reduce((a, b) => a + b, 0),
  );

  return (
    <div className="space-y-4">
      {errorMsg ? (
        <div className="rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {errorMsg}
        </div>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="cursor-pointer hover:border-muted-foreground" onClick={() => onNavigate('hosts')}>
          <CardHeader className="pb-2">
            <CardDescription>{t('dashboard.kpiHosts')}</CardDescription>
            <CardTitle className="font-mono text-3xl normal-case tracking-normal text-foreground">{s?.total_hosts ?? '—'}</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-1.5 text-xs">
            <Badge variant="success">
              {t('dashboard.activeCount', { count: s?.active_hosts ?? 0 })}
            </Badge>
            <Badge variant="warning">
              {t('dashboard.unstableCount', { count: s?.unstable_hosts ?? 0 })}
            </Badge>
            <Badge variant="destructive">
              {t('dashboard.tarpitCount', { count: s?.probable_tarpit_hosts ?? 0 })}
            </Badge>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:border-muted-foreground" onClick={() => onNavigate('clusters')}>
          <CardHeader className="pb-2">
            <CardDescription>{t('dashboard.kpiServices')}</CardDescription>
            <CardTitle className="font-mono text-3xl normal-case tracking-normal text-foreground">{s?.active_ports ?? '—'}</CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            {t('dashboard.webObsCount', { count: s?.web_observations ?? 0 })}
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:border-muted-foreground" onClick={() => onNavigate('diffs')}>
          <CardHeader className="pb-2">
            <CardDescription>{t('dashboard.kpiDiffs')}</CardDescription>
            <CardTitle className="font-mono text-3xl normal-case tracking-normal text-foreground">{s?.unacknowledged_diffs ?? '—'}</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-1.5 text-xs">
            <Badge variant="default">
              {t('dashboard.confirmed24h', { count: s?.confirmed_changes_24h ?? 0 })}
            </Badge>
            <Badge variant="outline">
              {t('dashboard.variance24h', { count: s?.active_variance_24h ?? 0 })}
            </Badge>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:border-muted-foreground" onClick={() => onNavigate('scans')}>
          <CardHeader className="pb-2">
            <CardDescription>{t('dashboard.kpiScansWorkers')}</CardDescription>
            <CardTitle className="font-mono text-3xl normal-case tracking-normal text-foreground">
              {s?.running_scans ?? 0} / {s?.online_workers ?? 0}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            {t('dashboard.sigAndChannels', {
              sigs: s?.enabled_signatures ?? 0,
              channels: s?.enabled_notification_channels ?? 0,
            })}
          </CardContent>
        </Card>
      </div>

      {/* Analytics Charts Section */}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-primary" />
              {t('dashboard.analytics.recentScansChartTitle')}
            </CardTitle>
            <CardDescription>{t('dashboard.analytics.recentScansChartSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent>
            {analytics?.recent_scans.length ? (
              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-4 text-[11px] text-muted-foreground">
                  <span className="flex items-center gap-1.5">
                    <span className="inline-block h-2.5 w-2.5 rounded-sm bg-sky-500" />
                    {t('dashboard.analytics.legendTargets')}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="inline-block h-2.5 w-2.5 rounded-sm bg-amber-500" />
                    {t('dashboard.analytics.legendDuration')}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="inline-block h-2.5 w-2.5 rounded-sm bg-rose-500" />
                    {t('dashboard.analytics.legendConfirmedDiffs')}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 md:grid-cols-6">
                  {analytics.recent_scans.map((pt) => {
                    const targetPct = Math.max(8, Math.round((pt.total_targets / maxScanTargets) * 100));
                    const durPct = Math.max(
                      6,
                      Math.round(((pt.duration_seconds ?? 0) / maxScanDuration) * 100),
                    );
                    const totalDiffs = pt.confirmed_diffs + pt.variance_diffs;
                    return (
                      <div
                        key={pt.scan_run_id}
                        className="flex flex-col justify-between rounded-md border border-border bg-background/70 p-2 text-[11px]"
                        title={`${pt.asset_group_name} (${pt.status})`}
                      >
                        <div className="mb-1 flex items-end justify-center gap-1.5 h-24 border-b border-border/60 pb-1">
                          <div
                            className="w-3 rounded-t bg-sky-500/85 transition-all"
                            style={{ height: `${targetPct}%` }}
                            title={`${t('dashboard.analytics.legendTargets')}: ${pt.total_targets}`}
                          />
                          <div
                            className="w-3 rounded-t bg-amber-500/85 transition-all"
                            style={{ height: `${durPct}%` }}
                            title={`${t('dashboard.analytics.legendDuration')}: ${pt.duration_seconds ?? 0}s`}
                          />
                          {totalDiffs > 0 ? (
                            <div
                              className="w-3 rounded-t bg-rose-500/85 transition-all"
                              style={{ height: `${Math.min(100, Math.max(12, totalDiffs * 12))}%` }}
                              title={`Diffs: ${pt.confirmed_diffs} / ${pt.variance_diffs}`}
                            />
                          ) : null}
                        </div>
                        <div className="space-y-0.5 truncate">
                          <div className="truncate font-semibold text-foreground">{pt.asset_group_name}</div>
                          <div className="font-mono text-[10px] text-muted-foreground">
                            {pt.total_targets} IP · {pt.duration_seconds !== null ? `${pt.duration_seconds}s` : pt.status}
                          </div>
                          <div className="flex items-center justify-between text-[10px]">
                            <span className="text-rose-300">+{pt.confirmed_diffs} diff</span>
                            <span className="text-muted-foreground">
                              {pt.completed_chunks}/{pt.total_chunks}
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">{t('dashboard.analytics.noScansYet')}</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              {t('dashboard.analytics.distributionsTitle')}
            </CardTitle>
            <CardDescription>{t('dashboard.analytics.distributionsSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="text-xs font-medium text-muted-foreground">
                {t('dashboard.analytics.diffSeverityHeading')}
              </div>
              {(['high', 'medium', 'low', 'info'] as const).map((sev) => {
                const count = analytics?.diffs_by_severity[sev] ?? 0;
                const pct = Math.round((count / totalSeverityDiffs) * 100);
                const barCls =
                  sev === 'high'
                    ? 'bg-red-500'
                    : sev === 'medium'
                      ? 'bg-amber-500'
                      : sev === 'low'
                        ? 'bg-sky-500'
                        : 'bg-slate-500';
                return (
                  <div key={sev} className="space-y-1 text-xs">
                    <div className="flex justify-between font-mono">
                      <span className="uppercase">{sev}</span>
                      <span>
                        {count} ({pct}%)
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded bg-muted">
                      <div className={`h-full ${barCls}`} style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="space-y-2 border-t border-border pt-3">
              <div className="text-xs font-medium text-muted-foreground">
                {t('dashboard.analytics.topPortsHeading')}
              </div>
              {analytics?.top_open_ports.length ? (
                <div className="space-y-1.5">
                  {analytics.top_open_ports.slice(0, 6).map((p) => {
                    const pct = Math.max(6, Math.round((p.host_count / maxPortHosts) * 100));
                    return (
                      <div key={`${p.port}-${p.protocol}`} className="flex items-center gap-2 text-xs">
                        <span className="w-28 shrink-0 truncate font-mono">
                          {p.port}/{p.protocol} {p.service_name ? `(${p.service_name})` : ''}
                        </span>
                        <div className="h-2 flex-1 overflow-hidden rounded bg-muted">
                          <div className="h-full bg-emerald-500" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="w-16 text-right font-mono text-muted-foreground">
                          {p.host_count} {t('dashboard.analytics.hostsShort')}
                        </span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">{t('dashboard.analytics.noPortsYet')}</p>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {analytics?.group_stats.length ? (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle>{t('dashboard.analytics.groupBreakdownTitle')}</CardTitle>
            <CardDescription>{t('dashboard.analytics.groupBreakdownSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border text-muted-foreground">
                <tr>
                  <th className="py-2 pr-4">{t('dashboard.analytics.colGroup')}</th>
                  <th className="py-2 pr-4">{t('dashboard.analytics.colActiveHosts')}</th>
                  <th className="py-2 pr-4">{t('dashboard.analytics.colOpenPorts')}</th>
                  <th className="py-2 pr-4">{t('dashboard.analytics.colConfirmedDiffs')}</th>
                  <th className="py-2">{t('dashboard.analytics.colTotalScans')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {analytics.group_stats.map((g) => (
                  <tr key={g.asset_group_id}>
                    <td className="py-2 pr-4 font-medium">{g.asset_group_name}</td>
                    <td className="py-2 pr-4 font-mono">{g.active_hosts}</td>
                    <td className="py-2 pr-4 font-mono">{g.open_ports}</td>
                    <td className="py-2 pr-4 font-mono">{g.confirmed_diffs}</td>
                    <td className="py-2 font-mono">{g.total_scans}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <div>
                <CardTitle>{t('dashboard.recentScansTitle')}</CardTitle>
                <CardDescription>{t('scans.queueSubtitle')}</CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => onNavigate('scans')}>
                {t('dashboard.openView')}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {scansQuery.data?.items.length ? (
              scansQuery.data.items.map((run) => {
                const pct =
                  run.total_chunks > 0
                    ? Math.round((run.completed_chunks / run.total_chunks) * 100)
                    : 0;
                const isActive = run.status === 'queued' || run.status === 'running';
                const isPaused = run.status === 'paused' || run.status === 'pausing';
                return (
                  <div
                    key={run.id}
                    className="border border-border bg-background p-3 space-y-2 text-xs"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Badge
                          variant={
                            run.status === 'completed'
                              ? 'success'
                              : isActive
                                ? 'default'
                                : isPaused
                                  ? 'warning'
                                  : 'destructive'
                          }
                        >
                          {run.status}
                        </Badge>
                        <span className="font-mono">
                          {run.completed_chunks}/{run.total_chunks} ({pct}%) · {run.total_targets} IP
                        </span>
                      </div>
                      {canControlScans && (isActive || isPaused) ? (
                        <div className="flex gap-1">
                          {isActive ? (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() =>
                                scanActionMutation.mutate({ id: run.id, action: 'pause' })
                              }
                            >
                              <Pause className="h-3 w-3" />
                            </Button>
                          ) : null}
                          {isPaused ? (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() =>
                                scanActionMutation.mutate({ id: run.id, action: 'resume' })
                              }
                            >
                              <Play className="h-3 w-3" />
                            </Button>
                          ) : null}
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() =>
                              scanActionMutation.mutate({ id: run.id, action: 'stop' })
                            }
                          >
                            <OctagonX className="h-3 w-3 text-red-400" />
                          </Button>
                        </div>
                      ) : null}
                    </div>
                    <div className="h-1.5 w-full overflow-hidden bg-secondary">
                      <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="text-sm text-muted-foreground">{t('scans.empty')}</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-2">
              <div>
                <CardTitle>{t('dashboard.recentDiffsTitle')}</CardTitle>
                <CardDescription>{t('diffs.subtitle')}</CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => onNavigate('diffs')}>
                {t('dashboard.openView')}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            {diffsQuery.data?.items.length ? (
              diffsQuery.data.items.map((ev) => (
                <div
                  key={ev.id}
                  className="border border-border bg-background p-3 space-y-1.5 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono font-bold">{ev.ip_addr}</span>
                    <div className="flex gap-1.5">
                      <Badge
                        variant={ev.event_kind === 'confirmed_change' ? 'default' : 'warning'}
                      >
                        {ev.event_kind}
                      </Badge>
                      <Badge variant="outline">{ev.severity}</Badge>
                    </div>
                  </div>
                  <ul className="space-y-0.5">
                    {ev.bullet_items.slice(0, 3).map((b, i) => (
                      <li key={i} className="text-muted-foreground">
                        {b.op} {formatBullet(t, b)}
                      </li>
                    ))}
                  </ul>
                </div>
              ))
            ) : (
              <p className="text-sm text-muted-foreground">{t('diffs.empty')}</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <div>
              <CardTitle>{t('health.title')}</CardTitle>
              <CardDescription>{t('health.description')}</CardDescription>
            </div>
            <div className="flex items-center gap-2">
              {healthQuery.isLoading ? (
                <Badge variant="outline">{t('health.checking')}</Badge>
              ) : healthQuery.isError ? (
                <Badge variant="destructive">{t('health.offline')}</Badge>
              ) : (
                <Badge variant="success">{t('health.online')}</Badge>
              )}
              <Button variant="outline" size="sm" onClick={() => void healthQuery.refetch()}>
                <RefreshCw className="h-3.5 w-3.5" />
                {t('health.refresh')}
              </Button>
            </div>
          </div>
        </CardHeader>
        {healthQuery.data ? (
          <CardContent>
            <dl className="grid gap-3 border border-border bg-background p-3 text-xs sm:grid-cols-3">
              <div>
                <dt className="text-muted-foreground">{t('health.service')}</dt>
                <dd className="font-mono">{healthQuery.data.service}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t('health.version')}</dt>
                <dd className="font-mono">{healthQuery.data.version}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">{t('health.timestamp')}</dt>
                <dd className="font-mono">{healthQuery.data.timestamp}</dd>
              </div>
            </dl>
          </CardContent>
        ) : null}
      </Card>
    </div>
  );
}
