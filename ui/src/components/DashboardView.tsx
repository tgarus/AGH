import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, BarChart3, ExternalLink, OctagonX, Pause, Play, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';
import { cn } from '@/lib/utils';
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
  const [selectedScanRunId, setSelectedScanRunId] = useState<string | null>(null);
  const [hoveredScanRunId, setHoveredScanRunId] = useState<string | null>(null);

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

  const activeScanPoint =
    analytics?.recent_scans.find(
      (p) => p.scan_run_id === (hoveredScanRunId || selectedScanRunId),
    ) ??
    (analytics?.recent_scans.length
      ? analytics.recent_scans[analytics.recent_scans.length - 1]
      : null);

  const totalRecentTargets = (analytics?.recent_scans ?? []).reduce(
    (acc, p) => acc + p.total_targets,
    0,
  );
  const totalRecentDiffs = (analytics?.recent_scans ?? []).reduce(
    (acc, p) => acc + p.confirmed_diffs,
    0,
  );
  const avgScanDuration = analytics?.recent_scans.length
    ? Math.round(
        analytics.recent_scans.reduce((acc, p) => acc + (p.duration_seconds ?? 0), 0) /
          analytics.recent_scans.length,
      )
    : 0;

  const formatScanTime = (isoString: string) => {
    try {
      const d = new Date(isoString);
      if (!isNaN(d.getTime())) {
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      }
    } catch {
      // fallback
    }
    return isoString.slice(11, 16) || '—';
  };

  const formatFullDateTime = (isoString: string) => {
    try {
      const d = new Date(isoString);
      if (!isNaN(d.getTime())) {
        return d.toLocaleString([], {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
        });
      }
    } catch {
      // fallback
    }
    return isoString;
  };

  const scans = analytics?.recent_scans ?? [];
  const svgWidth = 560;
  const svgHeight = 180;
  const padLeft = 45;
  const padRight = 45;
  const padTop = 20;
  const padBottom = 30;
  const plotWidth = svgWidth - padLeft - padRight;
  const plotHeight = svgHeight - padTop - padBottom;

  const chartPoints = scans.map((pt, i) => {
    const x =
      scans.length > 1
        ? padLeft + (i / (scans.length - 1)) * plotWidth
        : padLeft + plotWidth / 2;
    const targetNorm = maxScanTargets > 0 ? pt.total_targets / maxScanTargets : 0;
    const durNorm = maxScanDuration > 0 ? (pt.duration_seconds ?? 0) / maxScanDuration : 0;
    const yTarget = padTop + (1 - targetNorm) * plotHeight;
    const yDuration = padTop + (1 - durNorm) * plotHeight;
    const timeStr = formatScanTime(pt.started_at);
    return {
      ...pt,
      x,
      yTarget,
      yDuration,
      timeStr,
    };
  });

  const targetPathD =
    chartPoints.length > 0
      ? chartPoints
          .map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.yTarget.toFixed(1)}`)
          .join(' ')
      : '';

  const targetAreaD =
    chartPoints.length > 0 && chartPoints[0] && chartPoints[chartPoints.length - 1]
      ? `${targetPathD} L ${chartPoints[chartPoints.length - 1]!.x.toFixed(1)} ${(padTop + plotHeight).toFixed(1)} L ${chartPoints[0]!.x.toFixed(1)} ${(padTop + plotHeight).toFixed(1)} Z`
      : '';

  const durationPathD =
    chartPoints.length > 0
      ? chartPoints
          .map((p, idx) => `${idx === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.yDuration.toFixed(1)}`)
          .join(' ')
      : '';

  const durationAreaD =
    chartPoints.length > 0 && chartPoints[0] && chartPoints[chartPoints.length - 1]
      ? `${durationPathD} L ${chartPoints[chartPoints.length - 1]!.x.toFixed(1)} ${(padTop + plotHeight).toFixed(1)} L ${chartPoints[0]!.x.toFixed(1)} ${(padTop + plotHeight).toFixed(1)} Z`
      : '';

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
        <Card className="overflow-hidden">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-primary" />
                  {t('dashboard.analytics.recentScansChartTitle')}
                </CardTitle>
                <CardDescription>{t('dashboard.analytics.recentScansChartSubtitle')}</CardDescription>
              </div>
              {analytics?.recent_scans.length ? (
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="rounded bg-muted px-2 py-0.5 text-muted-foreground">
                    {analytics.recent_scans.length} {t('dashboard.kpiScansWorkers').split('/')[0]?.trim().toLowerCase() ?? 'scans'}
                  </span>
                  <span className="rounded bg-sky-950/60 text-sky-300 border border-sky-800/60 px-2 py-0.5">
                    {totalRecentTargets} IP
                  </span>
                  {totalRecentDiffs > 0 ? (
                    <span className="rounded bg-rose-950/60 text-rose-300 border border-rose-800/60 px-2 py-0.5 font-bold">
                      +{totalRecentDiffs} diff
                    </span>
                  ) : null}
                </div>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className="space-y-3 overflow-hidden">
            {analytics?.recent_scans.length ? (
              <div className="space-y-3">
                {/* Visual Legend */}
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2 text-[11px] text-muted-foreground">
                  <div className="flex flex-wrap items-center gap-4">
                    <span className="flex items-center gap-1.5 font-medium">
                      <span className="inline-block h-2.5 w-2.5 rounded-sm bg-sky-500 shadow-sm" />
                      {t('dashboard.analytics.legendTargets')}
                      <span className="font-mono text-[10px] text-sky-400">
                        (max {maxScanTargets})
                      </span>
                    </span>
                    <span className="flex items-center gap-1.5 font-medium">
                      <span className="inline-block h-2.5 w-2.5 rounded-sm bg-amber-500 shadow-sm" />
                      {t('dashboard.analytics.legendDuration')}
                      <span className="font-mono text-[10px] text-amber-400">
                        (max {maxScanDuration}s, avg {avgScanDuration}s)
                      </span>
                    </span>
                    <span className="flex items-center gap-1.5 font-medium">
                      <span className="inline-block h-2.5 w-2.5 rounded-sm bg-rose-500 shadow-sm" />
                      {t('dashboard.analytics.legendConfirmedDiffs')}
                    </span>
                  </div>
                </div>

                {/* Responsive Dual-Line SVG Chart - No Horizontal Overflow */}
                <div className="relative rounded-lg border border-border/80 bg-background/50 p-2 overflow-hidden">
                  <svg
                    viewBox={`0 0 ${svgWidth} ${svgHeight}`}
                    className="w-full h-44 select-none overflow-hidden"
                    preserveAspectRatio="none"
                  >
                    <defs>
                      <linearGradient id="targetGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.25" />
                        <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
                      </linearGradient>
                      <linearGradient id="durationGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#fbbf24" stopOpacity="0.2" />
                        <stop offset="100%" stopColor="#fbbf24" stopOpacity="0.0" />
                      </linearGradient>
                    </defs>

                    {/* Horizontal Grid Guide Lines & Y-axis labels */}
                    {/* 100% line */}
                    <line
                      x1={padLeft}
                      y1={padTop}
                      x2={svgWidth - padRight}
                      y2={padTop}
                      stroke="#334155"
                      strokeWidth="1"
                      strokeDasharray="3 3"
                    />
                    <text
                      x={padLeft - 6}
                      y={padTop + 3}
                      textAnchor="end"
                      fill="#38bdf8"
                      fontSize="9"
                      fontFamily="monospace"
                      fontWeight="bold"
                    >
                      {maxScanTargets}
                    </text>
                    <text
                      x={svgWidth - padRight + 6}
                      y={padTop + 3}
                      textAnchor="start"
                      fill="#fbbf24"
                      fontSize="9"
                      fontFamily="monospace"
                      fontWeight="bold"
                    >
                      {maxScanDuration}s
                    </text>

                    {/* 50% line */}
                    <line
                      x1={padLeft}
                      y1={padTop + plotHeight / 2}
                      x2={svgWidth - padRight}
                      y2={padTop + plotHeight / 2}
                      stroke="#334155"
                      strokeWidth="1"
                      strokeDasharray="3 3"
                      strokeOpacity="0.6"
                    />
                    <text
                      x={padLeft - 6}
                      y={padTop + plotHeight / 2 + 3}
                      textAnchor="end"
                      fill="#38bdf8"
                      fontSize="8"
                      fontFamily="monospace"
                      opacity="0.75"
                    >
                      {Math.round(maxScanTargets / 2)}
                    </text>
                    <text
                      x={svgWidth - padRight + 6}
                      y={padTop + plotHeight / 2 + 3}
                      textAnchor="start"
                      fill="#fbbf24"
                      fontSize="8"
                      fontFamily="monospace"
                      opacity="0.75"
                    >
                      {Math.round(maxScanDuration / 2)}s
                    </text>

                    {/* 0% baseline */}
                    <line
                      x1={padLeft}
                      y1={padTop + plotHeight}
                      x2={svgWidth - padRight}
                      y2={padTop + plotHeight}
                      stroke="#475569"
                      strokeWidth="1"
                    />
                    <text
                      x={padLeft - 6}
                      y={padTop + plotHeight + 3}
                      textAnchor="end"
                      fill="#38bdf8"
                      fontSize="8"
                      fontFamily="monospace"
                      opacity="0.5"
                    >
                      0
                    </text>
                    <text
                      x={svgWidth - padRight + 6}
                      y={padTop + plotHeight + 3}
                      textAnchor="start"
                      fill="#fbbf24"
                      fontSize="8"
                      fontFamily="monospace"
                      opacity="0.5"
                    >
                      0s
                    </text>

                    {/* Vertical guideline for active point */}
                    {activeScanPoint ? (() => {
                      const curPt = chartPoints.find((p) => p.scan_run_id === activeScanPoint.scan_run_id);
                      if (!curPt) return null;
                      return (
                        <line
                          x1={curPt.x}
                          y1={padTop}
                          x2={curPt.x}
                          y2={padTop + plotHeight}
                          stroke="#94a3b8"
                          strokeWidth="1.5"
                          strokeDasharray="3 3"
                          opacity="0.8"
                        />
                      );
                    })() : null}

                    {/* Target Area and Line (Sky Blue) */}
                    {targetAreaD ? (
                      <path d={targetAreaD} fill="url(#targetGrad)" />
                    ) : null}
                    {targetPathD ? (
                      <path
                        d={targetPathD}
                        fill="none"
                        stroke="#38bdf8"
                        strokeWidth="2.5"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    ) : null}

                    {/* Duration Area and Line (Amber) */}
                    {durationAreaD ? (
                      <path d={durationAreaD} fill="url(#durationGrad)" />
                    ) : null}
                    {durationPathD ? (
                      <path
                        d={durationPathD}
                        fill="none"
                        stroke="#fbbf24"
                        strokeWidth="2"
                        strokeDasharray="4 2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    ) : null}

                    {/* Points and Labels */}
                    {chartPoints.map((p) => {
                      const isSelected = activeScanPoint?.scan_run_id === p.scan_run_id;
                      return (
                        <g key={p.scan_run_id}>
                          {/* Target Point Dot */}
                          <circle
                            cx={p.x}
                            cy={p.yTarget}
                            r={isSelected ? 5.5 : 3.5}
                            fill="#0284c7"
                            stroke="#38bdf8"
                            strokeWidth={isSelected ? 2.5 : 1.5}
                          />

                          {/* Duration Point Dot */}
                          <circle
                            cx={p.x}
                            cy={p.yDuration}
                            r={isSelected ? 5.5 : 3.5}
                            fill="#b45309"
                            stroke="#fbbf24"
                            strokeWidth={isSelected ? 2.5 : 1.5}
                          />

                          {/* Confirmed Diff Alert Badge */}
                          {p.confirmed_diffs > 0 ? (
                            <g>
                              <circle
                                cx={p.x}
                                cy={p.yTarget}
                                r={9}
                                fill="none"
                                stroke="#f43f5e"
                                strokeWidth="1.5"
                              />
                              <rect
                                x={p.x - 12}
                                y={Math.max(2, Math.min(p.yTarget, p.yDuration) - 18)}
                                width={24}
                                height={12}
                                rx={3}
                                fill="#881337"
                                stroke="#f43f5e"
                                strokeWidth="0.8"
                              />
                              <text
                                x={p.x}
                                y={Math.max(2, Math.min(p.yTarget, p.yDuration) - 9)}
                                textAnchor="middle"
                                fill="#fecdd3"
                                fontSize="8"
                                fontFamily="monospace"
                                fontWeight="bold"
                              >
                                +{p.confirmed_diffs}
                              </text>
                            </g>
                          ) : null}

                          {/* X-Axis Time Label */}
                          <text
                            x={p.x}
                            y={padTop + plotHeight + 16}
                            textAnchor="middle"
                            fill={isSelected ? '#f8fafc' : '#94a3b8'}
                            fontSize="9"
                            fontFamily="monospace"
                            fontWeight={isSelected ? 'bold' : 'normal'}
                          >
                            {p.timeStr}
                          </text>

                          {/* Transparent Interactive Click/Hover Slice */}
                          {(() => {
                            const sliceW = chartPoints.length > 1 ? plotWidth / (chartPoints.length - 1) : plotWidth;
                            return (
                              <rect
                                x={Math.max(0, p.x - sliceW / 2)}
                                y={padTop - 10}
                                width={sliceW}
                                height={plotHeight + 35}
                                fill="transparent"
                                className="cursor-pointer"
                                onMouseEnter={() => setHoveredScanRunId(p.scan_run_id)}
                                onMouseLeave={() => setHoveredScanRunId(null)}
                                onClick={() => setSelectedScanRunId(p.scan_run_id)}
                              />
                            );
                          })()}
                        </g>
                      );
                    })}
                  </svg>
                </div>

                {/* Active Scan Inspector / Details Strip */}
                {activeScanPoint ? (
                  <div className="rounded-lg border border-border/80 bg-background/80 p-2.5 text-xs overflow-hidden">
                    <div className="flex flex-wrap items-center justify-between gap-2.5">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={cn(
                            'inline-block h-2 w-2 rounded-full shrink-0',
                            activeScanPoint.status === 'completed'
                              ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.8)]'
                              : activeScanPoint.status === 'failed'
                                ? 'bg-rose-500 shadow-[0_0_6px_rgba(244,63,94,0.8)]'
                                : 'bg-amber-400 animate-pulse',
                          )}
                        />
                        <span className="font-semibold text-foreground truncate max-w-[150px] sm:max-w-[200px]">
                          {activeScanPoint.asset_group_name}
                        </span>
                        <Badge variant="outline" className="font-mono text-[10px] uppercase shrink-0">
                          {activeScanPoint.status}
                        </Badge>
                        <span className="text-[11px] text-muted-foreground font-mono truncate hidden sm:inline">
                          {formatFullDateTime(activeScanPoint.started_at)}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 font-mono text-[11px]">
                        <div className="flex items-center gap-1 text-sky-400">
                          <span className="text-muted-foreground">IPs:</span>
                          <span className="font-bold">{activeScanPoint.total_targets}</span>
                        </div>
                        <div className="flex items-center gap-1 text-amber-400">
                          <span className="text-muted-foreground">Duration:</span>
                          <span className="font-bold">
                            {activeScanPoint.duration_seconds !== null
                              ? `${activeScanPoint.duration_seconds}s`
                              : '—'}
                          </span>
                        </div>
                        <div className="flex items-center gap-1 text-muted-foreground">
                          <span>Chunks:</span>
                          <span className="text-foreground">
                            {activeScanPoint.completed_chunks}/{activeScanPoint.total_chunks}
                          </span>
                        </div>
                        {activeScanPoint.confirmed_diffs > 0 ? (
                          <div className="flex items-center gap-1 text-rose-400 font-bold">
                            <span>Diffs:</span>
                            <span>+{activeScanPoint.confirmed_diffs}</span>
                          </div>
                        ) : null}
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 text-[11px] px-2 text-primary hover:text-primary gap-1"
                          onClick={() => onNavigate('scans')}
                        >
                          {t('dashboard.openView')}
                          <ExternalLink className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  </div>
                ) : null}
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
