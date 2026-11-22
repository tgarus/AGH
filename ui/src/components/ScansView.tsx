import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Calculator, OctagonX, Pause, Play, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError, type PreflightResponse } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

export function ScansView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [windowMinutes, setWindowMinutes] = useState(120);
  const [preflight, setPreflight] = useState<PreflightResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const groupsQuery = useQuery({
    queryKey: ['asset-groups'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/asset-groups', {
        params: { query: { page: 1, per_page: 100 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load asset groups.'));
      }
      return data;
    },
  });

  const scansQuery = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/scans', {
        params: { query: { page: 1, per_page: 50 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load scans.'));
      }
      return data;
    },
    refetchInterval: 4000,
  });

  const activeGroupId = selectedGroupId || groupsQuery.data?.items[0]?.id || '';

  const preflightMutation = useMutation({
    mutationFn: async () => {
      if (!activeGroupId) {
        throw new Error(t('scans.noGroupSelected'));
      }
      const { data, error } = await apiClient.POST('/api/v1/scans/preflight', {
        body: {
          asset_group_id: activeGroupId,
          window_minutes: windowMinutes,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Preflight check failed.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setErrorMsg(null);
      setPreflight(res);
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const startScanMutation = useMutation({
    mutationFn: async () => {
      if (!activeGroupId) {
        throw new Error(t('scans.noGroupSelected'));
      }
      const { data, error } = await apiClient.POST('/api/v1/scans', {
        body: {
          asset_group_id: activeGroupId,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to start scan.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const actionMutation = useMutation({
    mutationFn: async ({
      id,
      action,
    }: {
      id: string;
      action: 'pause' | 'resume' | 'stop';
    }) => {
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
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const canControlScans = hasPermission('run_or_stop_scans');

  const statusVariant = (status: string) => {
    if (status === 'completed') return 'success' as const;
    if (status === 'running' || status === 'queued') return 'default' as const;
    if (status === 'pausing' || status === 'paused' || status === 'stopping') {
      return 'warning' as const;
    }
    return 'destructive' as const;
  };

  return (
    <div className="space-y-6">
      {errorMsg ? (
        <div className="rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {errorMsg}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>{t('scans.launchTitle')}</CardTitle>
          <CardDescription>{t('scans.launchSubtitle')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-4">
            <select
              value={activeGroupId}
              onChange={(e) => {
                setSelectedGroupId(e.target.value);
                setPreflight(null);
              }}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm sm:col-span-2"
            >
              {groupsQuery.data?.items.map((grp) => (
                <option key={grp.id} value={grp.id}>
                  {grp.name} ({grp.target_count})
                </option>
              ))}
            </select>

            <input
              type="number"
              min={5}
              max={1440}
              value={windowMinutes}
              onChange={(e) => setWindowMinutes(Number(e.target.value) || 120)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              title={t('scans.windowMinutes')}
            />

            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                className="flex-1"
                onClick={() => preflightMutation.mutate()}
                disabled={!activeGroupId || preflightMutation.isPending}
              >
                <Calculator className="h-4 w-4" />
                {t('scans.preflightBtn')}
              </Button>
              {canControlScans ? (
                <Button
                  size="sm"
                  className="flex-1"
                  onClick={() => startScanMutation.mutate()}
                  disabled={!activeGroupId || startScanMutation.isPending}
                >
                  <Play className="h-4 w-4" />
                  {t('scans.startBtn')}
                </Button>
              ) : null}
            </div>
          </div>

          {preflight ? (
            <div className="rounded-md border border-border bg-background/60 p-4 text-sm">
              <div className="grid gap-4 sm:grid-cols-4">
                <div>
                  <div className="text-xs text-muted-foreground">{t('scans.preflightTargets')}</div>
                  <div className="font-mono text-lg font-semibold">{preflight.total_targets}</div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">{t('scans.preflightChunks')}</div>
                  <div className="font-mono text-lg font-semibold">
                    {preflight.total_chunks} ({preflight.chunk_size} IP)
                  </div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">{t('scans.preflightDuration')}</div>
                  <div className="font-mono text-lg font-semibold">
                    {preflight.estimated_duration_seconds}s
                  </div>
                </div>
                <div>
                  <div className="text-xs text-muted-foreground">{t('scans.preflightFits')}</div>
                  <Badge variant={preflight.fits_in_window ? 'success' : 'warning'}>
                    {preflight.fits_in_window ? t('scans.fitsYes') : t('scans.fitsNo')}
                  </Badge>
                </div>
              </div>
              {preflight.warnings.length > 0 ? (
                <ul className="mt-3 space-y-1 text-xs text-amber-300">
                  {preflight.warnings.map((w, idx) => (
                    <li key={idx}>• {w}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <div>
              <CardTitle>{t('scans.queueTitle')}</CardTitle>
              <CardDescription>{t('scans.queueSubtitle')}</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => void scansQuery.refetch()}>
              <RefreshCw className="h-4 w-4" />
              {t('health.refresh')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">{t('scans.colStatus')}</th>
                  <th className="px-3 py-2">{t('scans.colProgress')}</th>
                  <th className="px-3 py-2">{t('scans.colTargets')}</th>
                  <th className="px-3 py-2">{t('scans.colEta')}</th>
                  <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {scansQuery.data?.items.length ? (
                  scansQuery.data.items.map((run) => {
                    const pct =
                      run.total_chunks > 0
                        ? Math.round((run.completed_chunks / run.total_chunks) * 100)
                        : 0;
                    const isActive = run.status === 'queued' || run.status === 'running';
                    const isPaused = run.status === 'paused' || run.status === 'pausing';
                    const isStoppable = isActive || isPaused;

                    return (
                      <tr key={run.id} className="border-b border-border/60 last:border-0">
                        <td className="px-3 py-2">
                          <Badge variant={statusVariant(run.status)}>{run.status}</Badge>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">
                          {run.completed_chunks}/{run.total_chunks} ({pct}%)
                        </td>
                        <td className="px-3 py-2 font-mono">{run.total_targets}</td>
                        <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                          {run.estimated_finish_at ?? '—'}
                        </td>
                        <td className="px-3 py-2 text-right">
                          {canControlScans ? (
                            <div className="inline-flex gap-1">
                              {isActive ? (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => actionMutation.mutate({ id: run.id, action: 'pause' })}
                                >
                                  <Pause className="h-3.5 w-3.5" />
                                  {t('scans.pauseBtn')}
                                </Button>
                              ) : null}
                              {isPaused ? (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => actionMutation.mutate({ id: run.id, action: 'resume' })}
                                >
                                  <Play className="h-3.5 w-3.5" />
                                  {t('scans.resumeBtn')}
                                </Button>
                              ) : null}
                              {isStoppable ? (
                                <Button
                                  variant="outline"
                                  size="sm"
                                  onClick={() => actionMutation.mutate({ id: run.id, action: 'stop' })}
                                >
                                  <OctagonX className="h-3.5 w-3.5 text-red-400" />
                                  {t('scans.stopBtn')}
                                </Button>
                              ) : null}
                            </div>
                          ) : null}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} className="px-3 py-4 text-center text-muted-foreground">
                      {t('scans.empty')}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
