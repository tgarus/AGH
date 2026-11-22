import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Calculator,
  CalendarClock,
  Check,
  Eye,
  OctagonX,
  Pause,
  Pencil,
  Play,
  RefreshCw,
  Rocket,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  formatApiError,
  type PreflightResponse,
  type QuickScanResponse,
  type RecurringScanScheduleDto,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';
import { formatBullet } from '@/utils/formatBullet';

function countQuickTargets(raw: string) {
  let total = 0;
  let ips = 0;
  let cidrs = 0;
  let domains = 0;
  let excludes = 0;

  for (const line of raw.split(/\r?\n/)) {
    const trimmedLine = line.trim();
    if (!trimmedLine || trimmedLine.startsWith('#') || trimmedLine.startsWith('//')) {
      continue;
    }
    const body = trimmedLine.split('#')[0]?.trim() ?? '';
    for (const token of body.split(/[\s,;]+/)) {
      const t = token.trim();
      if (!t) {
        continue;
      }
      total += 1;
      if (t.startsWith('!')) {
        excludes += 1;
      } else if (t.includes('/')) {
        cidrs += 1;
      } else if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t) || t.includes(':')) {
        ips += 1;
      } else {
        domains += 1;
      }
    }
  }
  return { total, ips, cidrs, domains, excludes };
}

function formatShortDateTime(iso?: string | null) {
  if (!iso) {
    return '—';
  }
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function ScansView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [windowMinutes, setWindowMinutes] = useState(120);
  const [includeIgnoredIds, setIncludeIgnoredIds] = useState<string[]>([]);
  const [includeAllIgnored, setIncludeAllIgnored] = useState(false);
  const [recurringEnabled, setRecurringEnabled] = useState(false);
  const [intervalValue, setIntervalValue] = useState(6);
  const [intervalUnit, setIntervalUnit] = useState<'minutes' | 'hours'>('hours');
  const [firstRunTime, setFirstRunTime] = useState('02:00');
  const [editingScheduleId, setEditingScheduleId] = useState<string | null>(null);
  const [editIntervalValue, setEditIntervalValue] = useState(6);
  const [editIntervalUnit, setEditIntervalUnit] = useState<'minutes' | 'hours'>('hours');
  const [editFirstRunTime, setEditFirstRunTime] = useState('02:00');
  const [editWindowMinutes, setEditWindowMinutes] = useState(120);
  const [editIncludeAllIgnored, setEditIncludeAllIgnored] = useState(false);
  const [editIncludeIgnoredIds, setEditIncludeIgnoredIds] = useState<string[]>([]);
  const [exploringScanId, setExploringScanId] = useState<string | null>(null);
  const [preflight, setPreflight] = useState<PreflightResponse | null>(null);
  const [quickTargetsRaw, setQuickTargetsRaw] = useState('');
  const [quickGroupId, setQuickGroupId] = useState('');
  const [quickGroupName, setQuickGroupName] = useState('');
  const [quickPortSpec, setQuickPortSpec] = useState('');
  const [quickRatePps, setQuickRatePps] = useState('');
  const [quickFeedback, setQuickFeedback] = useState<QuickScanResponse | null>(null);
  const quickFileRef = useRef<HTMLInputElement>(null);
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

  const ignoredTargetsQuery = useQuery({
    queryKey: ['ignored-targets'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/ignored-targets', {
        params: { query: { page: 1, per_page: 200 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load ignored targets.'));
      }
      return data;
    },
  });

  const applicableIgnored = (ignoredTargetsQuery.data?.items ?? []).filter(
    (it) => it.asset_group_id === null || it.asset_group_id === activeGroupId,
  );

  const exploreQuery = useQuery({
    queryKey: ['scan-explore', exploringScanId],
    enabled: Boolean(exploringScanId),
    queryFn: async () => {
      if (!exploringScanId) {
        throw new Error('No scan selected');
      }
      const { data, error } = await apiClient.GET('/api/v1/scans/{id}/explore', {
        params: { path: { id: exploringScanId } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load scan details.'));
      }
      return data;
    },
  });

  const preflightMutation = useMutation({
    mutationFn: async () => {
      if (!activeGroupId) {
        throw new Error(t('scans.noGroupSelected'));
      }
      const { data, error } = await apiClient.POST('/api/v1/scans/preflight', {
        body: {
          asset_group_id: activeGroupId,
          window_minutes: windowMinutes,
          include_ignored_ids: includeIgnoredIds,
          include_all_ignored: includeAllIgnored,
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

  const recurringQuery = useQuery({
    queryKey: ['recurring-scans'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/scans/recurring');
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load recurring scans.'));
      }
      return data;
    },
    refetchInterval: 10000,
  });

  const startScanMutation = useMutation({
    mutationFn: async () => {
      if (!activeGroupId) {
        throw new Error(t('scans.noGroupSelected'));
      }
      const { data, error } = await apiClient.POST('/api/v1/scans', {
        body: {
          asset_group_id: activeGroupId,
          include_ignored_ids: includeIgnoredIds,
          include_all_ignored: includeAllIgnored,
          recurring_enabled: recurringEnabled,
          interval_value: recurringEnabled ? intervalValue : null,
          interval_unit: recurringEnabled ? intervalUnit : null,
          first_run_time: recurringEnabled ? firstRunTime : null,
          window_minutes: recurringEnabled ? windowMinutes : null,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to start scan.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      setIncludeIgnoredIds([]);
      setIncludeAllIgnored(false);
      setRecurringEnabled(false);
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
      void queryClient.invalidateQueries({ queryKey: ['recurring-scans'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const handleStartEdit = (sched: RecurringScanScheduleDto) => {
    setEditingScheduleId(sched.id);
    setEditIntervalValue(sched.interval_value);
    setEditIntervalUnit(sched.interval_unit === 'minutes' ? 'minutes' : 'hours');
    setEditFirstRunTime(sched.first_run_time);
    setEditWindowMinutes(sched.window_minutes);
    setEditIncludeAllIgnored(sched.include_all_ignored);
    setEditIncludeIgnoredIds(sched.include_ignored_ids ?? []);
  };

  const updateRecurringMutation = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await apiClient.PATCH('/api/v1/scans/recurring/{id}', {
        params: { path: { id } },
        body: {
          interval_value: editIntervalValue,
          interval_unit: editIntervalUnit,
          first_run_time: editFirstRunTime,
          window_minutes: editWindowMinutes,
          include_all_ignored: editIncludeAllIgnored,
          include_ignored_ids: editIncludeIgnoredIds,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to update recurring scan.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      setEditingScheduleId(null);
      void queryClient.invalidateQueries({ queryKey: ['recurring-scans'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const deleteRecurringMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await apiClient.DELETE('/api/v1/scans/recurring/{id}', {
        params: { path: { id } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to stop recurring scan.'));
      }
    },
    onSuccess: (_res, id) => {
      setErrorMsg(null);
      if (editingScheduleId === id) {
        setEditingScheduleId(null);
      }
      void queryClient.invalidateQueries({ queryKey: ['recurring-scans'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const runRecurringNowMutation = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await apiClient.POST('/api/v1/scans/recurring/{id}/run-now', {
        params: { path: { id } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to trigger recurring scan.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
      void queryClient.invalidateQueries({ queryKey: ['recurring-scans'] });
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

  const quickScanMutation = useMutation({
    mutationFn: async () => {
      const rateNum = quickRatePps.trim() ? Number(quickRatePps.trim()) : null;
      const { data, error } = await apiClient.POST('/api/v1/scans/quick', {
        body: {
          targets_raw: quickTargetsRaw,
          asset_group_id: quickGroupId || null,
          group_name: !quickGroupId && quickGroupName.trim() ? quickGroupName.trim() : null,
          port_spec: quickPortSpec.trim() || null,
          rate_pps: rateNum && Number.isFinite(rateNum) && rateNum > 0 ? rateNum : null,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Quick scan launch failed.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setErrorMsg(null);
      setQuickFeedback(res);
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
      void queryClient.invalidateQueries({ queryKey: ['asset-groups'] });
    },
    onError: (err) => {
      setQuickFeedback(null);
      setErrorMsg(err.message);
    },
  });

  const canControlScans = hasPermission('run_or_stop_scans');
  const canQuickScan = canControlScans && hasPermission('manage_asset_groups');
  const quickCounts = countQuickTargets(quickTargetsRaw);
  const editingSchedule =
    (recurringQuery.data ?? []).find((item) => item.id === editingScheduleId) ?? null;
  const editingApplicableIgnored = editingSchedule
    ? (ignoredTargetsQuery.data?.items ?? []).filter(
        (it) => it.asset_group_id === null || it.asset_group_id === editingSchedule.asset_group_id,
      )
    : [];

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

      {canQuickScan ? (
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle>{t('scans.quickTitle')}</CardTitle>
                <CardDescription>{t('scans.quickSubtitle')}</CardDescription>
              </div>
              <div>
                <input
                  ref={quickFileRef}
                  type="file"
                  accept=".txt,.csv,.json"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) {
                      void file.text().then((txt) => setQuickTargetsRaw(txt));
                    }
                    e.target.value = '';
                  }}
                />
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => quickFileRef.current?.click()}
                >
                  <Upload className="h-4 w-4" />
                  {t('io.loadFile')}
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <textarea
              rows={4}
              value={quickTargetsRaw}
              onChange={(e) => setQuickTargetsRaw(e.target.value)}
              placeholder={t('scans.quickPlaceholder')}
              className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs"
            />
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge variant="outline">
                {t('scans.quickCountTotal', { count: quickCounts.total })}
              </Badge>
              {quickCounts.ips > 0 ? <Badge variant="default">IP: {quickCounts.ips}</Badge> : null}
              {quickCounts.cidrs > 0 ? (
                <Badge variant="default">CIDR: {quickCounts.cidrs}</Badge>
              ) : null}
              {quickCounts.domains > 0 ? (
                <Badge variant="default">Domain: {quickCounts.domains}</Badge>
              ) : null}
              {quickCounts.excludes > 0 ? (
                <Badge variant="warning">Exclude: {quickCounts.excludes}</Badge>
              ) : null}
            </div>

            <div className="grid gap-2 sm:grid-cols-4">
              <select
                value={quickGroupId}
                onChange={(e) => setQuickGroupId(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              >
                <option value="">{t('scans.quickAutoGroup')}</option>
                {groupsQuery.data?.items.map((grp) => (
                  <option key={grp.id} value={grp.id}>
                    {grp.name}
                  </option>
                ))}
              </select>
              {!quickGroupId ? (
                <input
                  type="text"
                  value={quickGroupName}
                  onChange={(e) => setQuickGroupName(e.target.value)}
                  placeholder={t('scans.quickGroupNamePlaceholder')}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              ) : (
                <div className="hidden sm:block" />
              )}
              <input
                type="text"
                value={quickPortSpec}
                onChange={(e) => setQuickPortSpec(e.target.value)}
                placeholder={t('scans.quickPortPlaceholder')}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm font-mono"
              />
              <div className="flex gap-2">
                <input
                  type="number"
                  min={1}
                  value={quickRatePps}
                  onChange={(e) => setQuickRatePps(e.target.value)}
                  placeholder={t('scans.quickRatePlaceholder')}
                  className="w-28 rounded-md border border-border bg-background px-3 py-2 text-sm font-mono"
                />
                <Button
                  size="sm"
                  className="flex-1"
                  onClick={() => quickScanMutation.mutate()}
                  disabled={quickCounts.total === 0 || quickScanMutation.isPending}
                >
                  <Rocket className="h-4 w-4" />
                  {t('scans.quickLaunchBtn')}
                </Button>
              </div>
            </div>

            {quickFeedback ? (
              <div className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-300">
                {t('scans.quickStarted', {
                  group: quickFeedback.asset_group_name,
                  count: quickFeedback.imported_targets,
                })}
              </div>
            ) : null}
          </CardContent>
        </Card>
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
                setIncludeIgnoredIds([]);
                setIncludeAllIgnored(false);
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
                  {recurringEnabled ? (
                    <CalendarClock className="h-4 w-4" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  {recurringEnabled
                    ? t('scans.recurringStartAndScheduleBtn')
                    : t('scans.startBtn')}
                </Button>
              ) : null}
            </div>
          </div>

          {canControlScans ? (
            <div className="space-y-3 rounded-md border border-border bg-secondary/20 p-3 text-xs">
              <label className="flex cursor-pointer items-center gap-2 font-medium text-foreground">
                <input
                  type="checkbox"
                  checked={recurringEnabled}
                  onChange={(e) => setRecurringEnabled(e.target.checked)}
                />
                <CalendarClock className="h-4 w-4 text-primary" />
                <span>{t('scans.recurringToggle')}</span>
              </label>

              {recurringEnabled ? (
                <div className="space-y-2 border-t border-border/60 pt-2.5">
                  <div className="grid gap-3 sm:grid-cols-3">
                    <div className="space-y-1">
                      <div className="text-muted-foreground">{t('scans.recurringIntervalLabel')}</div>
                      <div className="flex gap-2">
                        <input
                          type="number"
                          min={1}
                          max={10080}
                          value={intervalValue}
                          onChange={(e) =>
                            setIntervalValue(Math.max(1, Number(e.target.value) || 1))
                          }
                          className="w-24 rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm"
                        />
                        <select
                          value={intervalUnit}
                          onChange={(e) =>
                            setIntervalUnit(e.target.value === 'minutes' ? 'minutes' : 'hours')
                          }
                          className="flex-1 rounded-md border border-border bg-background px-2.5 py-1.5 text-sm"
                        >
                          <option value="minutes">{t('scans.recurringUnitMinutes')}</option>
                          <option value="hours">{t('scans.recurringUnitHours')}</option>
                        </select>
                      </div>
                    </div>

                    <div className="space-y-1">
                      <div className="text-muted-foreground">{t('scans.recurringFirstRunTime')}</div>
                      <input
                        type="time"
                        value={firstRunTime}
                        onChange={(e) => setFirstRunTime(e.target.value || '02:00')}
                        className="w-full rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm"
                      />
                    </div>

                    <div className="flex items-end pb-1.5 text-muted-foreground">
                      <span>{t('scans.recurringWindowHint', { minutes: windowMinutes })}</span>
                    </div>
                  </div>
                  <p className="text-muted-foreground">
                    {t('scans.recurringSummaryHint', {
                      value: intervalValue,
                      unit:
                        intervalUnit === 'minutes'
                          ? t('scans.recurringUnitMinutes')
                          : t('scans.recurringUnitHours'),
                      time: firstRunTime,
                    })}
                  </p>
                </div>
              ) : null}
            </div>
          ) : null}

          {applicableIgnored.length > 0 ? (
            <div className="space-y-2 rounded-md border border-amber-800/70 bg-amber-950/20 p-3 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2 font-semibold text-amber-200">
                  <ShieldCheck className="h-4 w-4 text-amber-400" />
                  {t('scans.ignoredOverrideTitle', { count: applicableIgnored.length })}
                </div>
                <label className="flex cursor-pointer items-center gap-1.5 text-amber-100">
                  <input
                    type="checkbox"
                    checked={includeAllIgnored}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setIncludeAllIgnored(next);
                      setIncludeIgnoredIds(next ? applicableIgnored.map((it) => it.id) : []);
                    }}
                  />
                  <span>{t('scans.includeAllIgnoredOneShot')}</span>
                </label>
              </div>
              <p className="text-muted-foreground">{t('scans.ignoredOverrideHint')}</p>
              <div className="flex flex-wrap gap-2">
                {applicableIgnored.map((it) => {
                  const checked = includeAllIgnored || includeIgnoredIds.includes(it.id);
                  return (
                    <label
                      key={it.id}
                      className="flex cursor-pointer items-center gap-1.5 rounded border border-border bg-background/80 px-2.5 py-1 hover:bg-secondary/60"
                      title={it.reason}
                    >
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={includeAllIgnored}
                        onChange={(e) =>
                          setIncludeIgnoredIds((prev) =>
                            e.target.checked
                              ? [...prev, it.id]
                              : prev.filter((id) => id !== it.id),
                          )
                        }
                      />
                      <Badge variant="outline">{it.asset_group_id ? 'GROUP' : 'GLOBAL'}</Badge>
                      <span className="font-mono">{it.value}</span>
                      <span className="text-muted-foreground">({it.reason})</span>
                    </label>
                  );
                })}
              </div>
            </div>
          ) : null}

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
              <CardTitle className="flex items-center gap-2">
                <CalendarClock className="h-4 w-4 text-primary" />
                {t('scans.recurringTableTitle')}
              </CardTitle>
              <CardDescription>{t('scans.recurringTableSubtitle')}</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => void recurringQuery.refetch()}>
              <RefreshCw className="h-4 w-4" />
              {t('health.refresh')}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-sm">
              <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">{t('scans.recurringColGroup')}</th>
                  <th className="px-3 py-2">{t('scans.recurringColFrequency')}</th>
                  <th className="px-3 py-2">{t('scans.recurringColFirstRun')}</th>
                  <th className="px-3 py-2">{t('scans.recurringColIgnored')}</th>
                  <th className="px-3 py-2">{t('scans.recurringColLastRun')}</th>
                  <th className="px-3 py-2">{t('scans.recurringColNextRun')}</th>
                  <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {recurringQuery.data?.length ? (
                  recurringQuery.data.map((sched) => {
                    const freqLabel =
                      sched.interval_unit === 'minutes'
                        ? t('scans.recurringEveryMinutes', { value: sched.interval_value })
                        : t('scans.recurringEveryHours', { value: sched.interval_value });

                    return (
                      <tr key={sched.id} className="border-b border-border/60 last:border-0">
                        <td className="px-3 py-2 font-medium">{sched.asset_group_name}</td>
                        <td className="px-3 py-2 font-mono text-xs">
                          <span>{freqLabel}</span>{' '}
                          <span className="text-muted-foreground">
                            ({sched.window_minutes}m)
                          </span>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">{sched.first_run_time}</td>
                        <td className="px-3 py-2">
                          {sched.include_all_ignored ? (
                            <Badge variant="warning">{t('scans.recurringIgnoredAll')}</Badge>
                          ) : sched.include_ignored_ids.length > 0 ? (
                            <Badge variant="warning">
                              {t('scans.recurringIgnoredCount', {
                                count: sched.include_ignored_ids.length,
                              })}
                            </Badge>
                          ) : (
                            <Badge variant="outline">{t('scans.recurringIgnoredDefault')}</Badge>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                          {sched.last_run_at
                            ? formatShortDateTime(sched.last_run_at)
                            : t('scans.recurringNeverRun')}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">
                          {formatShortDateTime(sched.next_run_at)}
                        </td>
                        <td className="px-3 py-2 text-right">
                          {canControlScans ? (
                            <div className="inline-flex flex-wrap justify-end gap-1">
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={runRecurringNowMutation.isPending}
                                onClick={() => runRecurringNowMutation.mutate(sched.id)}
                              >
                                <Play className="h-3.5 w-3.5" />
                                {t('scans.recurringRunNowBtn')}
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => handleStartEdit(sched)}
                              >
                                <Pencil className="h-3.5 w-3.5" />
                                {t('scans.recurringEditBtn')}
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                disabled={deleteRecurringMutation.isPending}
                                onClick={() => deleteRecurringMutation.mutate(sched.id)}
                              >
                                <Trash2 className="h-3.5 w-3.5 text-red-400" />
                                {t('scans.recurringStopBtn')}
                              </Button>
                            </div>
                          ) : null}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={7} className="px-3 py-4 text-center text-muted-foreground">
                      {t('scans.recurringEmpty')}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {editingSchedule && canControlScans ? (
            <div className="space-y-3 rounded-md border border-primary/50 bg-secondary/25 p-4 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-semibold text-foreground">
                  {t('scans.recurringEditHint', { group: editingSchedule.asset_group_name })}
                </span>
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    disabled={updateRecurringMutation.isPending}
                    onClick={() => updateRecurringMutation.mutate(editingSchedule.id)}
                  >
                    <Check className="h-3.5 w-3.5" />
                    {t('scans.recurringSaveBtn')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setEditingScheduleId(null)}
                  >
                    <X className="h-3.5 w-3.5" />
                    {t('scans.recurringCancelBtn')}
                  </Button>
                </div>
              </div>

              <div className="grid gap-3 sm:grid-cols-3">
                <div className="space-y-1">
                  <div className="text-muted-foreground">{t('scans.recurringIntervalLabel')}</div>
                  <div className="flex gap-2">
                    <input
                      type="number"
                      min={1}
                      max={10080}
                      value={editIntervalValue}
                      onChange={(e) =>
                        setEditIntervalValue(Math.max(1, Number(e.target.value) || 1))
                      }
                      className="w-24 rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm"
                    />
                    <select
                      value={editIntervalUnit}
                      onChange={(e) =>
                        setEditIntervalUnit(e.target.value === 'minutes' ? 'minutes' : 'hours')
                      }
                      className="flex-1 rounded-md border border-border bg-background px-2.5 py-1.5 text-sm"
                    >
                      <option value="minutes">{t('scans.recurringUnitMinutes')}</option>
                      <option value="hours">{t('scans.recurringUnitHours')}</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1">
                  <div className="text-muted-foreground">{t('scans.recurringFirstRunTime')}</div>
                  <input
                    type="time"
                    value={editFirstRunTime}
                    onChange={(e) => setEditFirstRunTime(e.target.value || '02:00')}
                    className="w-full rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm"
                  />
                </div>

                <div className="space-y-1">
                  <div className="text-muted-foreground">{t('scans.windowMinutes')}</div>
                  <input
                    type="number"
                    min={5}
                    max={1440}
                    value={editWindowMinutes}
                    onChange={(e) => setEditWindowMinutes(Number(e.target.value) || 120)}
                    className="w-full rounded-md border border-border bg-background px-2.5 py-1.5 font-mono text-sm"
                  />
                </div>
              </div>

              {editingApplicableIgnored.length > 0 ? (
                <div className="space-y-2 border-t border-border/60 pt-2.5">
                  <label className="flex cursor-pointer items-center gap-1.5 font-medium text-amber-200">
                    <input
                      type="checkbox"
                      checked={editIncludeAllIgnored}
                      onChange={(e) => {
                        const next = e.target.checked;
                        setEditIncludeAllIgnored(next);
                        setEditIncludeIgnoredIds(
                          next ? editingApplicableIgnored.map((it) => it.id) : [],
                        );
                      }}
                    />
                    <span>{t('scans.recurringIncludeAllIgnored')}</span>
                  </label>
                  <div className="flex flex-wrap gap-2">
                    {editingApplicableIgnored.map((it) => {
                      const checked =
                        editIncludeAllIgnored || editIncludeIgnoredIds.includes(it.id);
                      return (
                        <label
                          key={it.id}
                          className="flex cursor-pointer items-center gap-1.5 rounded border border-border bg-background/80 px-2.5 py-1 hover:bg-secondary/60"
                          title={it.reason}
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={editIncludeAllIgnored}
                            onChange={(e) =>
                              setEditIncludeIgnoredIds((prev) =>
                                e.target.checked
                                  ? [...prev, it.id]
                                  : prev.filter((id) => id !== it.id),
                              )
                            }
                          />
                          <Badge variant="outline">
                            {it.asset_group_id ? 'GROUP' : 'GLOBAL'}
                          </Badge>
                          <span className="font-mono">{it.value}</span>
                        </label>
                      );
                    })}
                  </div>
                </div>
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
                          <div className="flex flex-wrap items-center gap-1.5">
                            <Badge variant={statusVariant(run.status)}>{run.status}</Badge>
                            {run.include_all_ignored || (run.overridden_ignored_values?.length ?? 0) > 0 ? (
                              <Badge variant="warning">
                                {run.include_all_ignored
                                  ? t('scans.ignoredOverriddenAllBadge')
                                  : t('scans.ignoredOverriddenCountBadge', {
                                      count: run.overridden_ignored_values?.length ?? 0,
                                    })}
                              </Badge>
                            ) : null}
                          </div>
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">
                          {run.completed_chunks}/{run.total_chunks} ({pct}%)
                        </td>
                        <td className="px-3 py-2 font-mono">{run.total_targets}</td>
                        <td className="px-3 py-2 font-mono text-xs text-muted-foreground">
                          {run.estimated_finish_at ?? '—'}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <div className="inline-flex flex-wrap justify-end gap-1">
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => setExploringScanId(run.id)}
                            >
                              <Eye className="h-3.5 w-3.5" />
                              {t('scans.exploreBtn')}
                            </Button>
                            {canControlScans ? (
                              <>
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
                              </>
                            ) : null}
                          </div>
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

      {exploringScanId ? (
        <Card className="border-primary/70">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-4 w-4 text-primary" />
                  {t('scans.explorer.title')}:{' '}
                  <span className="font-mono text-sm">
                    {exploreQuery.data?.asset_group_name ?? exploringScanId}
                  </span>
                </CardTitle>
                <CardDescription className="font-mono text-xs">{exploringScanId}</CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={() => setExploringScanId(null)}>
                <X className="h-4 w-4" />
                {t('scans.explorer.closeBtn')}
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-5">
            {exploreQuery.isLoading ? (
              <p className="text-sm text-muted-foreground">{t('common.loading')}</p>
            ) : exploreQuery.data ? (
              (() => {
                const exp = exploreQuery.data;
                const snap = (exp.scan.policy_snapshot ?? {}) as Record<string, unknown>;
                return (
                  <div className="space-y-5">
                    <div className="grid gap-3 rounded-md border border-border bg-background/60 p-3 text-xs sm:grid-cols-4">
                      <div>
                        <div className="text-muted-foreground">{t('scans.colStatus')}</div>
                        <Badge variant={statusVariant(exp.scan.status)} className="mt-1">
                          {exp.scan.status}
                        </Badge>
                      </div>
                      <div>
                        <div className="text-muted-foreground">{t('scans.colTargets')}</div>
                        <div className="font-mono text-sm font-semibold">
                          {exp.scan.total_targets}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">{t('scans.colProgress')}</div>
                        <div className="font-mono text-sm font-semibold">
                          {exp.scan.completed_chunks}/{exp.scan.total_chunks}
                        </div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">{t('scans.explorer.policyLabel')}</div>
                        <div className="font-mono">
                          {String(snap.discovery_tool ?? 'naabu')} · {String(snap.port_spec ?? '—')} ·{' '}
                          {String(snap.rate_pps ?? '—')} pps
                        </div>
                      </div>
                    </div>

                    {exp.scan.include_all_ignored ||
                    (exp.scan.overridden_ignored_values?.length ?? 0) > 0 ? (
                      <div className="rounded-md border border-amber-800 bg-amber-950/30 p-3 text-xs text-amber-200">
                        <span className="font-semibold">{t('scans.explorer.overriddenIgnored')}: </span>
                        <span className="font-mono">
                          {exp.scan.include_all_ignored
                            ? t('scans.ignoredOverriddenAllBadge')
                            : (exp.scan.overridden_ignored_values ?? []).join(', ')}
                        </span>
                      </div>
                    ) : null}

                    <div className="space-y-2">
                      <div className="text-xs font-semibold uppercase text-muted-foreground">
                        {t('scans.explorer.chunksTitle')} ({exp.chunks.length})
                      </div>
                      <div className="overflow-x-auto rounded-md border border-border">
                        <table className="w-full text-left text-xs">
                          <thead className="border-b border-border bg-secondary/40 text-muted-foreground">
                            <tr>
                              <th className="px-2.5 py-2">#</th>
                              <th className="px-2.5 py-2">{t('scans.explorer.colSubnet')}</th>
                              <th className="px-2.5 py-2">{t('scans.explorer.colWorker')}</th>
                              <th className="px-2.5 py-2">{t('scans.colStatus')}</th>
                              <th className="px-2.5 py-2">{t('scans.explorer.colDuration')}</th>
                              <th className="px-2.5 py-2">{t('scans.explorer.colTargetsSample')}</th>
                            </tr>
                          </thead>
                          <tbody>
                            {exp.chunks.map((c) => (
                              <tr key={c.id} className="border-b border-border/60 last:border-0">
                                <td className="px-2.5 py-1.5 font-mono">{c.sequence_no}</td>
                                <td className="px-2.5 py-1.5 font-mono">{c.subnet_bucket}</td>
                                <td className="px-2.5 py-1.5">
                                  {c.leased_by_worker_name ?? '—'}
                                </td>
                                <td className="px-2.5 py-1.5">
                                  <Badge variant="outline">{c.status}</Badge>
                                  {c.error_message ? (
                                    <span className="ml-1.5 text-red-300">{c.error_message}</span>
                                  ) : null}
                                </td>
                                <td className="px-2.5 py-1.5 font-mono">
                                  {c.duration_ms !== null && c.duration_ms !== undefined
                                    ? `${c.duration_ms} ms`
                                    : '—'}
                                </td>
                                <td className="px-2.5 py-1.5 font-mono text-muted-foreground">
                                  {c.target_ips.slice(0, 5).join(', ')}
                                  {c.target_ips.length > 5
                                    ? ` (+${c.target_ips.length - 5})`
                                    : ''}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>

                    <div className="grid gap-4 lg:grid-cols-2">
                      <div className="space-y-2">
                        <div className="text-xs font-semibold uppercase text-muted-foreground">
                          {t('scans.explorer.diffsTitle')} ({exp.diffs.length})
                        </div>
                        {exp.diffs.length ? (
                          <div className="max-h-72 space-y-2 overflow-y-auto pr-1">
                            {exp.diffs.map((ev) => (
                              <div
                                key={ev.id}
                                className="rounded border border-border bg-background p-2.5 text-xs space-y-1"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <span className="font-mono font-semibold">{ev.ip_addr}</span>
                                  <div className="flex gap-1">
                                    <Badge variant="outline">{ev.event_kind}</Badge>
                                    <Badge variant="outline">{ev.severity}</Badge>
                                  </div>
                                </div>
                                <ul className="space-y-0.5 text-muted-foreground">
                                  {ev.bullet_items.map((b, i) => (
                                    <li key={i}>
                                      {b.op} {formatBullet(t, b)}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground">
                            {t('scans.explorer.noDiffs')}
                          </p>
                        )}
                      </div>

                      <div className="space-y-2">
                        <div className="text-xs font-semibold uppercase text-muted-foreground">
                          {t('scans.explorer.hostSamplesTitle')} ({exp.host_samples.length})
                        </div>
                        {exp.host_samples.length ? (
                          <div className="max-h-72 overflow-y-auto rounded border border-border">
                            <table className="w-full text-left text-xs">
                              <thead className="border-b border-border bg-secondary/40 text-muted-foreground">
                                <tr>
                                  <th className="px-2 py-1.5">IP</th>
                                  <th className="px-2 py-1.5">{t('scans.explorer.colAlive')}</th>
                                  <th className="px-2 py-1.5">{t('scans.explorer.colOpenPorts')}</th>
                                </tr>
                              </thead>
                              <tbody>
                                {exp.host_samples.map((hs) => (
                                  <tr
                                    key={`${hs.host_id}-${hs.sampled_at}`}
                                    className="border-b border-border/60 last:border-0"
                                  >
                                    <td className="px-2 py-1.5 font-mono">{hs.ip_address}</td>
                                    <td className="px-2 py-1.5">
                                      <Badge variant={hs.is_alive ? 'success' : 'destructive'}>
                                        {hs.is_alive ? 'up' : 'down'} ({hs.time_slot})
                                      </Badge>
                                    </td>
                                    <td className="px-2 py-1.5 font-mono text-muted-foreground">
                                      {hs.open_ports.length ? hs.open_ports.join(', ') : '—'}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        ) : (
                          <p className="text-xs text-muted-foreground">
                            {t('scans.explorer.noSamples')}
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <div className="text-xs font-semibold uppercase text-muted-foreground">
                        {t('scans.explorer.auditTitle')} ({exp.audit_logs.length})
                      </div>
                      {exp.audit_logs.length ? (
                        <div className="max-h-48 space-y-1 overflow-y-auto rounded border border-border bg-background/50 p-2 text-xs font-mono">
                          {exp.audit_logs.map((al) => (
                            <div key={al.id} className="flex flex-wrap gap-x-3">
                              <span className="text-muted-foreground">{al.created_at}</span>
                              <span className="text-primary">{al.action}</span>
                              <span className="text-muted-foreground">{al.actor_type}</span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-xs text-muted-foreground">
                          {t('scans.explorer.noAudit')}
                        </p>
                      )}
                    </div>
                  </div>
                );
              })()
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
