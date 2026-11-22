import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Columns2, Download, LayoutGrid, MessageSquare, RefreshCw, Send, ShieldAlert, Trash2, X } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  downloadAuthorizedFile,
  formatApiError,
  type DiffEventDto,
  type HostStatus,
  type HostSummaryDto,
  type ServiceRowDto,
} from '@/api/client';
import { DdPayloadModal } from '@/components/DdPayloadModal';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { paginateItems, TablePagination } from '@/components/ui/pagination';
import { useAuth } from '@/context/AuthContext';

function HostDdBadge({ hostId }: { hostId: string }) {
  const { t } = useTranslation();
  const { data } = useQuery({
    queryKey: ['dd-host-link', hostId],
    queryFn: async () => {
      const { data, error } = await apiClient.GET(
        '/api/v1/integrations/defectdojo/host-link/{host_id}',
        { params: { path: { host_id: hostId } } },
      );
      if (error || !data) {
        return null;
      }
      return data;
    },
    retry: false,
    staleTime: 30_000,
  });
  if (!data) {
    return null;
  }
  return (
    <Badge variant="outline" title={t('diffs.ddTooltip', { id: data.dd_finding_id ?? '?' })}>
      DD #{data.dd_finding_id ?? '?'}
      {data.dd_finding_status ? ` · ${data.dd_finding_status}` : ''}
    </Badge>
  );
}

interface SlotStat {
  samples?: number;
  up?: number;
  up_ratio?: number;
}

const SLOTS = ['00_06', '06_12', '12_18', '18_24'] as const;

function HostMetadataEditor({
  host,
  onSaved,
  onError,
}: {
  host: HostSummaryDto;
  onSaved: () => void;
  onError: (msg: string | null) => void;
}) {
  const { t } = useTranslation();
  const [ownerHint, setOwnerHint] = useState(host.owner_hint ?? '');
  const [manualTagsInput, setManualTagsInput] = useState(host.manual_tags.join(', '));
  const [notes, setNotes] = useState(host.notes ?? '');

  const updateMutation = useMutation({
    mutationFn: async () => {
      const manualTags = manualTagsInput
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const { data, error } = await apiClient.PATCH('/api/v1/hosts/{id}', {
        params: { path: { id: host.id } },
        body: {
          owner_hint: ownerHint,
          manual_tags: manualTags,
          notes,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to save host metadata.'));
      }
      return data;
    },
    onSuccess: () => {
      onError(null);
      onSaved();
    },
    onError: (err) => onError(err.message),
  });

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    updateMutation.mutate();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-3 rounded-md border border-border bg-background/40 p-3">
      <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {t('hosts.analyticalSection')}
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <input
          type="text"
          value={ownerHint}
          onChange={(e) => setOwnerHint(e.target.value)}
          placeholder={t('hosts.ownerHintPlaceholder')}
          className="rounded-md border border-border bg-background px-3 py-2 text-sm"
        />
        <input
          type="text"
          value={manualTagsInput}
          onChange={(e) => setManualTagsInput(e.target.value)}
          placeholder={t('hosts.manualTagsPlaceholder')}
          className="rounded-md border border-border bg-background px-3 py-2 text-sm"
        />
      </div>
      <textarea
        rows={3}
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder={t('hosts.notesPlaceholder')}
        className="w-full rounded-md border border-border bg-background p-2 text-sm"
      />
      <Button type="submit" size="sm" disabled={updateMutation.isPending}>
        {t('hosts.saveMetadata')}
      </Button>
    </form>
  );
}

type QuickHostFilter = 'all' | 'active' | 'shadow' | 'flapping' | 'tarpit' | 'anomalies';

export function HostsView({
  initialSearch = '',
  workspaceMode = 'analyst',
}: {
  initialSearch?: string;
  workspaceMode?: 'analyst' | 'config';
} = {}) {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [searchText, setSearchText] = useState(initialSearch);
  const [statusFilter, setStatusFilter] = useState<HostStatus | ''>('');
  const [onlyUnstable, setOnlyUnstable] = useState(false);
  const [onlyTarpit, setOnlyTarpit] = useState(false);
  const [quickFilter, setQuickFilter] = useState<QuickHostFilter>('all');
  const [layoutMode, setLayoutMode] = useState<'table360' | 'split'>('table360');
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [perPage, setPerPage] = useState(25);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  void workspaceMode;

  const effectiveStatus = quickFilter === 'active' ? 'active' : statusFilter || null;
  const effectiveUnstable = quickFilter === 'flapping' || onlyUnstable ? true : null;
  const effectiveTarpit = quickFilter === 'tarpit' || onlyTarpit ? true : null;

  const hostsQuery = useQuery({
    queryKey: ['hosts', searchText, effectiveStatus, effectiveUnstable, effectiveTarpit],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/hosts', {
        params: {
          query: {
            page: 1,
            per_page: 100,
            status: effectiveStatus,
            is_unstable: effectiveUnstable,
            is_probable_tarpit: effectiveTarpit,
            q: searchText.trim() || null,
          },
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load hosts.'));
      }
      return data;
    },
  });

  const servicesQuery = useQuery({
    queryKey: ['services-for-hosts-360'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/services', {
        params: { query: { page: 1, per_page: 200 } },
      });
      if (error || !data) {
        return { items: [] as ServiceRowDto[] };
      }
      return data;
    },
    staleTime: 15_000,
  });

  const unackDiffsQuery = useQuery({
    queryKey: ['diffs-for-hosts-360'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/diffs', {
        params: { query: { page: 1, per_page: 100, acknowledged: false } },
      });
      if (error || !data) {
        return { items: [] as DiffEventDto[] };
      }
      return data;
    },
    staleTime: 15_000,
  });

  const activeHostId =
    layoutMode === 'split'
      ? (selectedHostId ?? hostsQuery.data?.items[0]?.id ?? null)
      : selectedHostId;

  const detailQuery = useQuery({
    queryKey: ['host-detail', activeHostId],
    enabled: Boolean(activeHostId),
    queryFn: async () => {
      if (!activeHostId) {
        throw new Error('No host selected');
      }
      const { data, error } = await apiClient.GET('/api/v1/hosts/{id}', {
        params: { path: { id: activeHostId } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load host details.'));
      }
      return data;
    },
  });

  const tarpitMutation = useMutation({
    mutationFn: async ({ hostId, forceSv }: { hostId: string; forceSv: boolean }) => {
      const { data, error } = await apiClient.POST('/api/v1/hosts/{id}/tarpit-override', {
        params: { path: { id: hostId } },
        body: {
          force_sv: forceSv,
          reason: 'admin_ui_toggle',
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to toggle tarpit override.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['hosts'] });
      void queryClient.invalidateQueries({ queryKey: ['host-detail', activeHostId] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const handleExportHosts = async () => {
    setErrorMsg(null);
    const { data, error } = await apiClient.GET('/api/v1/export/hosts', {
      params: { query: {} },
    });
    if (error || !data) {
      setErrorMsg(formatApiError(error, 'Failed to export hosts JSON.'));
      return;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'asi-hosts.json';
    link.click();
    URL.revokeObjectURL(url);
  };

  const [pushingHostId, setPushingHostId] = useState<string | null>(null);
  const [commentText, setCommentText] = useState('');
  const [commentTargetPortId, setCommentTargetPortId] = useState<string>('');
  const canEditMetadata = hasPermission('edit_analytical_metadata');
  const canForceSv = hasPermission('force_tarpit_scan');
  const canExport = hasPermission('export_reports');
  const canPushDd = hasPermission('manage_external_integrations');
  const canEditDd = canPushDd || canEditMetadata || hasPermission('acknowledge_diffs');

  useEffect(() => {
    setCommentText('');
    setCommentTargetPortId('');
  }, [activeHostId]);

  const addCommentMutation = useMutation({
    mutationFn: async () => {
      if (!activeHostId) {
        throw new Error('Select a host first.');
      }
      const trimmed = commentText.trim();
      if (!trimmed) {
        throw new Error(t('hosts.commentEmptyError'));
      }
      const { data, error } = await apiClient.POST('/api/v1/hosts/{id}/comments', {
        params: { path: { id: activeHostId } },
        body: {
          host_port_id: commentTargetPortId || null,
          content: trimmed,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to add comment.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      setCommentText('');
      void queryClient.invalidateQueries({ queryKey: ['host-detail', activeHostId] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const deleteCommentMutation = useMutation({
    mutationFn: async (commentId: string) => {
      if (!activeHostId) {
        return;
      }
      const { error } = await apiClient.DELETE('/api/v1/hosts/{id}/comments/{comment_id}', {
        params: { path: { id: activeHostId, comment_id: commentId } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to delete comment.'));
      }
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['host-detail', activeHostId] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const statusBadgeVariant = (st: HostStatus) => {
    if (st === 'active') return 'success' as const;
    if (st === 'missing_pending') return 'warning' as const;
    if (st === 'inactive') return 'destructive' as const;
    return 'outline' as const;
  };

  const detail = detailQuery.data;
  const profileObj =
    detail?.host.availability_profile &&
    typeof detail.host.availability_profile === 'object' &&
    !Array.isArray(detail.host.availability_profile)
      ? (detail.host.availability_profile as Record<string, SlotStat | undefined>)
      : {};

  const servicesByHost = new Map<string, ServiceRowDto[]>();
  for (const srv of servicesQuery.data?.items ?? []) {
    const arr = servicesByHost.get(srv.host_id) ?? [];
    arr.push(srv);
    servicesByHost.set(srv.host_id, arr);
  }

  const unackDiffsByHost = new Map<string, DiffEventDto[]>();
  for (const ev of unackDiffsQuery.data?.items ?? []) {
    const arr = unackDiffsByHost.get(ev.host_id) ?? [];
    arr.push(ev);
    unackDiffsByHost.set(ev.host_id, arr);
  }

  const filteredHosts = (hostsQuery.data?.items ?? []).filter((h) => {
    if (quickFilter === 'shadow') {
      const srvs = servicesByHost.get(h.id) ?? [];
      const hasWebOrPaths = srvs.some(
        (s) => Boolean(s.title) || Boolean(s.vhost) || s.detected_paths.length > 0,
      );
      const hasShadowTag = [...h.auto_tags, ...h.manual_tags].some((tag) =>
        /shadow|admin|staging|dev/i.test(tag),
      );
      return hasWebOrPaths || hasShadowTag;
    }
    if (quickFilter === 'anomalies') {
      const hasDiffs = (unackDiffsByHost.get(h.id)?.length ?? 0) > 0;
      const hasPaths = (servicesByHost.get(h.id) ?? []).some((s) => s.detected_paths.length > 0);
      return hasDiffs || hasPaths;
    }
    return true;
  });

  const pagedHosts = paginateItems(filteredHosts, page, perPage);

  const applyQuickFilter = (next: QuickHostFilter) => {
    setQuickFilter(next);
    setPage(1);
    if (next !== 'active') setStatusFilter('');
    if (next !== 'flapping') setOnlyUnstable(false);
    if (next !== 'tarpit') setOnlyTarpit(false);
  };

  const detailContent = detail ? (
    <>
      <div className="rounded-md border border-border bg-background/50 p-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-lg font-bold">{detail.host.ip_addr}</span>
              <HostDdBadge hostId={detail.host.id} />
            </div>
            <div className="text-xs text-muted-foreground">
              {detail.host.asset_group_name} · {t('hosts.misses')}:{' '}
              {detail.host.consecutive_misses}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {canEditDd ? (
              <Button
                size="sm"
                variant="outline"
                onClick={() => setPushingHostId(detail.host.id)}
              >
                <Send className="h-3.5 w-3.5" />
                {t('hosts.editPushDdBtn')}
              </Button>
            ) : null}
            {canForceSv && detail.host.is_probable_tarpit ? (
              <Button
                size="sm"
                variant={detail.host.tarpit_override_force_sv ? 'default' : 'outline'}
                className={
                  detail.host.tarpit_override_force_sv
                    ? 'bg-red-600 text-white hover:bg-red-600/90'
                    : undefined
                }
                onClick={() =>
                  tarpitMutation.mutate({
                    hostId: detail.host.id,
                    forceSv: !detail.host.tarpit_override_force_sv,
                  })
                }
              >
                <ShieldAlert className="h-3.5 w-3.5" />
                {detail.host.tarpit_override_force_sv
                  ? t('hosts.disableForceSv')
                  : t('hosts.enableForceSv')}
              </Button>
            ) : null}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-1.5">
          {detail.host.auto_tags.map((tag) => (
            <Badge key={`auto-${tag}`} variant="outline">
              auto:{tag}
            </Badge>
          ))}
          {detail.host.manual_tags.map((tag) => (
            <Badge key={`manual-${tag}`} variant="default">
              {tag}
            </Badge>
          ))}
        </div>

        {detail.hostnames.length > 0 ? (
          <div className="mt-3 text-xs">
            <span className="font-semibold text-muted-foreground">
              {t('hosts.hostnamesLabel')}:{' '}
            </span>
            {detail.hostnames.map((hn) => `${hn.hostname} (${hn.source})`).join(', ')}
          </div>
        ) : null}

        <div className="mt-4">
          <div className="mb-1.5 text-xs font-semibold uppercase text-muted-foreground">
            {t('hosts.availabilitySlots')}
          </div>
          <div className="grid grid-cols-4 gap-2 text-xs">
            {SLOTS.map((slot) => {
              const stat = profileObj[slot];
              const pct =
                stat && typeof stat.up_ratio === 'number'
                  ? `${Math.round(stat.up_ratio * 100)}%`
                  : '—';
              return (
                <div
                  key={slot}
                  className="rounded border border-border bg-background px-2 py-1.5 text-center"
                >
                  <div className="font-mono text-[11px] text-muted-foreground">{slot}</div>
                  <div className="font-mono font-semibold">{pct}</div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      <div className="overflow-x-auto rounded-md border border-border">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
            <tr>
              <th className="px-3 py-2">{t('hosts.colPort')}</th>
              <th className="px-3 py-2">{t('hosts.colService')}</th>
              <th className="px-3 py-2">{t('hosts.colWebTls')}</th>
            </tr>
          </thead>
          <tbody>
            {detail.ports.length ? (
              detail.ports.map((p) => {
                const portCommentCount = (detail.comments ?? []).filter(
                  (c) => c.host_port_id === p.id,
                ).length;
                return (
                  <tr key={p.id} className="border-b border-border/60 last:border-0">
                    <td className="px-3 py-2 font-mono">
                      <div>
                        {p.port}/{p.protocol}
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-1">
                        <Badge variant="outline">{p.state}</Badge>
                        {canEditMetadata ? (
                          <Button
                            type="button"
                            size="sm"
                            variant="ghost"
                            className="h-6 px-1.5 text-[11px]"
                            title={t('hosts.commentPortBtn')}
                            onClick={() => setCommentTargetPortId(p.id)}
                          >
                            <MessageSquare className="h-3 w-3" />
                            {portCommentCount > 0 ? (
                              <span className="ml-0.5">{portCommentCount}</span>
                            ) : null}
                          </Button>
                        ) : null}
                      </div>
                    </td>
                    <td className="px-3 py-2">
                      <div className="font-medium">
                        {p.service_name ?? '—'} {p.product ?? ''} {p.version ?? ''}
                      </div>
                      {p.tunnel ? (
                        <div className="text-muted-foreground">tunnel: {p.tunnel}</div>
                      ) : null}
                    </td>
                    <td className="px-3 py-2 space-y-1">
                      {p.tls_certificate ? (
                        <div className="text-muted-foreground">
                          TLS CN: {p.tls_certificate.subject_cn ?? '—'}
                          {p.tls_certificate.is_self_signed ? ' (self-signed)' : ''}
                        </div>
                      ) : null}
                      {p.web_observations.map((obs) => (
                        <div key={obs.id} className="rounded bg-secondary/30 p-1.5">
                          <div className="font-mono">
                            {obs.scheme}://{obs.vhost} [{obs.http_status ?? '—'}]
                          </div>
                          {obs.title ? <div>title: {obs.title}</div> : null}
                          {obs.matched_technologies.length > 0 ? (
                            <div className="text-primary">
                              tech: {obs.matched_technologies.join(', ')}
                            </div>
                          ) : null}
                          {obs.detected_paths.length > 0 ? (
                            <div className="text-amber-300">
                              paths: {obs.detected_paths.join(', ')}
                            </div>
                          ) : null}
                        </div>
                      ))}
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={3} className="px-3 py-4 text-center text-muted-foreground">
                  {t('hosts.noPorts')}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="space-y-3 rounded-md border border-border bg-background/40 p-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          <MessageSquare className="h-3.5 w-3.5 text-primary" />
          {t('hosts.commentsTitle')} ({detail.comments?.length ?? 0})
        </div>

        {detail.comments?.length ? (
          <div className="space-y-2">
            {detail.comments.map((c) => (
              <div
                key={c.id}
                className="flex items-start justify-between gap-2 rounded border border-border bg-background p-2.5 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant={c.host_port_id ? 'default' : 'outline'}>
                      {c.port
                        ? `${c.port}/${c.protocol ?? 'tcp'}`
                        : t('hosts.commentScopeHost')}
                    </Badge>
                    <span className="font-semibold text-foreground">{c.author_name}</span>
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {c.created_at}
                    </span>
                  </div>
                  <p className="whitespace-pre-wrap text-foreground">{c.content}</p>
                </div>
                {canEditMetadata ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    onClick={() => deleteCommentMutation.mutate(c.id)}
                    disabled={deleteCommentMutation.isPending}
                  >
                    <Trash2 className="h-3.5 w-3.5 text-red-400" />
                  </Button>
                ) : null}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">{t('hosts.commentsEmpty')}</p>
        )}

        {canEditMetadata ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              addCommentMutation.mutate();
            }}
            className="space-y-2 border-t border-border pt-2"
          >
            <div className="flex flex-wrap gap-2">
              <select
                value={commentTargetPortId}
                onChange={(e) => setCommentTargetPortId(e.target.value)}
                className="rounded-md border border-border bg-background px-2.5 py-1.5 text-xs"
              >
                <option value="">{t('hosts.commentScopeHostOption')}</option>
                {detail.ports.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.port}/{p.protocol} ({p.service_name ?? 'port'})
                  </option>
                ))}
              </select>
            </div>
            <div className="flex gap-2">
              <textarea
                rows={2}
                value={commentText}
                onChange={(e) => setCommentText(e.target.value)}
                placeholder={t('hosts.commentPlaceholder')}
                className="flex-1 rounded-md border border-border bg-background p-2 text-xs"
              />
              <Button
                type="submit"
                size="sm"
                disabled={addCommentMutation.isPending || !commentText.trim()}
              >
                {t('hosts.addCommentBtn')}
              </Button>
            </div>
          </form>
        ) : null}
      </div>

      {canEditMetadata ? (
        <HostMetadataEditor
          key={detail.host.id}
          host={detail.host}
          onSaved={() => {
            void queryClient.invalidateQueries({ queryKey: ['hosts'] });
            void queryClient.invalidateQueries({
              queryKey: ['host-detail', detail.host.id],
            });
          }}
          onError={setErrorMsg}
        />
      ) : null}
    </>
  ) : (
    <div className="rounded-md border border-border p-6 text-center text-sm text-muted-foreground">
      {t('hosts.selectHint')}
    </div>
  );

  return (
    <div className="space-y-6">
      {errorMsg ? (
        <div className="rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {errorMsg}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle>{t('hosts.title')}</CardTitle>
              <CardDescription>{t('hosts.subtitle')}</CardDescription>
            </div>
            <div className="flex flex-wrap gap-2">
              {canExport ? (
                <>
                  <Button variant="outline" size="sm" onClick={() => void handleExportHosts()}>
                    <Download className="h-4 w-4" />
                    {t('io.exportJson')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void downloadAuthorizedFile('/api/v1/export/hosts.csv', 'asi-hosts.csv').catch(
                        (err: Error) => setErrorMsg(err.message),
                      )
                    }
                  >
                    <Download className="h-4 w-4" />
                    {t('io.exportHostsCsv')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void downloadAuthorizedFile('/api/v1/export/services', 'asi-services.json').catch(
                        (err: Error) => setErrorMsg(err.message),
                      )
                    }
                  >
                    <Download className="h-4 w-4" />
                    {t('io.exportServicesJson')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void downloadAuthorizedFile('/api/v1/export/services.csv', 'asi-services.csv').catch(
                        (err: Error) => setErrorMsg(err.message),
                      )
                    }
                  >
                    <Download className="h-4 w-4" />
                    {t('io.exportServicesCsv')}
                  </Button>
                </>
              ) : null}
              <Button variant="outline" size="sm" onClick={() => void hostsQuery.refetch()}>
                <RefreshCw className="h-4 w-4" />
                {t('health.refresh')}
              </Button>
              <div className="inline-flex rounded-md border border-border bg-background p-0.5">
                <Button
                  type="button"
                  size="sm"
                  variant={layoutMode === 'table360' ? 'default' : 'ghost'}
                  className="h-7 px-2 text-xs"
                  onClick={() => setLayoutMode('table360')}
                >
                  <LayoutGrid className="h-3.5 w-3.5" />
                  {t('hosts.layoutTable360')}
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant={layoutMode === 'split' ? 'default' : 'ghost'}
                  className="h-7 px-2 text-xs"
                  onClick={() => setLayoutMode('split')}
                >
                  <Columns2 className="h-3.5 w-3.5" />
                  {t('hosts.layoutSplit')}
                </Button>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Quick Filter Pills (attack-surface-intelligence style) */}
          <div className="flex flex-wrap items-center gap-2">
            {(
              [
                ['all', t('hosts.pillAll')],
                ['active', t('hosts.pillActive')],
                ['shadow', t('hosts.pillShadow')],
                ['flapping', t('hosts.pillFlapping')],
                ['tarpit', t('hosts.pillTarpit')],
                ['anomalies', t('hosts.pillAnomalies')],
              ] as const
            ).map(([key, label]) => (
              <Button
                key={key}
                type="button"
                size="sm"
                variant={quickFilter === key ? 'default' : 'outline'}
                className={
                  key === 'shadow' && quickFilter !== 'shadow'
                    ? 'border-amber-500/40 text-amber-300'
                    : key === 'anomalies' && quickFilter !== 'anomalies'
                      ? 'border-rose-500/40 text-rose-300'
                      : undefined
                }
                onClick={() => applyQuickFilter(key)}
              >
                {label}
              </Button>
            ))}
          </div>

          <div className="grid gap-2 sm:grid-cols-4">
            <input
              type="text"
              value={searchText}
              onChange={(e) => {
                setSearchText(e.target.value);
                setPage(1);
              }}
              placeholder={t('hosts.searchPlaceholder')}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm sm:col-span-2"
            />
            <select
              value={statusFilter}
              onChange={(e) => {
                setQuickFilter('all');
                setStatusFilter(e.target.value as HostStatus | '');
                setPage(1);
              }}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            >
              <option value="">{t('hosts.allStatuses')}</option>
              <option value="active">active</option>
              <option value="missing_pending">missing_pending</option>
              <option value="inactive">inactive</option>
              <option value="ignored">ignored</option>
            </select>
            <div className="flex items-center gap-4 px-2 text-xs">
              <label className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={onlyUnstable}
                  onChange={(e) => {
                    setQuickFilter('all');
                    setOnlyUnstable(e.target.checked);
                    setPage(1);
                  }}
                />
                <span>{t('hosts.onlyUnstable')}</span>
              </label>
              <label className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={onlyTarpit}
                  onChange={(e) => {
                    setQuickFilter('all');
                    setOnlyTarpit(e.target.checked);
                    setPage(1);
                  }}
                />
                <span>{t('hosts.onlyTarpit')}</span>
              </label>
            </div>
          </div>

          {layoutMode === 'table360' ? (
            <div className="space-y-3">
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2.5">{t('hosts.colIp')}</th>
                    <th className="px-3 py-2.5">{t('hosts.colServicesPorts')}</th>
                    <th className="px-3 py-2.5">{t('hosts.colTechWeb')}</th>
                    <th className="px-3 py-2.5">{t('hosts.colStatus')}</th>
                    <th className="px-3 py-2.5">{t('hosts.colNotesTags')}</th>
                    <th className="px-3 py-2.5 text-right">{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedHosts.items.length ? (
                    pagedHosts.items.map((h) => {
                      const hostServices = servicesByHost.get(h.id) ?? [];
                      const portSeen = new Set<string>();
                      const portBadges: Array<{ key: string; label: string }> = [];
                      const techsSet = new Set<string>();
                      const pathsSet = new Set<string>();
                      let sampleTitle: string | null = null;
                      for (const srv of hostServices) {
                        const pk = `${srv.port}/${srv.protocol}`;
                        if (!portSeen.has(pk)) {
                          portSeen.add(pk);
                          portBadges.push({
                            key: pk,
                            label: srv.service_name ? `${srv.port} ${srv.service_name}` : pk,
                          });
                        }
                        for (const tech of srv.matched_technologies) techsSet.add(tech);
                        for (const path of srv.detected_paths) pathsSet.add(path);
                        if (!sampleTitle && srv.title) sampleTitle = srv.title;
                      }
                      const hostUnackDiffs = unackDiffsByHost.get(h.id) ?? [];
                      const hProfile =
                        h.availability_profile &&
                        typeof h.availability_profile === 'object' &&
                        !Array.isArray(h.availability_profile)
                          ? (h.availability_profile as Record<string, SlotStat | undefined>)
                          : {};

                      return (
                        <tr
                          key={h.id}
                          onClick={() => setSelectedHostId(h.id)}
                          className={`cursor-pointer border-b border-border/60 last:border-0 hover:bg-secondary/40 ${
                            selectedHostId === h.id ? 'bg-secondary/60' : ''
                          }`}
                        >
                          <td className="px-3 py-2.5 align-top">
                            <div className="font-mono text-sm font-semibold">{h.ip_addr}</div>
                            <div className="text-muted-foreground">{h.asset_group_name}</div>
                            <div className="mt-1 flex flex-wrap gap-1">
                              <HostDdBadge hostId={h.id} />
                              {hostUnackDiffs.length > 0 ? (
                                <Badge variant="warning">
                                  {t('hosts.unackDiffBadge', { count: hostUnackDiffs.length })}
                                </Badge>
                              ) : null}
                            </div>
                          </td>
                          <td className="px-3 py-2.5 align-top">
                            <div className="flex max-w-xs flex-wrap gap-1">
                              {portBadges.slice(0, 6).map((pb) => (
                                <Badge key={pb.key} variant="outline" className="font-mono">
                                  {pb.label}
                                </Badge>
                              ))}
                              {portBadges.length > 6 ? (
                                <Badge variant="outline">+{portBadges.length - 6}</Badge>
                              ) : portBadges.length === 0 ? (
                                <span className="font-mono text-muted-foreground">
                                  {h.open_port_count > 0 ? `${h.open_port_count} ports` : '—'}
                                </span>
                              ) : null}
                            </div>
                          </td>
                          <td className="px-3 py-2.5 align-top space-y-1">
                            <div className="flex max-w-xs flex-wrap gap-1">
                              {[...techsSet].slice(0, 5).map((tech) => (
                                <Badge key={tech} variant="default">
                                  {tech}
                                </Badge>
                              ))}
                              {pathsSet.size > 0 ? (
                                <Badge variant="destructive">
                                  admin: {[...pathsSet].slice(0, 2).join(', ')}
                                </Badge>
                              ) : null}
                            </div>
                            {sampleTitle ? (
                              <div className="max-w-xs truncate text-muted-foreground" title={sampleTitle}>
                                {sampleTitle}
                              </div>
                            ) : techsSet.size === 0 && pathsSet.size === 0 ? (
                              <span className="text-muted-foreground">—</span>
                            ) : null}
                          </td>
                          <td className="px-3 py-2.5 align-top space-y-1.5">
                            <div className="flex flex-wrap gap-1">
                              <Badge variant={statusBadgeVariant(h.status)}>{h.status}</Badge>
                              {h.is_unstable ? <Badge variant="warning">unstable</Badge> : null}
                              {h.is_probable_tarpit ? (
                                <Badge variant="destructive">tarpit</Badge>
                              ) : null}
                            </div>
                            <div className="grid grid-cols-4 gap-1 max-w-[160px]">
                              {SLOTS.map((slot) => {
                                const ratio = hProfile[slot]?.up_ratio;
                                const cls =
                                  typeof ratio !== 'number'
                                    ? 'bg-muted'
                                    : ratio >= 0.8
                                      ? 'bg-emerald-500'
                                      : ratio > 0
                                        ? 'bg-amber-500'
                                        : 'bg-red-500/70';
                                return (
                                  <div
                                    key={slot}
                                    className={`h-1.5 rounded-sm ${cls}`}
                                    title={`${slot}: ${typeof ratio === 'number' ? Math.round(ratio * 100) + '%' : '—'}`}
                                  />
                                );
                              })}
                            </div>
                          </td>
                          <td className="px-3 py-2.5 align-top space-y-1 max-w-xs">
                            {h.owner_hint ? (
                              <div className="font-medium text-foreground">{h.owner_hint}</div>
                            ) : null}
                            {h.manual_tags.length > 0 || h.auto_tags.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {h.manual_tags.map((tg) => (
                                  <Badge key={`m-${tg}`} variant="default">
                                    {tg}
                                  </Badge>
                                ))}
                                {h.auto_tags.slice(0, 2).map((tg) => (
                                  <Badge key={`a-${tg}`} variant="outline">
                                    {tg}
                                  </Badge>
                                ))}
                              </div>
                            ) : null}
                            {h.notes ? (
                              <p className="line-clamp-2 text-muted-foreground">{h.notes}</p>
                            ) : !h.owner_hint &&
                              h.manual_tags.length === 0 &&
                              h.auto_tags.length === 0 ? (
                              <span className="text-muted-foreground">—</span>
                            ) : null}
                          </td>
                          <td
                            className="px-3 py-2.5 align-top text-right"
                            onClick={(e) => e.stopPropagation()}
                          >
                            <div className="inline-flex gap-1">
                              <Button
                                type="button"
                                size="sm"
                                variant="outline"
                                onClick={() => setSelectedHostId(h.id)}
                              >
                                {t('hosts.inspectEditBtn')}
                              </Button>
                              {canEditDd ? (
                                <Button
                                  type="button"
                                  size="sm"
                                  variant="outline"
                                  onClick={() => setPushingHostId(h.id)}
                                  title={t('hosts.editPushDdBtn')}
                                >
                                  <Send className="h-3.5 w-3.5" />
                                </Button>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">
                        {t('hosts.empty')}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              page={pagedHosts.safePage}
              perPage={perPage}
              totalItems={pagedHosts.totalItems}
              onPageChange={setPage}
              onPerPageChange={(n) => {
                setPerPage(n);
                setPage(1);
              }}
            />
            </div>
          ) : (
            <div className="grid gap-6 lg:grid-cols-5">
              <div className="space-y-3 lg:col-span-2">
              <div className="overflow-x-auto rounded-md border border-border">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
                    <tr>
                      <th className="px-3 py-2">{t('hosts.colIp')}</th>
                      <th className="px-3 py-2">{t('hosts.colStatus')}</th>
                      <th className="px-3 py-2 text-right">{t('hosts.colPorts')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pagedHosts.items.length ? (
                      pagedHosts.items.map((h) => (
                        <tr
                          key={h.id}
                          onClick={() => setSelectedHostId(h.id)}
                          className={`cursor-pointer border-b border-border/60 last:border-0 hover:bg-secondary/40 ${
                            activeHostId === h.id ? 'bg-secondary' : ''
                          }`}
                        >
                          <td className="px-3 py-2">
                            <div className="font-mono font-medium">{h.ip_addr}</div>
                            <div className="text-xs text-muted-foreground">{h.asset_group_name}</div>
                          </td>
                          <td className="px-3 py-2">
                            <div className="flex flex-wrap gap-1">
                              <Badge variant={statusBadgeVariant(h.status)}>{h.status}</Badge>
                              {h.is_unstable ? <Badge variant="warning">unstable</Badge> : null}
                              {h.is_probable_tarpit ? (
                                <Badge variant="destructive">probable-tarpit</Badge>
                              ) : null}
                            </div>
                          </td>
                          <td className="px-3 py-2 text-right font-mono">{h.open_port_count}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={3} className="px-3 py-4 text-center text-muted-foreground">
                          {t('hosts.empty')}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <TablePagination
                page={pagedHosts.safePage}
                perPage={perPage}
                totalItems={pagedHosts.totalItems}
                onPageChange={setPage}
                onPerPageChange={(n) => {
                  setPerPage(n);
                  setPage(1);
                }}
              />
              </div>

              <div className="space-y-4 lg:col-span-3">{detailContent}</div>
            </div>
          )}
        </CardContent>
      </Card>

      {layoutMode === 'table360' && selectedHostId ? (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/60"
          onClick={() => setSelectedHostId(null)}
        >
          <div
            className="h-full w-full max-w-2xl space-y-4 overflow-y-auto border-l border-border bg-card p-5 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="font-mono text-base font-bold">
                  {detail?.host.ip_addr ?? t('hosts.drawerTitle')}
                </h3>
                <p className="text-xs text-muted-foreground">
                  {detail?.host.asset_group_name ?? t('common.loading')}
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setSelectedHostId(null)}
              >
                <X className="h-4 w-4" />
                {t('hosts.closeDrawer')}
              </Button>
            </div>
            {detailContent}
          </div>
        </div>
      ) : null}
      {pushingHostId ? (
        <DdPayloadModal
          mode="host"
          targetId={pushingHostId}
          fallbackHost={
            (hostsQuery.data?.items ?? []).find((h) => h.id === pushingHostId) ??
            (detail?.host.id === pushingHostId
              ? { ...detail.host, open_port_count: detail.ports.length }
              : undefined)
          }
          onClose={() => setPushingHostId(null)}
        />
      ) : null}
    </div>
  );
}
