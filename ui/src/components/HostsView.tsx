import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, RefreshCw, ShieldAlert } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError, type HostStatus, type HostSummaryDto } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

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

export function HostsView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [searchText, setSearchText] = useState('');
  const [statusFilter, setStatusFilter] = useState<HostStatus | ''>('');
  const [onlyUnstable, setOnlyUnstable] = useState(false);
  const [onlyTarpit, setOnlyTarpit] = useState(false);
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const hostsQuery = useQuery({
    queryKey: ['hosts', searchText, statusFilter, onlyUnstable, onlyTarpit],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/hosts', {
        params: {
          query: {
            page: 1,
            per_page: 100,
            status: statusFilter || null,
            is_unstable: onlyUnstable ? true : null,
            is_probable_tarpit: onlyTarpit ? true : null,
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

  const activeHostId = selectedHostId ?? hostsQuery.data?.items[0]?.id ?? null;

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

  const canEditMetadata = hasPermission('edit_analytical_metadata');
  const canForceSv = hasPermission('force_tarpit_scan');
  const canExport = hasPermission('export_reports');

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
            <div className="flex gap-2">
              {canExport ? (
                <Button variant="outline" size="sm" onClick={() => void handleExportHosts()}>
                  <Download className="h-4 w-4" />
                  {t('io.exportJson')}
                </Button>
              ) : null}
              <Button variant="outline" size="sm" onClick={() => void hostsQuery.refetch()}>
                <RefreshCw className="h-4 w-4" />
                {t('health.refresh')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2 sm:grid-cols-4">
            <input
              type="text"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder={t('hosts.searchPlaceholder')}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm sm:col-span-2"
            />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as HostStatus | '')}
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
                  onChange={(e) => setOnlyUnstable(e.target.checked)}
                />
                <span>{t('hosts.onlyUnstable')}</span>
              </label>
              <label className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={onlyTarpit}
                  onChange={(e) => setOnlyTarpit(e.target.checked)}
                />
                <span>{t('hosts.onlyTarpit')}</span>
              </label>
            </div>
          </div>

          <div className="grid gap-6 lg:grid-cols-5">
            <div className="overflow-x-auto rounded-md border border-border lg:col-span-2">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2">{t('hosts.colIp')}</th>
                    <th className="px-3 py-2">{t('hosts.colStatus')}</th>
                    <th className="px-3 py-2 text-right">{t('hosts.colPorts')}</th>
                  </tr>
                </thead>
                <tbody>
                  {hostsQuery.data?.items.length ? (
                    hostsQuery.data.items.map((h) => (
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

            <div className="space-y-4 lg:col-span-3">
              {detail ? (
                <>
                  <div className="rounded-md border border-border bg-background/50 p-4">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div>
                        <div className="font-mono text-lg font-bold">{detail.host.ip_addr}</div>
                        <div className="text-xs text-muted-foreground">
                          {detail.host.asset_group_name} · {t('hosts.misses')}:{' '}
                          {detail.host.consecutive_misses}
                        </div>
                      </div>
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
                          detail.ports.map((p) => (
                            <tr key={p.id} className="border-b border-border/60 last:border-0">
                              <td className="px-3 py-2 font-mono">
                                <div>
                                  {p.port}/{p.protocol}
                                </div>
                                <Badge variant="outline" className="mt-1">
                                  {p.state}
                                </Badge>
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
                          ))
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
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
