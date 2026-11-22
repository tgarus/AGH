import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Download, FileText, GitCompare, Pencil, RefreshCw, Send } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  downloadAuthorizedFile,
  formatApiError,
  type DiffEventKind,
  type DiffSeverity,
} from '@/api/client';
import { DdPayloadModal } from '@/components/DdPayloadModal';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';
import { formatBullet } from '@/utils/formatBullet';

function DiffDdBadge({ diffId }: { diffId: string }) {
  const { t } = useTranslation();
  const { data } = useQuery({
    queryKey: ['dd-link', diffId],
    queryFn: async () => {
      const { data, error } = await apiClient.GET(
        '/api/v1/integrations/defectdojo/link/{diff_event_id}',
        { params: { path: { diff_event_id: diffId } } },
      );
      if (error || !data) {
        return null; // brak linku = nie było jeszcze pushowane
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

export function DiffsView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [kindFilter, setKindFilter] = useState<DiffEventKind | ''>('');
  const [severityFilter, setSeverityFilter] = useState<DiffSeverity | ''>('');
  const [ackFilter, setAckFilter] = useState<'all' | 'unack' | 'ack'>('all');
  const [scanAId, setScanAId] = useState<string>('');
  const [scanBId, setScanBId] = useState<string>('');
  const [editingDiffId, setEditingDiffId] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const groupsQuery = useQuery({
    queryKey: ['asset-groups'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/asset-groups', {
        params: { query: { page: 1, per_page: 100 } },
      });
      if (error || !data) {
        return { items: [] };
      }
      return data;
    },
  });

  const scansListQuery = useQuery({
    queryKey: ['scans-for-diff-compare'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/scans', {
        params: { query: { page: 1, per_page: 50 } },
      });
      if (error || !data) {
        return { items: [] };
      }
      return data;
    },
  });

  const exploreAQuery = useQuery({
    queryKey: ['scan-explore-compare', scanAId],
    enabled: Boolean(scanAId && scanBId && scanAId !== scanBId),
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/scans/{id}/explore', {
        params: { path: { id: scanAId } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load baseline scan A.'));
      }
      return data;
    },
  });

  const exploreBQuery = useQuery({
    queryKey: ['scan-explore-compare', scanBId],
    enabled: Boolean(scanBId),
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/scans/{id}/explore', {
        params: { path: { id: scanBId } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load target scan B.'));
      }
      return data;
    },
  });

  const diffsQuery = useQuery({
    queryKey: ['diffs', kindFilter, severityFilter, ackFilter],
    queryFn: async () => {
      const acknowledged = ackFilter === 'all' ? null : ackFilter === 'ack';
      const { data, error } = await apiClient.GET('/api/v1/diffs', {
        params: {
          query: {
            page: 1,
            per_page: 100,
            event_kind: kindFilter || null,
            severity: severityFilter || null,
            acknowledged,
          },
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load diff events.'));
      }
      return data;
    },
  });

  const ackMutation = useMutation({
    mutationFn: async (diffId: string) => {
      const { data, error } = await apiClient.POST('/api/v1/diffs/{id}/acknowledge', {
        params: { path: { id: diffId } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to acknowledge diff.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['diffs'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const handleExportDiffs = async () => {
    setErrorMsg(null);
    const { data, error } = await apiClient.GET('/api/v1/export/diffs', {
      params: { query: {} },
    });
    if (error || !data) {
      setErrorMsg(formatApiError(error, 'Failed to export diffs JSON.'));
      return;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'asi-diffs.json';
    link.click();
    URL.revokeObjectURL(url);
  };

  const pushDdMutation = useMutation({
    mutationFn: async (diffId: string) => {
      const { data, error } = await apiClient.POST(
        '/api/v1/integrations/defectdojo/push/{diff_event_id}',
        { params: { path: { diff_event_id: diffId } } },
      );
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to push diff to DefectDojo.'));
      }
      return data;
    },
    onSuccess: (_res, diffId) => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['dd-link', diffId] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const canAck = hasPermission('acknowledge_diffs');
  const canExport = hasPermission('export_reports');
  const canPushDd = hasPermission('manage_external_integrations');

  const severityVariant = (sev: DiffSeverity) => {
    if (sev === 'high') return 'destructive' as const;
    if (sev === 'medium') return 'warning' as const;
    if (sev === 'low') return 'default' as const;
    return 'outline' as const;
  };

  const opClass = (op: '+' | '-' | '~') => {
    if (op === '+') return 'text-emerald-300';
    if (op === '-') return 'text-red-300';
    return 'text-amber-300';
  };

  const groupNameById = new Map(
    (groupsQuery.data?.items ?? []).map((g) => [g.id, g.name] as const),
  );

  const visibleDiffs = (scanBId ? (exploreBQuery.data?.diffs ?? []) : (diffsQuery.data?.items ?? [])).filter(
    (ev) => {
      if (kindFilter && ev.event_kind !== kindFilter) return false;
      if (severityFilter && ev.severity !== severityFilter) return false;
      if (ackFilter === 'ack' && !ev.acknowledged_at) return false;
      if (ackFilter === 'unack' && ev.acknowledged_at) return false;
      return true;
    },
  );

  let addedServicesCount = 0;
  let closedPortsCount = 0;
  let modifiedCount = 0;
  let varianceEventsCount = 0;
  for (const ev of visibleDiffs) {
    if (ev.event_kind === 'active_variance') {
      varianceEventsCount += 1;
    }
    for (const b of ev.bullet_items) {
      if (b.op === '+') addedServicesCount += 1;
      else if (b.op === '-') closedPortsCount += 1;
      else if (b.op === '~') modifiedCount += 1;
    }
  }

  const scanComparisonRows = (() => {
    if (!scanAId || !scanBId || scanAId === scanBId || !exploreAQuery.data || !exploreBQuery.data) {
      return null;
    }
    const mapA = new Map(exploreAQuery.data.host_samples.map((h) => [h.ip_address, h] as const));
    const mapB = new Map(exploreBQuery.data.host_samples.map((h) => [h.ip_address, h] as const));
    const ips = Array.from(new Set([...mapA.keys(), ...mapB.keys()])).sort();
    return ips.map((ip) => {
      const a = mapA.get(ip);
      const b = mapB.get(ip);
      const portsA = new Set(a?.open_ports ?? []);
      const portsB = new Set(b?.open_ports ?? []);
      const addedPorts = [...portsB].filter((p) => !portsA.has(p)).sort((x, y) => x - y);
      const removedPorts = [...portsA].filter((p) => !portsB.has(p)).sort((x, y) => x - y);
      return {
        ip,
        aliveA: a?.is_alive ?? null,
        aliveB: b?.is_alive ?? null,
        portsA: a?.open_ports ?? [],
        portsB: b?.open_ports ?? [],
        addedPorts,
        removedPorts,
      };
    });
  })();

  const handleExportMarkdown = () => {
    const lines: string[] = [
      '# ASI — Raport Analizy Różnicowej (Diff Engine)',
      `Wygenerowano: ${new Date().toISOString()}`,
      '',
      '## Podsumowanie',
      `- Nowe usługi / elementy (+): **${addedServicesCount}**`,
      `- Zamknięte porty / wyłączenia (-): **${closedPortsCount}**`,
      `- Zmodyfikowane usługi / konfiguracje (~): **${modifiedCount}**`,
      `- Zdarzenia niestabilności (Flapping / active_variance): **${varianceEventsCount}**`,
      '',
    ];
    if (scanComparisonRows) {
      lines.push(`## Porównanie skanu bazowego A (\`${scanAId}\`) vs skanu docelowego B (\`${scanBId}\`)`);
      lines.push('| Host IP | Skan A | Skan B | Nowe porty (+) | Zamknięte porty (-) |');
      lines.push('| --- | --- | --- | --- | --- |');
      for (const row of scanComparisonRows) {
        const stA = row.aliveA === null ? 'brak' : row.aliveA ? `up (${row.portsA.join(',') || '-'})` : 'down';
        const stB = row.aliveB === null ? 'brak' : row.aliveB ? `up (${row.portsB.join(',') || '-'})` : 'down';
        lines.push(
          `| ${row.ip} | ${stA} | ${stB} | ${row.addedPorts.join(', ') || '—'} | ${row.removedPorts.join(', ') || '—'} |`,
        );
      }
      lines.push('');
    }
    lines.push('## Zdarzenia Diff Engine');
    for (const ev of visibleDiffs) {
      lines.push(`### ${ev.ip_addr} · ${ev.event_kind} [${ev.severity}] (${ev.detected_at})`);
      for (const b of ev.bullet_items) {
        lines.push(`- ${b.op} ${formatBullet(t, b)}`);
      }
      lines.push('');
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `asi-diff-report-${new Date().toISOString().slice(0, 10)}.md`;
    link.click();
    URL.revokeObjectURL(url);
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
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle>{t('diffs.title')}</CardTitle>
              <CardDescription>{t('diffs.subtitle')}</CardDescription>
            </div>
            <div className="flex flex-wrap gap-2">
              {canExport ? (
                <>
                  <Button variant="outline" size="sm" onClick={() => void handleExportDiffs()}>
                    <Download className="h-4 w-4" />
                    {t('io.exportJson')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void downloadAuthorizedFile('/api/v1/export/diffs.csv', 'asi-diffs.csv').catch(
                        (err: Error) => setErrorMsg(err.message),
                      )
                    }
                  >
                    <Download className="h-4 w-4" />
                    {t('io.exportCsv')}
                  </Button>
                  <Button variant="outline" size="sm" onClick={handleExportMarkdown}>
                    <FileText className="h-4 w-4" />
                    {t('diffs.exportMarkdownBtn')}
                  </Button>
                </>
              ) : null}
              <Button variant="outline" size="sm" onClick={() => void diffsQuery.refetch()}>
                <RefreshCw className="h-4 w-4" />
                {t('health.refresh')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Executive Diff Counters (attack-surface-intelligence style) */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-md border border-border bg-background/60 p-3">
              <div className="text-xs text-muted-foreground">{t('diffs.statAdded')}</div>
              <div className="mt-1 font-mono text-2xl font-bold text-emerald-400">
                {addedServicesCount}
              </div>
            </div>
            <div className="rounded-md border border-border bg-background/60 p-3">
              <div className="text-xs text-muted-foreground">{t('diffs.statRemoved')}</div>
              <div className="mt-1 font-mono text-2xl font-bold text-red-400">
                {closedPortsCount}
              </div>
            </div>
            <div className="rounded-md border border-border bg-background/60 p-3">
              <div className="text-xs text-muted-foreground">{t('diffs.statModified')}</div>
              <div className="mt-1 font-mono text-2xl font-bold text-sky-400">
                {modifiedCount}
              </div>
            </div>
            <div className="rounded-md border border-border bg-background/60 p-3">
              <div className="text-xs text-muted-foreground">{t('diffs.statVariance')}</div>
              <div className="mt-1 font-mono text-2xl font-bold text-amber-400">
                {varianceEventsCount}
              </div>
            </div>
          </div>

          {/* Scan A vs Scan B Run Comparison Bar */}
          <div className="rounded-md border border-border bg-background/40 p-3 space-y-3">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              <GitCompare className="h-3.5 w-3.5 text-primary" />
              {t('diffs.compareTitle')}
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] text-muted-foreground">
                  {t('diffs.scanALabel')}
                </label>
                <select
                  value={scanAId}
                  onChange={(e) => setScanAId(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs"
                >
                  <option value="">{t('diffs.scanANone')}</option>
                  {(scansListQuery.data?.items ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {groupNameById.get(s.asset_group_id) ?? s.asset_group_id.slice(0, 8)} ·{' '}
                      {s.status} · {s.total_targets} IP · {s.started_at}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-muted-foreground">
                  {t('diffs.scanBLabel')}
                </label>
                <select
                  value={scanBId}
                  onChange={(e) => setScanBId(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs"
                >
                  <option value="">{t('diffs.scanBAll')}</option>
                  {(scansListQuery.data?.items ?? []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {groupNameById.get(s.asset_group_id) ?? s.asset_group_id.slice(0, 8)} ·{' '}
                      {s.status} · {s.total_targets} IP · {s.started_at}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {scanComparisonRows ? (
              <div className="overflow-x-auto rounded border border-border">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-border bg-secondary/40 text-muted-foreground">
                    <tr>
                      <th className="px-2.5 py-1.5">IP</th>
                      <th className="px-2.5 py-1.5">{t('diffs.colScanA')}</th>
                      <th className="px-2.5 py-1.5">{t('diffs.colScanB')}</th>
                      <th className="px-2.5 py-1.5">{t('diffs.colDelta')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanComparisonRows.length ? (
                      scanComparisonRows.map((row) => (
                        <tr key={row.ip} className="border-b border-border/60 last:border-0">
                          <td className="px-2.5 py-1.5 font-mono font-medium">{row.ip}</td>
                          <td className="px-2.5 py-1.5 font-mono text-muted-foreground">
                            {row.aliveA === null
                              ? '—'
                              : row.aliveA
                                ? `up: ${row.portsA.join(', ') || 'brak portów'}`
                                : 'down'}
                          </td>
                          <td className="px-2.5 py-1.5 font-mono text-muted-foreground">
                            {row.aliveB === null
                              ? '—'
                              : row.aliveB
                                ? `up: ${row.portsB.join(', ') || 'brak portów'}`
                                : 'down'}
                          </td>
                          <td className="px-2.5 py-1.5">
                            <div className="flex flex-wrap gap-1">
                              {row.addedPorts.map((p) => (
                                <Badge key={`add-${p}`} variant="success">
                                  +{p}
                                </Badge>
                              ))}
                              {row.removedPorts.map((p) => (
                                <Badge key={`rem-${p}`} variant="destructive">
                                  -{p}
                                </Badge>
                              ))}
                              {row.addedPorts.length === 0 && row.removedPorts.length === 0 ? (
                                <span className="text-muted-foreground">
                                  {t('diffs.noPortDelta')}
                                </span>
                              ) : null}
                            </div>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={4} className="px-2.5 py-3 text-center text-muted-foreground">
                          {t('diffs.noSamplesToCompare')}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            ) : null}
          </div>

          <div className="grid gap-2 sm:grid-cols-3">
            <select
              value={kindFilter}
              onChange={(e) => setKindFilter(e.target.value as DiffEventKind | '')}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            >
              <option value="">{t('diffs.allKinds')}</option>
              <option value="confirmed_change">{t('diffs.kindConfirmed')}</option>
              <option value="active_variance">{t('diffs.kindVariance')}</option>
            </select>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value as DiffSeverity | '')}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            >
              <option value="">{t('diffs.allSeverities')}</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
            <select
              value={ackFilter}
              onChange={(e) => setAckFilter(e.target.value as 'all' | 'unack' | 'ack')}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            >
              <option value="all">{t('diffs.allAckStates')}</option>
              <option value="unack">{t('diffs.unacknowledgedOnly')}</option>
              <option value="ack">{t('diffs.acknowledgedOnly')}</option>
            </select>
          </div>

          <div className="space-y-3">
            {visibleDiffs.length ? (
              visibleDiffs.map((ev) => (
                <div
                  key={ev.id}
                  className="rounded-md border border-border bg-background/50 p-4 space-y-2.5"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-bold">{ev.ip_addr}</span>
                      <Badge
                        variant={
                          ev.event_kind === 'confirmed_change' ? 'default' : 'warning'
                        }
                      >
                        {ev.event_kind === 'confirmed_change'
                          ? t('diffs.kindConfirmed')
                          : t('diffs.kindVariance')}
                      </Badge>
                      <Badge variant={severityVariant(ev.severity)}>{ev.severity}</Badge>
                      {ev.acknowledged_at ? (
                        <Badge variant="success">{t('diffs.acknowledgedBadge')}</Badge>
                      ) : null}
                      <DiffDdBadge diffId={ev.id} />
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-muted-foreground">
                        {ev.detected_at}
                      </span>
                      {canPushDd ? (
                        <>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setEditingDiffId(ev.id)}
                            title={t('diffs.editPushDdBtn')}
                          >
                            <Pencil className="h-3.5 w-3.5" />
                            {t('diffs.editPushDdBtn')}
                          </Button>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => pushDdMutation.mutate(ev.id)}
                            disabled={pushDdMutation.isPending}
                            title={t('diffs.pushDdBtn')}
                          >
                            <Send className="h-3.5 w-3.5" />
                            {t('diffs.pushDdBtn')}
                          </Button>
                        </>
                      ) : null}
                      {canAck && !ev.acknowledged_at ? (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => ackMutation.mutate(ev.id)}
                          disabled={ackMutation.isPending}
                        >
                          <Check className="h-3.5 w-3.5" />
                          {t('diffs.acknowledgeBtn')}
                        </Button>
                      ) : null}
                    </div>
                  </div>

                  <ul className="space-y-1 text-sm">
                    {ev.bullet_items.map((bullet, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className={`font-mono font-bold ${opClass(bullet.op)}`}>
                          {bullet.op}
                        </span>
                        <span>{formatBullet(t, bullet)}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))
            ) : (
              <div className="rounded-md border border-border p-6 text-center text-sm text-muted-foreground">
                {t('diffs.empty')}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
      {editingDiffId ? (
        <DdPayloadModal
          mode="diff"
          targetId={editingDiffId}
          onClose={() => setEditingDiffId(null)}
        />
      ) : null}
    </div>
  );
}
