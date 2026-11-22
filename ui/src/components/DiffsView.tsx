import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Check, Download, RefreshCw, Send } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  formatApiError,
  type DiffEventKind,
  type DiffSeverity,
} from '@/api/client';
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
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

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
            <div className="flex gap-2">
              {canExport ? (
                <Button variant="outline" size="sm" onClick={() => void handleExportDiffs()}>
                  <Download className="h-4 w-4" />
                  {t('io.exportJson')}
                </Button>
              ) : null}
              <Button variant="outline" size="sm" onClick={() => void diffsQuery.refetch()}>
                <RefreshCw className="h-4 w-4" />
                {t('health.refresh')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
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
            {diffsQuery.data?.items.length ? (
              diffsQuery.data.items.map((ev) => (
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
    </div>
  );
}
