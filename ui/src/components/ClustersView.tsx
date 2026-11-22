import { useQuery } from '@tanstack/react-query';
import { Download, RefreshCw } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError, type ClusterKind } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

export function ClustersView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const [kind, setKind] = useState<ClusterKind>('favicon');
  const [minMembers, setMinMembers] = useState(2);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const clustersQuery = useQuery({
    queryKey: ['clusters', kind, minMembers],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/clusters', {
        params: {
          query: {
            kind,
            min_members: minMembers,
          },
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load service clusters.'));
      }
      return data;
    },
  });

  const handleExportServices = async () => {
    setErrorMsg(null);
    const { data, error } = await apiClient.GET('/api/v1/export/services', {
      params: { query: {} },
    });
    if (error || !data) {
      setErrorMsg(formatApiError(error, 'Failed to export services JSON.'));
      return;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'asi-services.json';
    link.click();
    URL.revokeObjectURL(url);
  };

  const canExport = hasPermission('export_reports');

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
              <CardTitle>{t('clusters.title')}</CardTitle>
              <CardDescription>{t('clusters.subtitle')}</CardDescription>
            </div>
            <div className="flex gap-2">
              {canExport ? (
                <Button variant="outline" size="sm" onClick={() => void handleExportServices()}>
                  <Download className="h-4 w-4" />
                  {t('io.exportJson')}
                </Button>
              ) : null}
              <Button variant="outline" size="sm" onClick={() => void clustersQuery.refetch()}>
                <RefreshCw className="h-4 w-4" />
                {t('health.refresh')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-3">
            <select
              value={kind}
              onChange={(e) => setKind(e.target.value as ClusterKind)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            >
              <option value="favicon">{t('clusters.kindFavicon')}</option>
              <option value="title">{t('clusters.kindTitle')}</option>
              <option value="technology">{t('clusters.kindTechnology')}</option>
            </select>
            <select
              value={minMembers}
              onChange={(e) => setMinMembers(Number(e.target.value) || 2)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            >
              <option value={2}>{t('clusters.minMembersLabel', { count: 2 })}</option>
              <option value={3}>{t('clusters.minMembersLabel', { count: 3 })}</option>
              <option value={5}>{t('clusters.minMembersLabel', { count: 5 })}</option>
            </select>
          </div>

          {clustersQuery.data?.length ? (
            <div className="space-y-4">
              {clustersQuery.data.map((cluster) => (
                <div
                  key={cluster.cluster_key}
                  className="rounded-md border border-border bg-background/50 p-4 space-y-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-semibold text-sm">{cluster.label}</div>
                    <Badge variant="default">
                      {t('clusters.membersBadge', { count: cluster.member_count })}
                    </Badge>
                  </div>
                  <div className="overflow-x-auto rounded border border-border">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
                        <tr>
                          <th className="px-3 py-1.5">IP</th>
                          <th className="px-3 py-1.5">{t('clusters.colEndpoint')}</th>
                          <th className="px-3 py-1.5">{t('clusters.colTitle')}</th>
                          <th className="px-3 py-1.5">{t('clusters.colTech')}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {cluster.members.map((m, idx) => (
                          <tr
                            key={`${m.host_id}-${m.port}-${idx}`}
                            className="border-b border-border/60 last:border-0"
                          >
                            <td className="px-3 py-1.5 font-mono">
                              {m.ip_addr} ({m.asset_group_name})
                            </td>
                            <td className="px-3 py-1.5 font-mono">
                              {m.scheme ?? 'http'}://{m.vhost ?? m.ip_addr}:{m.port} [
                              {m.http_status ?? '—'}]
                            </td>
                            <td className="px-3 py-1.5">{m.title ?? '—'}</td>
                            <td className="px-3 py-1.5">
                              {m.matched_technologies.join(', ') || '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-md border border-border p-6 text-center text-sm text-muted-foreground">
              {t('clusters.empty')}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
