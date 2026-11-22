import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, Plus, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError, type IgnoredTargetType } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

export function IgnoredTargetsView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [targetType, setTargetType] = useState<IgnoredTargetType>('ip');
  const [value, setValue] = useState('');
  const [reason, setReason] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ['ignored-targets'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/ignored-targets', {
        params: { query: { page: 1, per_page: 100 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load ignored targets.'));
      }
      return data;
    },
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/ignored-targets', {
        body: {
          asset_group_id: null,
          target_type: targetType,
          value,
          reason,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to add ignored target.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      setValue('');
      setReason('');
      void queryClient.invalidateQueries({ queryKey: ['ignored-targets'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await apiClient.DELETE('/api/v1/ignored-targets/{id}', {
        params: { path: { id } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to delete ignored target.'));
      }
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['ignored-targets'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const handleExport = async () => {
    setErrorMsg(null);
    const { data, error } = await apiClient.GET('/api/v1/export/ignored-targets');
    if (error || !data) {
      setErrorMsg(formatApiError(error, 'Export failed.'));
      return;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'asi-ignored-targets.json';
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    createMutation.mutate();
  };

  const canManage = hasPermission('manage_ignored_targets');
  const canExport = hasPermission('export_reports');

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <CardTitle>{t('ignored.title')}</CardTitle>
            <CardDescription>{t('ignored.subtitle')}</CardDescription>
          </div>
          {canExport ? (
            <Button variant="outline" size="sm" onClick={() => void handleExport()}>
              <Download className="h-4 w-4" />
              {t('io.exportJson')}
            </Button>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {errorMsg ? (
          <div className="rounded-md border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">
            {errorMsg}
          </div>
        ) : null}

        {canManage ? (
          <form onSubmit={handleSubmit} className="grid gap-2 sm:grid-cols-4">
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value as IgnoredTargetType)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            >
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="domain">Domain</option>
            </select>
            <input
              type="text"
              required
              placeholder={t('assetGroups.targetPlaceholder')}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
            <input
              type="text"
              required
              placeholder={t('ignored.reasonPlaceholder')}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
            <Button type="submit" size="sm" disabled={createMutation.isPending}>
              <Plus className="h-4 w-4" />
              {t('ignored.addButton')}
            </Button>
          </form>
        ) : null}

        <div className="overflow-x-auto rounded-md border border-border">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2">{t('assetGroups.colType')}</th>
                <th className="px-3 py-2">{t('assetGroups.colValue')}</th>
                <th className="px-3 py-2">{t('ignored.colReason')}</th>
                <th className="px-3 py-2 text-right">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody>
              {listQuery.data?.items.length ? (
                listQuery.data.items.map((item) => (
                  <tr key={item.id} className="border-b border-border/60 last:border-0">
                    <td className="px-3 py-2">
                      <Badge variant="outline">{item.target_type}</Badge>
                    </td>
                    <td className="px-3 py-2 font-mono">{item.value}</td>
                    <td className="px-3 py-2 text-muted-foreground">{item.reason}</td>
                    <td className="px-3 py-2 text-right">
                      {canManage ? (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteMutation.mutate(item.id)}
                        >
                          <Trash2 className="h-4 w-4 text-red-400" />
                        </Button>
                      ) : null}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="px-3 py-4 text-center text-muted-foreground">
                    {t('ignored.empty')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
