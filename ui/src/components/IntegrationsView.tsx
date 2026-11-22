import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Plug, RefreshCw, Send, Wifi } from 'lucide-react';
import { useEffect, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

type FindingScope = 'changes' | 'all_diffs' | 'inventory';

const SCOPE_KEYS: Record<FindingScope, string> = {
  changes: 'integrations.scope.changes',
  all_diffs: 'integrations.scope.allDiffs',
  inventory: 'integrations.scope.inventory',
};

export function IntegrationsView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();
  const canManage = hasPermission('manage_external_integrations');

  const [baseUrl, setBaseUrl] = useState('');
  const [asiPublicUrl, setAsiPublicUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [scope, setScope] = useState<FindingScope>('changes');
  const [autoPush, setAutoPush] = useState(true);
  const [pullInterval, setPullInterval] = useState(15);
  const [enabled, setEnabled] = useState(false);
  const [formMsg, setFormMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);

  const configQuery = useQuery({
    queryKey: ['dd-config'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/integrations/defectdojo');
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load DefectDojo config.'));
      }
      return data;
    },
  });

  const outboxQuery = useQuery({
    queryKey: ['dd-outbox'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/integrations/defectdojo/outbox', {
        params: { query: { page: 1, per_page: 20 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load DefectDojo outbox.'));
      }
      return data;
    },
    refetchInterval: 10_000,
  });

  useEffect(() => {
    const cfg = configQuery.data;
    if (cfg) {
      setBaseUrl(cfg.base_url);
      setScope(cfg.finding_scope as FindingScope);
      setAutoPush(cfg.auto_push);
      setPullInterval(cfg.pull_interval_minutes);
      setEnabled(cfg.enabled);
    }
  }, [configQuery.data]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = {
        base_url: baseUrl.trim(),
        asi_public_url: asiPublicUrl.trim(),
        finding_scope: scope,
        auto_push: autoPush,
        pull_interval_minutes: pullInterval,
        enabled,
      };
      if (apiKey.trim()) {
        body.api_key = apiKey.trim();
      }
      const { data, error } = await apiClient.PUT('/api/v1/integrations/defectdojo', { body });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to save DefectDojo config.'));
      }
      return data;
    },
    onSuccess: () => {
      setApiKey('');
      setFormMsg({ kind: 'ok', text: t('integrations.messages.saved') });
      void queryClient.invalidateQueries({ queryKey: ['dd-config'] });
    },
    onError: (err) => setFormMsg({ kind: 'err', text: err.message }),
  });

  const testMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST(
        '/api/v1/integrations/defectdojo/test-connection',
      );
      if (error) {
        throw new Error(formatApiError(error, 'Connection test failed.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setTestResult({
        ok: Boolean(res?.ok),
        text: res?.ok
          ? t('integrations.messages.testOk', { count: res.product_count ?? 0 })
          : t('integrations.messages.testFail', { error: res?.error ?? '' }),
      });
    },
    onError: (err) => setTestResult({ ok: false, text: err.message }),
  });

  const syncMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/integrations/defectdojo/sync', {
        body: {},
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Sync failed.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setFormMsg({
        kind: 'ok',
        text: t('integrations.messages.syncEnqueued', { count: res?.enqueued ?? 0 }),
      });
      void queryClient.invalidateQueries({ queryKey: ['dd-outbox'] });
      void queryClient.invalidateQueries({ queryKey: ['dd-config'] });
    },
    onError: (err) => setFormMsg({ kind: 'err', text: err.message }),
  });

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    setFormMsg(null);
    saveMutation.mutate();
  };

  const cfg = configQuery.data;
  const inputCls =
    'w-full rounded-md border border-border bg-background px-3 py-2 text-sm disabled:opacity-60';
  const labelCls = 'mb-1 block text-xs font-medium text-muted-foreground';

  const outboxStatusVariant = (s: string) => {
    if (s === 'sent') return 'success' as const;
    if (s === 'failed') return 'destructive' as const;
    if (s === 'processing') return 'warning' as const;
    return 'outline' as const;
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Plug className="h-5 w-5" />
                {t('integrations.title')}
              </CardTitle>
              <CardDescription>{t('integrations.subtitle')}</CardDescription>
            </div>
            {cfg ? (
              <Badge variant={cfg.enabled ? 'success' : 'outline'}>
                {cfg.enabled ? t('integrations.enabled') : t('integrations.disabled')}
              </Badge>
            ) : null}
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {formMsg ? (
            <div
              className={`rounded-md border px-4 py-3 text-sm ${
                formMsg.kind === 'ok'
                  ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300'
                  : 'border-red-800 bg-red-950/40 text-red-300'
              }`}
            >
              {formMsg.text}
            </div>
          ) : null}

          <div className="grid gap-4 md:grid-cols-2">
            <div>
              <span className={labelCls}>{t('integrations.status.lastPush')}</span>
              <div className="text-sm">{cfg?.last_push_at ?? '—'}</div>
            </div>
            <div>
              <span className={labelCls}>{t('integrations.status.lastPull')}</span>
              <div className="text-sm">{cfg?.last_pull_at ?? '—'}</div>
            </div>
            <div>
              <span className={labelCls}>{t('integrations.status.pendingOutbox')}</span>
              <div className="text-sm">{cfg?.pending_outbox ?? 0}</div>
            </div>
            <div>
              <span className={labelCls}>{t('integrations.status.hasApiKey')}</span>
              <div className="text-sm">{cfg?.has_api_key ? t('common.yes') : t('common.no')}</div>
            </div>
          </div>

          {cfg?.last_error ? (
            <div className="rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
              {cfg.last_error}
            </div>
          ) : null}

          <form onSubmit={onSubmit} className="grid gap-4 md:grid-cols-2">
            <div>
              <label className={labelCls}>{t('integrations.form.baseUrl')}</label>
              <input
                className={inputCls}
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                placeholder="https://defectdojo.agh.edu.pl"
                disabled={!canManage}
              />
            </div>
            <div>
              <label className={labelCls}>{t('integrations.form.asiPublicUrl')}</label>
              <input
                className={inputCls}
                value={asiPublicUrl}
                onChange={(e) => setAsiPublicUrl(e.target.value)}
                placeholder="https://asi.agh.edu.pl"
                disabled={!canManage}
              />
            </div>
            <div>
              <label className={labelCls}>{t('integrations.form.apiKey')}</label>
              <input
                type="password"
                className={inputCls}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={cfg?.has_api_key ? t('integrations.form.apiKeyKeep') : '••••••••'}
                disabled={!canManage}
              />
            </div>
            <div>
              <label className={labelCls}>{t('integrations.form.scope')}</label>
              <select
                className={inputCls}
                value={scope}
                onChange={(e) => setScope(e.target.value as FindingScope)}
                disabled={!canManage}
              >
                {(Object.keys(SCOPE_KEYS) as FindingScope[]).map((s) => (
                  <option key={s} value={s}>
                    {t(SCOPE_KEYS[s])}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelCls}>{t('integrations.form.pullInterval')}</label>
              <input
                type="number"
                min={1}
                max={1440}
                className={inputCls}
                value={pullInterval}
                onChange={(e) => setPullInterval(Number(e.target.value))}
                disabled={!canManage}
              />
            </div>
            <div className="flex items-center gap-6 pt-5">
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={enabled}
                  onChange={(e) => setEnabled(e.target.checked)}
                  disabled={!canManage}
                />
                {t('integrations.form.enabled')}
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={autoPush}
                  onChange={(e) => setAutoPush(e.target.checked)}
                  disabled={!canManage}
                />
                {t('integrations.form.autoPush')}
              </label>
            </div>

            {canManage ? (
              <div className="flex flex-wrap gap-2 md:col-span-2">
                <Button type="submit" size="sm" disabled={saveMutation.isPending}>
                  {t('integrations.actions.save')}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => testMutation.mutate()}
                  disabled={testMutation.isPending}
                >
                  <Wifi className="h-4 w-4" />
                  {t('integrations.actions.testConnection')}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => syncMutation.mutate()}
                  disabled={syncMutation.isPending}
                >
                  <Send className="h-4 w-4" />
                  {t('integrations.actions.syncNow')}
                </Button>
              </div>
            ) : null}
          </form>

          {testResult ? (
            <div
              className={`rounded-md border px-4 py-3 text-sm ${
                testResult.ok
                  ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300'
                  : 'border-red-800 bg-red-950/40 text-red-300'
              }`}
            >
              {testResult.text}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>{t('integrations.outbox.title')}</CardTitle>
              <CardDescription>{t('integrations.outbox.subtitle')}</CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void outboxQuery.refetch()}
            >
              <RefreshCw className="h-4 w-4" />
              {t('health.refresh')}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {outboxQuery.data?.items.length ? (
              outboxQuery.data.items.map((item) => (
                <div
                  key={item.id}
                  className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-md border border-border bg-background/50 px-3 py-2 text-sm"
                >
                  <Badge variant={outboxStatusVariant(item.status)}>{item.status}</Badge>
                  <span className="font-medium">{item.kind}</span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {item.diff_event_id ?? item.scan_run_id ?? item.asset_group_id}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {t('integrations.outbox.attempts')}: {item.attempt_count}
                  </span>
                  {item.next_retry_at ? (
                    <span className="text-xs text-amber-300">
                      {t('integrations.outbox.retryAt')}: {item.next_retry_at}
                    </span>
                  ) : null}
                  {item.last_error ? (
                    <span className="text-xs text-red-300">{item.last_error}</span>
                  ) : null}
                  <span className="ml-auto font-mono text-xs text-muted-foreground">
                    {item.created_at}
                  </span>
                </div>
              ))
            ) : (
              <div className="rounded-md border border-border p-6 text-center text-sm text-muted-foreground">
                {t('integrations.outbox.empty')}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
