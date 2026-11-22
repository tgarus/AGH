import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BellRing, Plus, RefreshCw, Send, Trash2, Zap } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  formatApiError,
  type NotificationChannelDto,
  type NotificationChannelType,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { paginateItems, TablePagination } from '@/components/ui/pagination';
import { useAuth } from '@/context/AuthContext';

const WEBHOOK_EVENTS = [
  'diff.confirmed_change',
  'diff.active_variance',
  'scan.started',
  'scan.completed',
  'host.new_discovered',
  'host.admin_panel_detected',
  'host.anomaly_detected',
  'defectdojo.finding_pushed',
] as const;

export function NotificationsView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [name, setName] = useState('');
  const [channelType, setChannelType] = useState<NotificationChannelType>('webhook_json');
  const [webhookUrl, setWebhookUrl] = useState('https://soc.agh.local/webhooks/asi');
  const [customHeadersText, setCustomHeadersText] = useState('{}');
  const [customPayloadText, setCustomPayloadText] = useState('{}');
  const [smtpHost, setSmtpHost] = useState('smtp.agh.local');
  const [smtpPort, setSmtpPort] = useState(587);
  const [smtpFrom, setSmtpFrom] = useState('asi@agh.local');
  const [smtpTo, setSmtpTo] = useState('soc@agh.local');
  const [secret, setSecret] = useState('');
  const [subscribedEvents, setSubscribedEvents] = useState<string[]>([
    'diff.confirmed_change',
    'diff.active_variance',
    'scan.completed',
    'host.admin_panel_detected',
    'host.anomaly_detected',
  ]);
  const [triggerChannel, setTriggerChannel] = useState<NotificationChannelDto | null>(null);
  const [triggerEventType, setTriggerEventType] = useState('custom.manual_alert');
  const [triggerPayloadText, setTriggerPayloadText] = useState(
    '{\n  "severity": "high",\n  "message": "Manual incident escalation from ASI"\n}',
  );
  const [testFeedback, setTestFeedback] = useState<string | null>(null);
  const [channelsPage, setChannelsPage] = useState(1);
  const [channelsPerPage, setChannelsPerPage] = useState(10);
  const [deliveriesPage, setDeliveriesPage] = useState(1);
  const [deliveriesPerPage, setDeliveriesPerPage] = useState(10);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const channelsQuery = useQuery({
    queryKey: ['notification-channels'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/notifications/channels', {
        params: { query: { page: 1, per_page: 100 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load notification channels.'));
      }
      return data;
    },
  });

  const deliveriesQuery = useQuery({
    queryKey: ['notification-deliveries'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/notifications/deliveries', {
        params: { query: { page: 1, per_page: 100 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load deliveries.'));
      }
      return data;
    },
  });

  const pagedChannels = paginateItems(
    channelsQuery.data?.items ?? [],
    channelsPage,
    channelsPerPage,
  );
  const pagedDeliveries = paginateItems(
    deliveriesQuery.data?.items ?? [],
    deliveriesPage,
    deliveriesPerPage,
  );

  const parseJsonObjectField = (raw: string, fieldLabel: string): Record<string, unknown> | undefined => {
    const trimmed = raw.trim();
    if (!trimmed || trimmed === '{}') {
      return undefined;
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(trimmed);
    } catch {
      throw new Error(t('notifications.invalidJsonObject', { field: fieldLabel }));
    }
    if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) {
      throw new Error(t('notifications.invalidJsonObject', { field: fieldLabel }));
    }
    return decoded as Record<string, unknown>;
  };

  const toggleEventSubscription = (evt: string) => {
    setSubscribedEvents((prev) =>
      prev.includes(evt) ? prev.filter((item) => item !== evt) : [...prev, evt],
    );
  };

  const createMutation = useMutation({
    mutationFn: async () => {
      let configPublic: Record<string, unknown>;
      if (channelType === 'smtp') {
        configPublic = { host: smtpHost, port: smtpPort, from: smtpFrom, to: smtpTo };
      } else {
        configPublic = { url: webhookUrl };
        if (channelType === 'webhook_json') {
          const customHeaders = parseJsonObjectField(customHeadersText, 'custom_headers');
          const customPayload = parseJsonObjectField(customPayloadText, 'custom_payload_data');
          if (customHeaders) {
            configPublic.custom_headers = customHeaders;
          }
          if (customPayload) {
            configPublic.custom_payload_data = customPayload;
          }
        }
      }
      const { data, error } = await apiClient.POST('/api/v1/notifications/channels', {
        body: {
          name,
          channel_type: channelType,
          notify_on_confirmed: subscribedEvents.includes('diff.confirmed_change'),
          notify_on_variance: subscribedEvents.includes('diff.active_variance'),
          subscribed_events: subscribedEvents,
          config_public: configPublic,
          secret: secret.trim() || null,
          is_enabled: true,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to create notification channel.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      setName('');
      setSecret('');
      void queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const triggerCustomMutation = useMutation({
    mutationFn: async () => {
      if (!triggerChannel) {
        throw new Error('No channel selected');
      }
      let parsedPayload: unknown;
      try {
        parsedPayload = JSON.parse(triggerPayloadText);
      } catch {
        throw new Error(t('io.invalidJson'));
      }
      const { data, error } = await apiClient.POST(
        '/api/v1/notifications/channels/{id}/trigger',
        {
          params: { path: { id: triggerChannel.id } },
          body: {
            event_type: triggerEventType.trim() || 'custom.manual',
            payload: parsedPayload,
          },
        },
      );
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to trigger custom webhook.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setErrorMsg(null);
      setTestFeedback(`${res.delivered ? 'OK' : 'FAILED'}: ${res.detail}`);
      setTriggerChannel(null);
      void queryClient.invalidateQueries({ queryKey: ['notification-deliveries'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const toggleMutation = useMutation({
    mutationFn: async (ch: NotificationChannelDto) => {
      const { data, error } = await apiClient.PATCH('/api/v1/notifications/channels/{id}', {
        params: { path: { id: ch.id } },
        body: { is_enabled: !ch.is_enabled },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to update channel.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      const { data, error } = await apiClient.POST('/api/v1/notifications/channels/{id}/test', {
        params: { path: { id } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to send test notification.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setErrorMsg(null);
      setTestFeedback(`${res.delivered ? 'OK' : 'FAILED'}: ${res.detail}`);
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await apiClient.DELETE('/api/v1/notifications/channels/{id}', {
        params: { path: { id } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to delete channel.'));
      }
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['notification-channels'] });
      void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const canManage = hasPermission('manage_global_policies_and_notifications');

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    createMutation.mutate();
  };

  return (
    <div className="space-y-6">
      {errorMsg ? (
        <div className="rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {errorMsg}
        </div>
      ) : null}
      {testFeedback ? (
        <div className="rounded-md border border-primary/50 bg-transparent px-4 py-3 text-sm">
          {testFeedback}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-2">
            <div>
              <CardTitle>{t('notifications.channelsTitle')}</CardTitle>
              <CardDescription>{t('notifications.channelsSubtitle')}</CardDescription>
            </div>
            <Button variant="outline" size="sm" onClick={() => void channelsQuery.refetch()}>
              <RefreshCw className="h-4 w-4" />
              {t('health.refresh')}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {canManage ? (
            <form onSubmit={handleSubmit} className="space-y-3 rounded-md border border-border bg-background/40 p-4">
              <div className="grid gap-2 sm:grid-cols-3">
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder={t('notifications.namePlaceholder')}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
                <select
                  value={channelType}
                  onChange={(e) => setChannelType(e.target.value as NotificationChannelType)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                >
                  <option value="webhook_json">webhook_json (HMAC-SHA256)</option>
                  <option value="slack">slack</option>
                  <option value="teams">teams</option>
                  <option value="mattermost">mattermost</option>
                  <option value="smtp">smtp</option>
                </select>
                <input
                  type="password"
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  placeholder={t('notifications.secretPlaceholder')}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
              </div>

              {channelType === 'smtp' ? (
                <div className="grid gap-2 sm:grid-cols-4">
                  <input
                    type="text"
                    required
                    value={smtpHost}
                    onChange={(e) => setSmtpHost(e.target.value)}
                    placeholder="smtp.agh.local"
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                  <input
                    type="number"
                    required
                    value={smtpPort}
                    onChange={(e) => setSmtpPort(Number(e.target.value) || 587)}
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                  <input
                    type="email"
                    required
                    value={smtpFrom}
                    onChange={(e) => setSmtpFrom(e.target.value)}
                    placeholder="from@agh.local"
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                  <input
                    type="email"
                    required
                    value={smtpTo}
                    onChange={(e) => setSmtpTo(e.target.value)}
                    placeholder="to@agh.local"
                    className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                </div>
              ) : (
                <div className="space-y-2">
                  <input
                    type="url"
                    required
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://..."
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  />
                  {channelType === 'webhook_json' ? (
                    <div className="grid gap-2 sm:grid-cols-2">
                      <div>
                        <label className="mb-1 block text-xs text-muted-foreground">
                          {t('notifications.customHeadersLabel')}
                        </label>
                        <textarea
                          rows={2}
                          value={customHeadersText}
                          onChange={(e) => setCustomHeadersText(e.target.value)}
                          placeholder='{"X-Team": "SOC"}'
                          className="w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
                        />
                      </div>
                      <div>
                        <label className="mb-1 block text-xs text-muted-foreground">
                          {t('notifications.customPayloadLabel')}
                        </label>
                        <textarea
                          rows={2}
                          value={customPayloadText}
                          onChange={(e) => setCustomPayloadText(e.target.value)}
                          placeholder='{"env": "prod"}'
                          className="w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
                        />
                      </div>
                    </div>
                  ) : null}
                </div>
              )}

              <div className="space-y-2">
                <div className="text-xs font-medium text-muted-foreground">
                  {t('notifications.subscribedEventsLabel')}
                </div>
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap gap-3 text-xs">
                    {WEBHOOK_EVENTS.map((evt) => (
                      <label key={evt} className="flex items-center gap-1.5 font-mono">
                        <input
                          type="checkbox"
                          checked={subscribedEvents.includes(evt)}
                          onChange={() => toggleEventSubscription(evt)}
                        />
                        <span>{evt}</span>
                      </label>
                    ))}
                  </div>
                  <Button type="submit" size="sm" disabled={createMutation.isPending}>
                    <Plus className="h-4 w-4" />
                    {t('notifications.addChannel')}
                  </Button>
                </div>
              </div>
            </form>
          ) : null}

          {triggerChannel ? (
            <div className="space-y-3 rounded-md border border-primary/50 bg-background/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-semibold">
                  {t('notifications.triggerTitle', { name: triggerChannel.name })}
                </div>
                <Button variant="ghost" size="sm" onClick={() => setTriggerChannel(null)}>
                  {t('integrations.modal.close')}
                </Button>
              </div>
              <div className="grid gap-2 sm:grid-cols-3">
                <input
                  type="text"
                  value={triggerEventType}
                  onChange={(e) => setTriggerEventType(e.target.value)}
                  placeholder="custom.manual_alert"
                  className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs"
                />
                <textarea
                  rows={3}
                  value={triggerPayloadText}
                  onChange={(e) => setTriggerPayloadText(e.target.value)}
                  className="rounded-md border border-border bg-background p-2 font-mono text-xs sm:col-span-2"
                />
              </div>
              <div className="flex justify-end">
                <Button
                  size="sm"
                  onClick={() => triggerCustomMutation.mutate()}
                  disabled={triggerCustomMutation.isPending}
                >
                  <Zap className="h-3.5 w-3.5" />
                  {t('notifications.sendCustomBtn')}
                </Button>
              </div>
            </div>
          ) : null}

          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">{t('notifications.colChannel')}</th>
                  <th className="px-3 py-2">{t('notifications.colFilters')}</th>
                  <th className="px-3 py-2">{t('admin.status')}</th>
                  <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {pagedChannels.items.length ? (
                  pagedChannels.items.map((ch) => (
                    <tr key={ch.id} className="border-b border-border/60 last:border-0">
                      <td className="px-3 py-2">
                        <div className="font-semibold">{ch.name}</div>
                        <div className="font-mono text-muted-foreground">
                          {ch.channel_type} {ch.has_secret ? '· AES-256 secret' : ''}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-1">
                          {(ch.subscribed_events?.length
                            ? ch.subscribed_events
                            : [
                                ...(ch.notify_on_confirmed ? ['diff.confirmed_change'] : []),
                                ...(ch.notify_on_variance ? ['diff.active_variance'] : []),
                              ]
                          ).map((evt) => (
                            <Badge key={evt} variant="outline" className="font-mono text-[10px]">
                              {evt}
                            </Badge>
                          ))}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <Badge variant={ch.is_enabled ? 'success' : 'outline'}>
                          {ch.is_enabled ? t('admin.active') : t('admin.inactive')}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-right">
                        {canManage ? (
                          <div className="inline-flex gap-1">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => setTriggerChannel(ch)}
                              title={t('notifications.triggerBtn')}
                            >
                              <Zap className="h-3.5 w-3.5" />
                              {t('notifications.triggerBtn')}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => testMutation.mutate(ch.id)}
                            >
                              <Send className="h-3.5 w-3.5" />
                              {t('notifications.testBtn')}
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => toggleMutation.mutate(ch)}
                            >
                              <BellRing className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => deleteMutation.mutate(ch.id)}
                            >
                              <Trash2 className="h-3.5 w-3.5 text-red-400" />
                            </Button>
                          </div>
                        ) : null}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={4} className="px-3 py-4 text-center text-muted-foreground">
                      {t('notifications.emptyChannels')}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <TablePagination
            page={pagedChannels.safePage}
            perPage={channelsPerPage}
            totalItems={pagedChannels.totalItems}
            onPageChange={setChannelsPage}
            onPerPageChange={(n) => {
              setChannelsPerPage(n);
              setChannelsPage(1);
            }}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t('notifications.deliveriesTitle')}</CardTitle>
          <CardDescription>{t('notifications.deliveriesSubtitle')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">{t('notifications.colChannel')}</th>
                  <th className="px-3 py-2">{t('notifications.colEvent')}</th>
                  <th className="px-3 py-2">{t('admin.status')}</th>
                  <th className="px-3 py-2">{t('notifications.colAttempts')}</th>
                  <th className="px-3 py-2">{t('notifications.colPayloadOrError')}</th>
                </tr>
              </thead>
              <tbody>
                {pagedDeliveries.items.length ? (
                  pagedDeliveries.items.map((d) => (
                    <tr key={d.id} className="border-b border-border/60 last:border-0">
                      <td className="px-3 py-2 font-medium">{d.channel_name}</td>
                      <td className="px-3 py-2 font-mono text-[11px]">{d.event_type}</td>
                      <td className="px-3 py-2">
                        <Badge
                          variant={
                            d.status === 'sent'
                              ? 'success'
                              : d.status === 'pending'
                                ? 'warning'
                                : 'destructive'
                          }
                        >
                          {d.status}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 font-mono">{d.attempt_count}</td>
                      <td className="px-3 py-2 text-muted-foreground">
                        {d.last_error ? (
                          <span className="text-red-300">{d.last_error}</span>
                        ) : d.custom_payload ? (
                          <code className="block max-w-md truncate font-mono text-[11px]">
                            {JSON.stringify(d.custom_payload)}
                          </code>
                        ) : (
                          '—'
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-3 py-4 text-center text-muted-foreground">
                      {t('notifications.emptyDeliveries')}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <TablePagination
            page={pagedDeliveries.safePage}
            perPage={deliveriesPerPage}
            totalItems={pagedDeliveries.totalItems}
            onPageChange={setDeliveriesPage}
            onPerPageChange={(n) => {
              setDeliveriesPerPage(n);
              setDeliveriesPage(1);
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}
