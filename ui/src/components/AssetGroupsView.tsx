import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, Plus, Trash2, Upload } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  formatApiError,
  type ImportTargetsJsonResponse,
  type TargetType,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

export function AssetGroupsView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [policyId, setPolicyId] = useState('');
  const [targetType, setTargetType] = useState<TargetType>('cidr');
  const [targetValue, setTargetValue] = useState('');
  const [targetNotes, setTargetNotes] = useState('');
  const [jsonInput, setJsonInput] = useState(
    '{\n  "schema_version": "1.0",\n  "items": [\n    { "target_type": "cidr", "value": "172.28.0.0/24", "notes": "Mock Lab" }\n  ]\n}',
  );
  const [importResult, setImportResult] = useState<ImportTargetsJsonResponse | null>(null);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);

  const [policyName, setPolicyName] = useState('');
  const [portSpec, setPortSpec] = useState('top-1000');
  const [discoveryTool, setDiscoveryTool] = useState<'naabu' | 'masscan'>('naabu');
  const [ratePps, setRatePps] = useState(500);
  const [inactivityK, setInactivityK] = useState(3);
  const [tarpitThreshold, setTarpitThreshold] = useState(200);
  const [windowStart, setWindowStart] = useState('00:00');
  const [windowEnd, setWindowEnd] = useState('23:59');
  const [enableNuclei, setEnableNuclei] = useState(false);

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

  const policiesQuery = useQuery({
    queryKey: ['policies'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/policies', {
        params: { query: { page: 1, per_page: 100 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load policies.'));
      }
      return data;
    },
  });

  const activeGroupId = selectedGroupId ?? groupsQuery.data?.items[0]?.id ?? null;

  const detailQuery = useQuery({
    queryKey: ['asset-group-detail', activeGroupId],
    enabled: Boolean(activeGroupId),
    queryFn: async () => {
      if (!activeGroupId) {
        throw new Error('No group selected');
      }
      const { data, error } = await apiClient.GET('/api/v1/asset-groups/{id}', {
        params: { path: { id: activeGroupId } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load group details.'));
      }
      return data;
    },
  });

  const createGroupMutation = useMutation({
    mutationFn: async () => {
      const chosenPolicy = policyId || policiesQuery.data?.items[0]?.id;
      if (!chosenPolicy) {
        throw new Error(t('assetGroups.noPolicyAvailable'));
      }
      const { data, error } = await apiClient.POST('/api/v1/asset-groups', {
        body: {
          name: groupName,
          description: groupDesc || null,
          policy_id: chosenPolicy,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to create asset group.'));
      }
      return data;
    },
    onSuccess: (created) => {
      setFeedbackError(null);
      setGroupName('');
      setGroupDesc('');
      setSelectedGroupId(created.id);
      void queryClient.invalidateQueries({ queryKey: ['asset-groups'] });
    },
    onError: (err) => setFeedbackError(err.message),
  });

  const addTargetMutation = useMutation({
    mutationFn: async () => {
      if (!activeGroupId) {
        throw new Error('Select a group first.');
      }
      const { data, error } = await apiClient.POST('/api/v1/asset-groups/{id}/targets', {
        params: { path: { id: activeGroupId } },
        body: {
          targets: [
            {
              target_type: targetType,
              value: targetValue,
              notes: targetNotes || null,
            },
          ],
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to add target.'));
      }
      return data;
    },
    onSuccess: () => {
      setFeedbackError(null);
      setTargetValue('');
      setTargetNotes('');
      void queryClient.invalidateQueries({ queryKey: ['asset-groups'] });
      void queryClient.invalidateQueries({ queryKey: ['asset-group-detail', activeGroupId] });
    },
    onError: (err) => setFeedbackError(err.message),
  });

  const deleteTargetMutation = useMutation({
    mutationFn: async (targetId: string) => {
      if (!activeGroupId) {
        return;
      }
      const { error } = await apiClient.DELETE('/api/v1/asset-groups/{id}/targets/{target_id}', {
        params: { path: { id: activeGroupId, target_id: targetId } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to remove target.'));
      }
    },
    onSuccess: () => {
      setFeedbackError(null);
      void queryClient.invalidateQueries({ queryKey: ['asset-groups'] });
      void queryClient.invalidateQueries({ queryKey: ['asset-group-detail', activeGroupId] });
    },
    onError: (err) => setFeedbackError(err.message),
  });

  const importJsonMutation = useMutation({
    mutationFn: async (dryRun: boolean) => {
      if (!activeGroupId) {
        throw new Error('Select an asset group before importing JSON targets.');
      }
      let parsed: {
        schema_version?: string;
        items?: Array<{ target_type: TargetType; value: string; notes?: string | null }>;
      };
      try {
        parsed = JSON.parse(jsonInput) as typeof parsed;
      } catch {
        throw new Error(t('io.invalidJson'));
      }
      const { data, error } = await apiClient.POST('/api/v1/import/targets', {
        body: {
          schema_version: parsed.schema_version ?? '1.0',
          asset_group_id: activeGroupId,
          dry_run: dryRun,
          items: parsed.items ?? [],
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'JSON import failed.'));
      }
      return data;
    },
    onSuccess: (summary) => {
      setFeedbackError(null);
      setImportResult(summary);
      if (!summary.dry_run) {
        void queryClient.invalidateQueries({ queryKey: ['asset-groups'] });
        void queryClient.invalidateQueries({ queryKey: ['asset-group-detail', activeGroupId] });
      }
    },
    onError: (err) => setFeedbackError(err.message),
  });

  const handleExportJson = async () => {
    setFeedbackError(null);
    const { data, error } = await apiClient.GET('/api/v1/export/targets', {
      params: { query: activeGroupId ? { asset_group_id: activeGroupId } : {} },
    });
    if (error || !data) {
      setFeedbackError(formatApiError(error, 'JSON export failed.'));
      return;
    }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `asi-targets-${activeGroupId ?? 'all'}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleCreateGroup = (e: FormEvent) => {
    e.preventDefault();
    createGroupMutation.mutate();
  };

  const handleAddTarget = (e: FormEvent) => {
    e.preventDefault();
    addTargetMutation.mutate();
  };

  const createPolicyMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/policies', {
        body: {
          name: policyName,
          port_spec: portSpec,
          discovery_tool: discoveryTool,
          rate_pps: ratePps,
          per_ip_cooldown_ms: 250,
          subnet_concurrency: 4,
          kill_grace_seconds: 3,
          inactivity_threshold: inactivityK,
          tarpit_port_threshold: tarpitThreshold,
          enable_nuclei: enableNuclei,
          time_windows: {
            allowed_windows: [
              { start: windowStart, end: windowEnd, timezone: 'Europe/Warsaw' },
            ],
            sampling_slots: ['00_06', '06_12', '12_18', '18_24'],
          },
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to create scan policy.'));
      }
      return data;
    },
    onSuccess: () => {
      setFeedbackError(null);
      setPolicyName('');
      void queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
    onError: (err) => setFeedbackError(err.message),
  });

  const deletePolicyMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await apiClient.DELETE('/api/v1/policies/{id}', {
        params: { path: { id } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to delete policy.'));
      }
    },
    onSuccess: () => {
      setFeedbackError(null);
      void queryClient.invalidateQueries({ queryKey: ['policies'] });
    },
    onError: (err) => setFeedbackError(err.message),
  });

  const canManageGroups = hasPermission('manage_asset_groups');
  const canManagePolicies = hasPermission('manage_group_policies');
  const canDeleteTargets = canManageGroups && hasPermission('delete_local_targets_and_results');
  const canImport = hasPermission('import_data');
  const canExport = hasPermission('export_reports');

  return (
    <div className="space-y-6">
      {feedbackError ? (
        <div className="rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {feedbackError}
        </div>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>{t('assetGroups.listTitle')}</CardTitle>
            <CardDescription>{t('assetGroups.listSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {groupsQuery.data?.items.length ? (
              <div className="space-y-2">
                {groupsQuery.data.items.map((grp) => (
                  <button
                    key={grp.id}
                    type="button"
                    onClick={() => setSelectedGroupId(grp.id)}
                    className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm transition-colors ${
                      activeGroupId === grp.id
                        ? 'border-primary bg-secondary text-foreground'
                        : 'border-border bg-background/40 text-muted-foreground hover:bg-secondary/50'
                    }`}
                  >
                    <span className="font-medium">{grp.name}</span>
                    <Badge variant="outline">{grp.target_count}</Badge>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">{t('assetGroups.empty')}</p>
            )}

            {canManageGroups ? (
              <form onSubmit={handleCreateGroup} className="space-y-3 border-t border-border pt-4">
                <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  {t('assetGroups.createTitle')}
                </div>
                <input
                  type="text"
                  required
                  placeholder={t('assetGroups.namePlaceholder')}
                  value={groupName}
                  onChange={(e) => setGroupName(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
                <input
                  type="text"
                  placeholder={t('assetGroups.descPlaceholder')}
                  value={groupDesc}
                  onChange={(e) => setGroupDesc(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
                <select
                  value={policyId || policiesQuery.data?.items[0]?.id || ''}
                  onChange={(e) => setPolicyId(e.target.value)}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                >
                  {policiesQuery.data?.items.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} ({p.port_spec})
                    </option>
                  ))}
                </select>
                <Button type="submit" size="sm" className="w-full" disabled={createGroupMutation.isPending}>
                  <Plus className="h-4 w-4" />
                  {t('assetGroups.createButton')}
                </Button>
              </form>
            ) : null}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle>{detailQuery.data?.group.name ?? t('assetGroups.selectGroup')}</CardTitle>
                <CardDescription>
                  {detailQuery.data
                    ? `${t('assetGroups.policyLabel')}: ${detailQuery.data.policy.name} (${detailQuery.data.policy.port_spec})`
                    : t('assetGroups.selectGroupHint')}
                </CardDescription>
              </div>
              {canExport ? (
                <Button variant="outline" size="sm" onClick={() => void handleExportJson()}>
                  <Download className="h-4 w-4" />
                  {t('io.exportJson')}
                </Button>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className="space-y-6">
            {activeGroupId && canManageGroups ? (
              <form onSubmit={handleAddTarget} className="grid gap-2 sm:grid-cols-4">
                <select
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value as TargetType)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                >
                  <option value="cidr">CIDR</option>
                  <option value="ip">IP</option>
                  <option value="domain">Domain</option>
                  <option value="exclude_cidr">Exclude CIDR</option>
                </select>
                <input
                  type="text"
                  required
                  placeholder={t('assetGroups.targetPlaceholder')}
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
                <input
                  type="text"
                  placeholder={t('assetGroups.notesPlaceholder')}
                  value={targetNotes}
                  onChange={(e) => setTargetNotes(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
                <Button type="submit" size="sm" disabled={addTargetMutation.isPending}>
                  <Plus className="h-4 w-4" />
                  {t('assetGroups.addTarget')}
                </Button>
              </form>
            ) : null}

            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2">{t('assetGroups.colType')}</th>
                    <th className="px-3 py-2">{t('assetGroups.colValue')}</th>
                    <th className="px-3 py-2">{t('assetGroups.colNotes')}</th>
                    <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {detailQuery.data?.targets.length ? (
                    detailQuery.data.targets.map((tgt) => (
                      <tr key={tgt.id} className="border-b border-border/60 last:border-0">
                        <td className="px-3 py-2">
                          <Badge variant={tgt.target_type === 'exclude_cidr' ? 'warning' : 'outline'}>
                            {tgt.target_type}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 font-mono">{tgt.value}</td>
                        <td className="px-3 py-2 text-muted-foreground">{tgt.notes ?? '—'}</td>
                        <td className="px-3 py-2 text-right">
                          {canDeleteTargets ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => deleteTargetMutation.mutate(tgt.id)}
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
                        {t('assetGroups.noTargets')}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {activeGroupId && canImport ? (
              <div className="space-y-3 border-t border-border pt-4">
                <div className="text-sm font-semibold">{t('io.importTitle')}</div>
                <textarea
                  rows={5}
                  value={jsonInput}
                  onChange={(e) => setJsonInput(e.target.value)}
                  className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs"
                />
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => importJsonMutation.mutate(true)}
                    disabled={importJsonMutation.isPending}
                  >
                    {t('io.dryRun')}
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => importJsonMutation.mutate(false)}
                    disabled={importJsonMutation.isPending}
                  >
                    <Upload className="h-4 w-4" />
                    {t('io.importJson')}
                  </Button>
                  {importResult ? (
                    <span className="text-xs text-emerald-300">
                      {t('io.importSummary', {
                        received: importResult.received_count,
                        inserted: importResult.inserted_count,
                        skipped: importResult.skipped_duplicates,
                      })}
                    </span>
                  ) : null}
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{t('policies.title')}</CardTitle>
          <CardDescription>{t('policies.subtitle')}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {canManagePolicies ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                createPolicyMutation.mutate();
              }}
              className="grid gap-2 rounded-md border border-border bg-background/40 p-3 sm:grid-cols-4"
            >
              <input
                type="text"
                required
                placeholder={t('policies.namePlaceholder')}
                value={policyName}
                onChange={(e) => setPolicyName(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
              <input
                type="text"
                required
                placeholder={t('policies.portSpecPlaceholder')}
                value={portSpec}
                onChange={(e) => setPortSpec(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
              <select
                value={discoveryTool}
                onChange={(e) => setDiscoveryTool(e.target.value as 'naabu' | 'masscan')}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              >
                <option value="naabu">naabu</option>
                <option value="masscan">masscan</option>
              </select>
              <input
                type="number"
                min={1}
                max={100000}
                value={ratePps}
                onChange={(e) => setRatePps(Number(e.target.value) || 500)}
                placeholder={t('policies.ratePlaceholder')}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                title={t('policies.ratePlaceholder')}
              />
              <input
                type="number"
                min={1}
                max={20}
                value={inactivityK}
                onChange={(e) => setInactivityK(Number(e.target.value) || 3)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                title="K inactivity threshold"
              />
              <input
                type="number"
                min={1}
                max={65535}
                value={tarpitThreshold}
                onChange={(e) => setTarpitThreshold(Number(e.target.value) || 200)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                title="Tarpit Guard threshold"
              />
              <div className="flex items-center gap-1 text-xs">
                <input
                  type="text"
                  value={windowStart}
                  onChange={(e) => setWindowStart(e.target.value)}
                  className="w-20 rounded-md border border-border bg-background px-2 py-2 text-sm font-mono"
                  title={t('policies.windowStartLabel')}
                />
                <span>–</span>
                <input
                  type="text"
                  value={windowEnd}
                  onChange={(e) => setWindowEnd(e.target.value)}
                  className="w-20 rounded-md border border-border bg-background px-2 py-2 text-sm font-mono"
                  title={t('policies.windowEndLabel')}
                />
              </div>
              <div className="flex items-center justify-between gap-2">
                <label className="flex items-center gap-1.5 text-xs">
                  <input
                    type="checkbox"
                    checked={enableNuclei}
                    onChange={(e) => setEnableNuclei(e.target.checked)}
                  />
                  <span>{t('policies.enableNuclei')}</span>
                </label>
                <Button type="submit" size="sm" disabled={createPolicyMutation.isPending}>
                  <Plus className="h-4 w-4" />
                  {t('policies.createBtn')}
                </Button>
              </div>
            </form>
          ) : null}

          <div className="overflow-x-auto rounded-md border border-border">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
                <tr>
                  <th className="px-3 py-2">{t('policies.colName')}</th>
                  <th className="px-3 py-2">{t('policies.colPorts')}</th>
                  <th className="px-3 py-2">{t('policies.colRate')}</th>
                  <th className="px-3 py-2">{t('policies.colThresholds')}</th>
                  <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody>
                {policiesQuery.data?.items.length ? (
                  policiesQuery.data.items.map((p) => (
                    <tr key={p.id} className="border-b border-border/60 last:border-0">
                      <td className="px-3 py-2 font-medium">{p.name}</td>
                      <td className="px-3 py-2 font-mono">{p.port_spec}</td>
                      <td className="px-3 py-2 font-mono">
                        {p.rate_pps} PPS ({p.discovery_tool})
                      </td>
                      <td className="px-3 py-2 font-mono">
                        K={p.inactivity_threshold} · Tarpit&gt;{p.tarpit_port_threshold}
                        {p.enable_nuclei ? ' · nuclei' : ''}
                      </td>
                      <td className="px-3 py-2 text-right">
                        {canManagePolicies ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deletePolicyMutation.mutate(p.id)}
                          >
                            <Trash2 className="h-3.5 w-3.5 text-red-400" />
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={5} className="px-3 py-4 text-center text-muted-foreground">
                      {t('policies.empty')}
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
