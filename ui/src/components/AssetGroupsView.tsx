import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, Download, Plus, Save, SlidersHorizontal, Trash2, Upload, Users } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  downloadAuthorizedFile,
  formatApiError,
  type ImportScanResultsResponse,
  type ImportTargetsFlexibleResponse,
  type TargetType,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { paginateItems, TablePagination } from '@/components/ui/pagination';
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
    '# Wklej IP, CIDR, domeny, !exclude, CSV lub JSON\n172.28.0.0/24\napp.lab.local',
  );
  const [importFormat, setImportFormat] = useState<'auto' | 'raw' | 'csv' | 'json'>('auto');
  const [startScanAfterImport, setStartScanAfterImport] = useState(false);
  const [importResult, setImportResult] = useState<ImportTargetsFlexibleResponse | null>(null);
  const targetsFileRef = useRef<HTMLInputElement>(null);

  const [scanResultsFormat, setScanResultsFormat] = useState<'auto' | 'csv' | 'json'>('auto');
  const [scanResultsContent, setScanResultsContent] = useState(
    'ip_addr,port,protocol,service_name,vhost,http_status,title,technologies\n172.28.0.10,443,tcp,https,portal.lab.local,200,Admin Portal,nginx;react',
  );
  const [scanResultsSummary, setScanResultsSummary] = useState<ImportScanResultsResponse | null>(
    null,
  );
  const scanResultsFileRef = useRef<HTMLInputElement>(null);
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

  const [selectedMemberIds, setSelectedMemberIds] = useState<string[]>([]);
  const [editGroupName, setEditGroupName] = useState('');
  const [editGroupDesc, setEditGroupDesc] = useState('');
  const [editGroupPolicyId, setEditGroupPolicyId] = useState('');
  const [editSamplingEnabled, setEditSamplingEnabled] = useState(true);
  const [settingsSavedMsg, setSettingsSavedMsg] = useState(false);
  const [targetsPage, setTargetsPage] = useState(1);
  const [targetsPerPage, setTargetsPerPage] = useState(10);
  const [policiesPage, setPoliciesPage] = useState(1);
  const [policiesPerPage, setPoliciesPerPage] = useState(10);

  const usersDirectoryQuery = useQuery({
    queryKey: ['users-directory'],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/users/directory');
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load user directory.'));
      }
      return data;
    },
  });

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

  const adminUserIds = (usersDirectoryQuery.data ?? [])
    .filter((u) => u.role === 'Admin')
    .map((u) => u.id);
  const adminIdSet = new Set(adminUserIds);

  const detailGroup = detailQuery.data?.group;
  const detailMembers = detailQuery.data?.members;

  useEffect(() => {
    setSettingsSavedMsg(false);
    if (detailGroup) {
      setEditGroupName(detailGroup.name);
      setEditGroupDesc(detailGroup.description ?? '');
      setEditGroupPolicyId(detailGroup.policy_id);
      setEditSamplingEnabled(detailGroup.sampling_enabled);
    }
    setSelectedMemberIds((detailMembers ?? []).map((m) => m.user_id));
  }, [detailGroup, detailMembers]);

  const originalNonAdminMembers = (detailQuery.data?.members ?? [])
    .map((m) => m.user_id)
    .filter((id) => !adminIdSet.has(id))
    .sort();
  const draftNonAdminMembers = selectedMemberIds.filter((id) => !adminIdSet.has(id)).sort();
  const membersChanged =
    Boolean(detailQuery.data) &&
    JSON.stringify(originalNonAdminMembers) !== JSON.stringify(draftNonAdminMembers);
  const groupMetaChanged = Boolean(
    detailQuery.data &&
      (editGroupName.trim() !== detailQuery.data.group.name ||
        editGroupDesc.trim() !== (detailQuery.data.group.description ?? '').trim() ||
        editGroupPolicyId !== detailQuery.data.group.policy_id ||
        editSamplingEnabled !== detailQuery.data.group.sampling_enabled),
  );
  const hasUnsavedChanges = Boolean(
    activeGroupId && detailQuery.data && (groupMetaChanged || membersChanged),
  );

  const saveAllGroupSettingsMutation = useMutation({
    mutationFn: async () => {
      if (!activeGroupId) {
        throw new Error('Select a group first.');
      }
      if (groupMetaChanged) {
        const trimmedName = editGroupName.trim();
        if (!trimmedName) {
          throw new Error('Group name cannot be empty.');
        }
        const { data, error } = await apiClient.PATCH('/api/v1/asset-groups/{id}', {
          params: { path: { id: activeGroupId } },
          body: {
            name: trimmedName,
            description: editGroupDesc.trim(),
            policy_id: editGroupPolicyId || undefined,
            sampling_enabled: editSamplingEnabled,
          },
        });
        if (error || !data) {
          throw new Error(formatApiError(error, 'Failed to update asset group settings.'));
        }
      }
      if (membersChanged) {
        const finalUserIds = Array.from(
          new Set([...selectedMemberIds.filter((id) => !adminIdSet.has(id)), ...adminUserIds]),
        );
        const { data, error } = await apiClient.PUT('/api/v1/asset-groups/{id}/members', {
          params: { path: { id: activeGroupId } },
          body: { user_ids: finalUserIds },
        });
        if (error || !data) {
          throw new Error(formatApiError(error, 'Failed to update asset group members.'));
        }
      }
    },
    onSuccess: () => {
      setFeedbackError(null);
      setSettingsSavedMsg(true);
      void queryClient.invalidateQueries({ queryKey: ['asset-groups'] });
      void queryClient.invalidateQueries({ queryKey: ['asset-group-detail', activeGroupId] });
      void queryClient.invalidateQueries({ queryKey: ['scans'] });
    },
    onError: (err) => setFeedbackError(err.message),
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

  const importFlexibleMutation = useMutation({
    mutationFn: async (dryRun: boolean) => {
      if (!activeGroupId) {
        throw new Error('Select an asset group before importing targets.');
      }
      const { data, error } = await apiClient.POST('/api/v1/import/targets-flexible', {
        body: {
          asset_group_id: activeGroupId,
          format: importFormat,
          content: jsonInput,
          dry_run: dryRun,
          start_scan: dryRun ? false : startScanAfterImport,
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Flexible target import failed.'));
      }
      return data;
    },
    onSuccess: (summary) => {
      setFeedbackError(null);
      setImportResult(summary);
      if (!summary.dry_run) {
        void queryClient.invalidateQueries({ queryKey: ['asset-groups'] });
        void queryClient.invalidateQueries({ queryKey: ['asset-group-detail', activeGroupId] });
        if (summary.started_scan_run_id) {
          void queryClient.invalidateQueries({ queryKey: ['scans'] });
        }
      }
    },
    onError: (err) => setFeedbackError(err.message),
  });

  const importScanResultsMutation = useMutation({
    mutationFn: async () => {
      if (!activeGroupId) {
        throw new Error('Select an asset group before importing scan results.');
      }
      const { data, error } = await apiClient.POST('/api/v1/import/scan-results', {
        body: {
          asset_group_id: activeGroupId,
          format: scanResultsFormat,
          content: scanResultsContent,
          items: [],
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Scan results import failed.'));
      }
      return data;
    },
    onSuccess: (summary) => {
      setFeedbackError(null);
      setScanResultsSummary(summary);
      void queryClient.invalidateQueries({ queryKey: ['hosts'] });
      void queryClient.invalidateQueries({ queryKey: ['diffs'] });
      void queryClient.invalidateQueries({ queryKey: ['services'] });
      void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
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

  const pagedTargets = paginateItems(detailQuery.data?.targets ?? [], targetsPage, targetsPerPage);
  const pagedPolicies = paginateItems(
    policiesQuery.data?.items ?? [],
    policiesPage,
    policiesPerPage,
  );

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
                    onClick={() => {
                      setSelectedGroupId(grp.id);
                      setTargetsPage(1);
                      setSettingsSavedMsg(false);
                    }}
                    className={`flex w-full items-center justify-between rounded-md border px-3 py-2 text-left text-sm transition-colors ${
                      activeGroupId === grp.id
                        ? 'border-primary bg-secondary text-foreground'
                        : 'border-border bg-background/40 text-muted-foreground hover:bg-secondary/50'
                    }`}
                  >
                    <span className="font-medium">{grp.name}</span>
                    <div className="flex items-center gap-1.5">
                      {(grp.assigned_user_ids?.length ?? 0) > 0 ? (
                        <Badge variant="default" title={t('assetGroups.membersTitle')}>
                          <Users className="mr-1 h-3 w-3" />
                          {grp.assigned_user_ids?.length}
                        </Badge>
                      ) : null}
                      <Badge variant="outline">{grp.target_count}</Badge>
                    </div>
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
                <div className="flex flex-wrap gap-2">
                  <Button variant="outline" size="sm" onClick={() => void handleExportJson()}>
                    <Download className="h-4 w-4" />
                    {t('io.exportJson')}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() =>
                      void downloadAuthorizedFile(
                        activeGroupId
                          ? `/api/v1/export/targets.csv?asset_group_id=${activeGroupId}`
                          : '/api/v1/export/targets.csv',
                        `asi-targets-${activeGroupId ?? 'all'}.csv`,
                      ).catch((err: Error) => setFeedbackError(err.message))
                    }
                  >
                    <Download className="h-4 w-4" />
                    {t('io.exportCsv')}
                  </Button>
                </div>
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
                  {pagedTargets.items.length ? (
                    pagedTargets.items.map((tgt) => (
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
            <TablePagination
              page={pagedTargets.safePage}
              perPage={targetsPerPage}
              totalItems={pagedTargets.totalItems}
              onPageChange={setTargetsPage}
              onPerPageChange={(n) => {
                setTargetsPerPage(n);
                setTargetsPage(1);
              }}
            />

            {activeGroupId && canImport ? (
              <>
                <div className="space-y-3 border-t border-border pt-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-sm font-semibold">{t('io.importFlexibleTitle')}</div>
                    <div className="flex items-center gap-2">
                      <select
                        value={importFormat}
                        onChange={(e) =>
                          setImportFormat(e.target.value as 'auto' | 'raw' | 'csv' | 'json')
                        }
                        className="rounded-md border border-border bg-background px-2 py-1 text-xs"
                      >
                        <option value="auto">auto</option>
                        <option value="raw">raw (IP/CIDR/domain)</option>
                        <option value="csv">CSV</option>
                        <option value="json">JSON</option>
                      </select>
                      <input
                        ref={targetsFileRef}
                        type="file"
                        accept=".txt,.csv,.json"
                        className="hidden"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) {
                            void file.text().then((txt) => setJsonInput(txt));
                          }
                          e.target.value = '';
                        }}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => targetsFileRef.current?.click()}
                      >
                        <Upload className="h-3.5 w-3.5" />
                        {t('io.loadFile')}
                      </Button>
                    </div>
                  </div>
                  <textarea
                    rows={5}
                    value={jsonInput}
                    onChange={(e) => setJsonInput(e.target.value)}
                    className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs"
                  />
                  <div className="flex flex-wrap items-center gap-3">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => importFlexibleMutation.mutate(true)}
                      disabled={importFlexibleMutation.isPending}
                    >
                      {t('io.dryRun')}
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => importFlexibleMutation.mutate(false)}
                      disabled={importFlexibleMutation.isPending}
                    >
                      <Upload className="h-4 w-4" />
                      {t('io.importBtn')}
                    </Button>
                    <label className="flex items-center gap-1.5 text-xs">
                      <input
                        type="checkbox"
                        checked={startScanAfterImport}
                        onChange={(e) => setStartScanAfterImport(e.target.checked)}
                      />
                      {t('io.startScanAfterImport')}
                    </label>
                    {importResult ? (
                      <div className="flex flex-wrap items-center gap-2 text-xs text-emerald-300">
                        <span>
                          {t('io.importSummary', {
                            received: importResult.received_count,
                            inserted: importResult.inserted_count,
                            skipped: importResult.skipped_duplicates,
                          })}
                        </span>
                        {Object.entries(importResult.detected_summary).map(([kind, cnt]) => (
                          <Badge key={kind} variant="outline" className="text-[10px]">
                            {kind}: {cnt}
                          </Badge>
                        ))}
                        {importResult.started_scan_run_id ? (
                          <Badge variant="success" className="text-[10px]">
                            scan #{importResult.started_scan_run_id.slice(0, 8)}
                          </Badge>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                </div>

                <div className="space-y-3 border-t border-border pt-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="text-sm font-semibold">{t('io.importResultsTitle')}</div>
                    <div className="flex items-center gap-2">
                      <select
                        value={scanResultsFormat}
                        onChange={(e) =>
                          setScanResultsFormat(e.target.value as 'auto' | 'csv' | 'json')
                        }
                        className="rounded-md border border-border bg-background px-2 py-1 text-xs"
                      >
                        <option value="auto">auto</option>
                        <option value="csv">CSV</option>
                        <option value="json">JSON</option>
                      </select>
                      <input
                        ref={scanResultsFileRef}
                        type="file"
                        accept=".csv,.json"
                        className="hidden"
                        onChange={(e) => {
                          const file = e.target.files?.[0];
                          if (file) {
                            void file.text().then((txt) => setScanResultsContent(txt));
                          }
                          e.target.value = '';
                        }}
                      />
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        onClick={() => scanResultsFileRef.current?.click()}
                      >
                        <Upload className="h-3.5 w-3.5" />
                        {t('io.loadFile')}
                      </Button>
                    </div>
                  </div>
                  <textarea
                    rows={4}
                    value={scanResultsContent}
                    onChange={(e) => setScanResultsContent(e.target.value)}
                    className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs"
                  />
                  <div className="flex flex-wrap items-center gap-3">
                    <Button
                      size="sm"
                      onClick={() => importScanResultsMutation.mutate()}
                      disabled={importScanResultsMutation.isPending}
                    >
                      <Upload className="h-4 w-4" />
                      {t('io.importResultsBtn')}
                    </Button>
                    {scanResultsSummary ? (
                      <span className="text-xs text-emerald-300">
                        {t('io.importResultsSummary', {
                          hosts: scanResultsSummary.hosts_upserted,
                          ports: scanResultsSummary.ports_upserted,
                          web: scanResultsSummary.web_observations_upserted,
                          diffs: scanResultsSummary.diff_events_created,
                        })}
                      </span>
                    ) : null}
                  </div>
                </div>
              </>
            ) : null}

            {activeGroupId && detailQuery.data ? (
              <div className="space-y-4 border-t border-border pt-4">
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-sm font-semibold">
                    <SlidersHorizontal className="h-4 w-4 text-primary" />
                    {t('assetGroups.settingsTitle')}
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2">
                    <label className="space-y-1 text-xs">
                      <span className="text-muted-foreground">{t('assetGroups.nameLabel')}</span>
                      <input
                        type="text"
                        disabled={!canManageGroups}
                        value={editGroupName}
                        onChange={(e) => {
                          setSettingsSavedMsg(false);
                          setEditGroupName(e.target.value);
                        }}
                        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm disabled:opacity-60"
                      />
                    </label>
                    <label className="space-y-1 text-xs">
                      <span className="text-muted-foreground">
                        {t('assetGroups.policySelectLabel')}
                      </span>
                      <select
                        disabled={!canManageGroups}
                        value={editGroupPolicyId}
                        onChange={(e) => {
                          setSettingsSavedMsg(false);
                          setEditGroupPolicyId(e.target.value);
                        }}
                        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm disabled:opacity-60"
                      >
                        {(policiesQuery.data?.items ?? []).map((p) => (
                          <option key={p.id} value={p.id}>
                            {p.name} ({p.port_spec})
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="space-y-1 text-xs sm:col-span-2">
                      <span className="text-muted-foreground">{t('assetGroups.descLabel')}</span>
                      <input
                        type="text"
                        disabled={!canManageGroups}
                        value={editGroupDesc}
                        onChange={(e) => {
                          setSettingsSavedMsg(false);
                          setEditGroupDesc(e.target.value);
                        }}
                        placeholder={t('assetGroups.descPlaceholder')}
                        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm disabled:opacity-60"
                      />
                    </label>
                    <label className="flex cursor-pointer items-center gap-2 text-xs sm:col-span-2">
                      <input
                        type="checkbox"
                        disabled={!canManageGroups}
                        checked={editSamplingEnabled}
                        onChange={(e) => {
                          setSettingsSavedMsg(false);
                          setEditSamplingEnabled(e.target.checked);
                        }}
                      />
                      <span>{t('assetGroups.samplingEnabledLabel')}</span>
                    </label>
                  </div>
                </div>

                <div className="space-y-3 border-t border-border/60 pt-4">
                  <div>
                    <div className="flex items-center gap-2 text-sm font-semibold">
                      <Users className="h-4 w-4 text-primary" />
                      {t('assetGroups.membersTitle')}
                    </div>
                    <p className="text-xs text-muted-foreground">{t('assetGroups.membersSubtitle')}</p>
                    <p className="mt-0.5 text-[11px] text-primary/90">
                      {t('assetGroups.adminAlwaysAccess')}
                    </p>
                  </div>

                  {detailQuery.data.members?.length ? (
                    <div className="flex flex-wrap gap-1.5">
                      {detailQuery.data.members.map((m) => (
                        <Badge key={m.user_id} variant="default">
                          {m.username} ({m.role})
                        </Badge>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      {t('assetGroups.membersAllFallback')}
                    </p>
                  )}

                  {canManageGroups && (usersDirectoryQuery.data?.length ?? 0) > 0 ? (
                    <div className="flex flex-wrap gap-2 rounded-md border border-border bg-background/50 p-3 text-xs">
                      {usersDirectoryQuery.data?.map((u) => {
                        const isAdmin = u.role === 'Admin';
                        const checked = isAdmin || selectedMemberIds.includes(u.id);
                        return (
                          <label
                            key={u.id}
                            className={
                              isAdmin
                                ? 'flex cursor-not-allowed items-center gap-1.5 rounded border border-primary bg-primary/50 px-2.5 py-1.5 text-foreground'
                                : 'flex cursor-pointer items-center gap-1.5 rounded border border-border px-2.5 py-1.5 hover:bg-secondary/50'
                            }
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={isAdmin}
                              onChange={(e) => {
                                if (isAdmin) return;
                                setSettingsSavedMsg(false);
                                setSelectedMemberIds((prev) =>
                                  e.target.checked
                                    ? [...prev, u.id]
                                    : prev.filter((id) => id !== u.id),
                                );
                              }}
                            />
                            <span className="font-medium">{u.username}</span>
                            <span className="text-muted-foreground">({u.role})</span>
                          </label>
                        );
                      })}
                    </div>
                  ) : null}
                </div>

                {canManageGroups ? (
                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border bg-secondary/20 px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      {hasUnsavedChanges ? (
                        <Badge variant="warning">{t('assetGroups.unsavedChangesDetected')}</Badge>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-muted-foreground">
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                          {t('assetGroups.allSettingsSaved')}
                        </span>
                      )}
                      {settingsSavedMsg ? (
                        <span className="text-emerald-300">
                          {t('assetGroups.allSettingsSavedToast')}
                        </span>
                      ) : null}
                    </div>
                    <Button
                      type="button"
                      size="sm"
                      onClick={() => saveAllGroupSettingsMutation.mutate()}
                      disabled={!hasUnsavedChanges || saveAllGroupSettingsMutation.isPending}
                    >
                      <Save className="h-4 w-4" />
                      {t('assetGroups.saveAllSettings')}
                    </Button>
                  </div>
                ) : null}
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
                {pagedPolicies.items.length ? (
                  pagedPolicies.items.map((p) => (
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
          <TablePagination
            page={pagedPolicies.safePage}
            perPage={policiesPerPage}
            totalItems={pagedPolicies.totalItems}
            onPageChange={setPoliciesPage}
            onPerPageChange={(n) => {
              setPoliciesPerPage(n);
              setPoliciesPage(1);
            }}
          />
        </CardContent>
      </Card>
    </div>
  );
}
