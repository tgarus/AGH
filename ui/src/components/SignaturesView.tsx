import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { CheckCircle2, Plus, RefreshCw, Trash2, Upload } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  formatApiError,
  type SignatureRuleDto,
  type ValidateSignatureResponse,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

const DEFAULT_SAMPLE_YAML = `id: custom-agh-portal
info:
  name: AGH Custom Web Portal
  author: asi-analyst
  severity: info
  tags: custom,web
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: regex
        part: title
        regex:
          - "(?i)AGH"
`;

export function SignaturesView() {
  const { t } = useTranslation();
  const { hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [searchText, setSearchText] = useState('');
  const [selectedRule, setSelectedRule] = useState<SignatureRuleDto | null>(null);
  const [yamlDraft, setYamlDraft] = useState(DEFAULT_SAMPLE_YAML);
  const [validationResult, setValidationResult] = useState<ValidateSignatureResponse | null>(null);
  const [bulkJson, setBulkJson] = useState(
    JSON.stringify({ schema_version: '1.0', dry_run: false, items: [DEFAULT_SAMPLE_YAML] }, null, 2),
  );
  const [feedback, setFeedback] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const signaturesQuery = useQuery({
    queryKey: ['signatures', searchText],
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/signatures', {
        params: {
          query: {
            page: 1,
            per_page: 100,
            q: searchText.trim() || null,
          },
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load signatures.'));
      }
      return data;
    },
  });

  const validateMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/signatures/validate', {
        body: { yaml_content: yamlDraft },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'YAML validation request failed.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setErrorMsg(null);
      setValidationResult(res);
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const createMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/signatures', {
        body: { yaml_content: yamlDraft, is_enabled: true },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to create signature.'));
      }
      return data;
    },
    onSuccess: (created) => {
      setErrorMsg(null);
      setFeedback(`Created signature '${created.template_id}'`);
      void queryClient.invalidateQueries({ queryKey: ['signatures'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const toggleMutation = useMutation({
    mutationFn: async (rule: SignatureRuleDto) => {
      const { data, error } = await apiClient.PATCH('/api/v1/signatures/{id}', {
        params: { path: { id: rule.id } },
        body: { is_enabled: !rule.is_enabled },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to update signature.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['signatures'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await apiClient.DELETE('/api/v1/signatures/{id}', {
        params: { path: { id } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to delete signature.'));
      }
    },
    onSuccess: () => {
      setErrorMsg(null);
      setSelectedRule(null);
      void queryClient.invalidateQueries({ queryKey: ['signatures'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const syncMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/signatures/sync');
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to sync built-in signatures.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setErrorMsg(null);
      setFeedback(
        t('signatures.syncedNotice', {
          count: res.synced_count,
          builtin: res.builtin_count ?? 0,
          repo: res.repo_count ?? 0,
          skipped: res.skipped_count ?? 0,
          source: res.source ?? '',
          repoError: res.repo_error ?? '—',
        }),
      );
      void queryClient.invalidateQueries({ queryKey: ['signatures'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const importJsonMutation = useMutation({
    mutationFn: async (dryRun: boolean) => {
      let parsed: { schema_version?: string; items?: string[] };
      try {
        parsed = JSON.parse(bulkJson) as typeof parsed;
      } catch {
        throw new Error(t('io.invalidJson'));
      }
      const { data, error } = await apiClient.POST('/api/v1/import/signatures', {
        body: {
          schema_version: parsed.schema_version ?? '1.0',
          dry_run: dryRun,
          items: parsed.items ?? [],
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'JSON signature import failed.'));
      }
      return data;
    },
    onSuccess: (res) => {
      setErrorMsg(null);
      setFeedback(
        t('signatures.importSummary', {
          received: res.received_count,
          upserted: res.upserted_count,
        }),
      );
      if (!res.dry_run) {
        void queryClient.invalidateQueries({ queryKey: ['signatures'] });
      }
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const canManage = hasPermission('manage_custom_signatures');
  const canSync = hasPermission('sync_fingerprint_hub');
  const canImport = hasPermission('import_data') && canManage;

  const handleCreate = (e: FormEvent) => {
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
      {feedback ? (
        <div className="rounded-md border border-emerald-800 bg-emerald-950/40 px-4 py-3 text-sm text-emerald-300">
          {feedback}
        </div>
      ) : null}

      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle>{t('signatures.title')}</CardTitle>
              <CardDescription>{t('signatures.subtitle')}</CardDescription>
            </div>
            <div className="flex gap-2">
              {canSync ? (
                <Button
                  size="sm"
                  onClick={() => syncMutation.mutate()}
                  disabled={syncMutation.isPending}
                >
                  <RefreshCw className="h-4 w-4" />
                  {t('signatures.syncBtn')}
                </Button>
              ) : null}
              <Button variant="outline" size="sm" onClick={() => void signaturesQuery.refetch()}>
                {t('health.refresh')}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <input
            type="text"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder={t('signatures.searchPlaceholder')}
            className="w-full max-w-md rounded-md border border-border bg-background px-3 py-2 text-sm"
          />

          <div className="grid gap-6 lg:grid-cols-2">
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2">{t('signatures.colTemplate')}</th>
                    <th className="px-3 py-2">{t('signatures.colSource')}</th>
                    <th className="px-3 py-2">{t('admin.status')}</th>
                    <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {signaturesQuery.data?.items.length ? (
                    signaturesQuery.data.items.map((rule) => (
                      <tr
                        key={rule.id}
                        onClick={() => {
                          setSelectedRule(rule);
                          setYamlDraft(rule.yaml_content);
                          setValidationResult(null);
                        }}
                        className={`cursor-pointer border-b border-border/60 last:border-0 hover:bg-secondary/40 ${
                          selectedRule?.id === rule.id ? 'bg-secondary' : ''
                        }`}
                      >
                        <td className="px-3 py-2">
                          <div className="font-mono font-semibold">{rule.template_id}</div>
                          <div className="text-muted-foreground">{rule.name}</div>
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={rule.source === 'fingerprinthub' ? 'default' : 'outline'}>
                            {rule.source}
                          </Badge>
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={rule.is_enabled ? 'success' : 'outline'}>
                            {rule.is_enabled ? t('admin.active') : t('admin.inactive')}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-right" onClick={(e) => e.stopPropagation()}>
                          {canManage ? (
                            <div className="inline-flex gap-1">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => toggleMutation.mutate(rule)}
                              >
                                {rule.is_enabled ? t('signatures.disable') : t('signatures.enable')}
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                onClick={() => deleteMutation.mutate(rule.id)}
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
                        {t('signatures.empty')}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <form onSubmit={handleCreate} className="space-y-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                {t('signatures.editorTitle')}
              </div>
              <textarea
                rows={14}
                value={yamlDraft}
                onChange={(e) => setYamlDraft(e.target.value)}
                className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs"
              />
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => validateMutation.mutate()}
                  disabled={validateMutation.isPending}
                >
                  <CheckCircle2 className="h-4 w-4" />
                  {t('signatures.validateBtn')}
                </Button>
                {canManage ? (
                  <Button type="submit" size="sm" disabled={createMutation.isPending}>
                    <Plus className="h-4 w-4" />
                    {t('signatures.saveNewBtn')}
                  </Button>
                ) : null}
              </div>

              {validationResult ? (
                <div
                  className={`rounded-md border p-3 text-xs ${
                    validationResult.valid
                      ? 'border-emerald-800 bg-emerald-950/40 text-emerald-300'
                      : 'border-red-800 bg-red-950/40 text-red-300'
                  }`}
                >
                  {validationResult.valid
                    ? `${validationResult.template_id} — ${validationResult.name} [${validationResult.tags.join(', ')}]`
                    : validationResult.error}
                </div>
              ) : null}
            </form>
          </div>

          {canImport ? (
            <div className="space-y-3 border-t border-border pt-4">
              <div className="text-sm font-semibold">{t('signatures.importJsonTitle')}</div>
              <textarea
                rows={4}
                value={bulkJson}
                onChange={(e) => setBulkJson(e.target.value)}
                className="w-full rounded-md border border-border bg-background p-3 font-mono text-xs"
              />
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => importJsonMutation.mutate(true)}
                >
                  {t('io.dryRun')}
                </Button>
                <Button size="sm" onClick={() => importJsonMutation.mutate(false)}>
                  <Upload className="h-4 w-4" />
                  {t('io.importJson')}
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
