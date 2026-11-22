import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Save, Send, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

import {
  apiClient,
  formatApiError,
  type DdFindingPayloadOverride,
  type DdFindingPreviewDto,
} from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

interface DdPayloadModalProps {
  mode: 'diff' | 'host';
  targetId: string;
  onClose: () => void;
  onPushed?: () => void;
}

const SEVERITIES = ['Info', 'Low', 'Medium', 'High', 'Critical'] as const;
const NUMERIC_SEVERITIES = ['S0', 'S1', 'S2', 'S3', 'S4'] as const;

const SEVERITY_TO_NUM: Record<string, string> = {
  Info: 'S0',
  Low: 'S1',
  Medium: 'S2',
  High: 'S3',
  Critical: 'S4',
};

export function DdPayloadModal({ mode, targetId, onClose, onPushed }: DdPayloadModalProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('Medium');
  const [numericalSeverity, setNumericalSeverity] = useState('S2');
  const [componentName, setComponentName] = useState('');
  const [tagsText, setTagsText] = useState('');
  const [description, setDescription] = useState('');
  const [extraNotes, setExtraNotes] = useState('');
  const [mitigation, setMitigation] = useState('');
  const [impact, setImpact] = useState('');
  const [references, setReferences] = useState('');
  const [active, setActive] = useState(true);
  const [verified, setVerified] = useState(false);
  const [falsePositive, setFalsePositive] = useState(false);
  const [outOfScope, setOutOfScope] = useState(false);
  const [customFieldsText, setCustomFieldsText] = useState('{}');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  const previewQuery = useQuery<DdFindingPreviewDto>({
    queryKey: ['dd-preview', mode, targetId],
    queryFn: async () => {
      if (mode === 'diff') {
        const { data, error } = await apiClient.GET(
          '/api/v1/integrations/defectdojo/preview/diff/{diff_event_id}',
          { params: { path: { diff_event_id: targetId } } },
        );
        if (error || !data) {
          throw new Error(formatApiError(error, 'Failed to load DefectDojo preview.'));
        }
        return data;
      }
      const { data, error } = await apiClient.GET(
        '/api/v1/integrations/defectdojo/preview/host/{host_id}',
        { params: { path: { host_id: targetId } } },
      );
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load DefectDojo host preview.'));
      }
      return data;
    },
  });

  useEffect(() => {
    const data = previewQuery.data;
    if (!data) {
      return;
    }
    const eff = data.effective_payload;
    setTitle(eff.title);
    setSeverity(eff.severity);
    setNumericalSeverity(eff.numerical_severity ?? SEVERITY_TO_NUM[eff.severity] ?? 'S0');
    setComponentName(eff.component_name ?? '');
    setTagsText((eff.tags ?? []).join(', '));
    setDescription(data.saved_override?.description ?? data.default_payload.description);
    setExtraNotes(data.saved_override?.extra_notes ?? '');
    setMitigation(eff.mitigation ?? '');
    setImpact(eff.impact ?? '');
    setReferences(eff.references ?? '');
    setActive(eff.active);
    setVerified(eff.verified);
    setFalsePositive(Boolean(eff.false_p));
    setOutOfScope(Boolean(eff.out_of_scope));
    setCustomFieldsText(
      eff.custom_fields && typeof eff.custom_fields === 'object'
        ? JSON.stringify(eff.custom_fields, null, 2)
        : '{}',
    );
  }, [previewQuery.data]);

  const buildOverride = (): DdFindingPayloadOverride => {
    let parsedCustomFields: unknown = undefined;
    const trimmedCustom = customFieldsText.trim();
    if (trimmedCustom && trimmedCustom !== '{}') {
      let decoded: unknown;
      try {
        decoded = JSON.parse(trimmedCustom);
      } catch {
        throw new Error(t('integrations.modal.invalidCustomFields'));
      }
      if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) {
        throw new Error(t('integrations.modal.invalidCustomFields'));
      }
      parsedCustomFields = decoded;
    }

    const tags = tagsText
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    return {
      title: title.trim() || null,
      severity,
      numerical_severity: numericalSeverity,
      component_name: componentName.trim() || null,
      tags,
      description,
      extra_notes: extraNotes.trim() || null,
      mitigation: mitigation.trim() || null,
      impact: impact.trim() || null,
      references: references.trim() || null,
      active,
      verified,
      false_p: falsePositive,
      out_of_scope: outOfScope,
      custom_fields: parsedCustomFields,
    };
  };

  const saveMutation = useMutation({
    mutationFn: async () => {
      const ov = buildOverride();
      if (mode === 'diff') {
        const { data, error } = await apiClient.PUT(
          '/api/v1/integrations/defectdojo/override/diff/{diff_event_id}',
          { params: { path: { diff_event_id: targetId } }, body: ov },
        );
        if (error || !data) {
          throw new Error(formatApiError(error, 'Failed to save payload override.'));
        }
        return data;
      }
      const { data, error } = await apiClient.PUT(
        '/api/v1/integrations/defectdojo/override/host/{host_id}',
        { params: { path: { host_id: targetId } }, body: ov },
      );
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to save host payload override.'));
      }
      return data;
    },
    onSuccess: (updated) => {
      setErrorMsg(null);
      setStatusMsg(t('integrations.modal.overrideSaved'));
      queryClient.setQueryData(['dd-preview', mode, targetId], updated);
      onPushed?.();
    },
    onError: (err) => {
      setStatusMsg(null);
      setErrorMsg(err.message);
    },
  });

  const pushMutation = useMutation({
    mutationFn: async () => {
      const ov = buildOverride();
      if (mode === 'diff') {
        const { data, error } = await apiClient.POST(
          '/api/v1/integrations/defectdojo/push/{diff_event_id}',
          { params: { path: { diff_event_id: targetId } }, body: ov },
        );
        if (error || !data) {
          throw new Error(formatApiError(error, 'Failed to push diff to DefectDojo.'));
        }
        return t('integrations.modal.pushedDiffOk', { note: data.note });
      }
      const { data, error } = await apiClient.POST(
        '/api/v1/integrations/defectdojo/push-host/{host_id}',
        { params: { path: { host_id: targetId } }, body: ov },
      );
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to push host to DefectDojo.'));
      }
      return t('integrations.modal.pushedOk', { id: data.dd_finding_id });
    },
    onSuccess: (message) => {
      setErrorMsg(null);
      setStatusMsg(message);
      void queryClient.invalidateQueries({
        queryKey: [mode === 'diff' ? 'dd-link' : 'dd-host-link', targetId],
      });
      void queryClient.invalidateQueries({ queryKey: ['dd-outbox'] });
      void previewQuery.refetch();
      onPushed?.();
    },
    onError: (err) => {
      setStatusMsg(null);
      setErrorMsg(err.message);
    },
  });

  const wirePreview = (() => {
    const base = previewQuery.data?.effective_payload;
    if (!base) {
      return null;
    }
    let parsedCustom: Record<string, unknown> | undefined;
    try {
      const parsed: unknown = JSON.parse(customFieldsText.trim() || '{}');
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        parsedCustom = parsed as Record<string, unknown>;
      }
    } catch {
      parsedCustom = undefined;
    }
    return {
      ...base,
      title,
      severity,
      numerical_severity: numericalSeverity,
      component_name: componentName.trim() || null,
      tags: tagsText
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0),
      description: extraNotes.trim() ? `${description}\n\n[Notatka analityka]:\n${extraNotes}` : description,
      mitigation: mitigation.trim() || null,
      impact: impact.trim() || null,
      references: references.trim() || null,
      active,
      verified,
      false_p: falsePositive,
      out_of_scope: outOfScope,
      ...(parsedCustom ?? {}),
    };
  })();

  const inputCls =
    'w-full rounded-md border border-border bg-background px-3 py-2 text-xs focus:outline-none focus:ring-1 focus:ring-primary';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <div className="flex max-h-[90vh] w-full max-w-4xl flex-col rounded-lg border border-border bg-card text-card-foreground shadow-xl">
        <div className="flex items-center justify-between border-b border-border px-5 py-4">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold">
              {mode === 'diff' ? t('integrations.modal.diffTitle') : t('integrations.modal.hostTitle')}
            </h2>
            {previewQuery.data ? (
              <>
                <Badge variant="outline" className="font-mono">
                  {previewQuery.data.ip_addr}
                </Badge>
                <Badge variant="default">{previewQuery.data.asset_group_name}</Badge>
              </>
            ) : null}
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {errorMsg ? (
            <div className="rounded-md border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">
              {errorMsg}
            </div>
          ) : null}
          {statusMsg ? (
            <div className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-2 text-xs text-emerald-300">
              {statusMsg}
            </div>
          ) : null}

          {previewQuery.isLoading ? (
            <div className="py-10 text-center text-sm text-muted-foreground">
              {t('common.loading')}
            </div>
          ) : previewQuery.isError ? (
            <div className="rounded-md border border-red-800 bg-red-950/40 p-4 text-sm text-red-300">
              {previewQuery.error.message}
            </div>
          ) : (
            <div className="grid gap-4 lg:grid-cols-2">
              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">
                    {t('integrations.modal.fieldTitle')}
                  </label>
                  <input
                    type="text"
                    className={inputCls}
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                  />
                </div>

                <div className="grid grid-cols-3 gap-2">
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      {t('integrations.modal.fieldSeverity')}
                    </label>
                    <select
                      className={inputCls}
                      value={severity}
                      onChange={(e) => {
                        const nextSev = e.target.value;
                        setSeverity(nextSev);
                        setNumericalSeverity(SEVERITY_TO_NUM[nextSev] ?? 'S0');
                      }}
                    >
                      {SEVERITIES.map((s) => (
                        <option key={s} value={s}>
                          {s}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      {t('integrations.modal.fieldNumSeverity')}
                    </label>
                    <select
                      className={inputCls}
                      value={numericalSeverity}
                      onChange={(e) => setNumericalSeverity(e.target.value)}
                    >
                      {NUMERIC_SEVERITIES.map((ns) => (
                        <option key={ns} value={ns}>
                          {ns}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      {t('integrations.modal.fieldComponent')}
                    </label>
                    <input
                      type="text"
                      className={inputCls}
                      value={componentName}
                      onChange={(e) => setComponentName(e.target.value)}
                    />
                  </div>
                </div>

                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">
                    {t('integrations.modal.fieldTags')}
                  </label>
                  <input
                    type="text"
                    className={inputCls}
                    value={tagsText}
                    onChange={(e) => setTagsText(e.target.value)}
                    placeholder="asi, critical, staging"
                  />
                </div>

                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">
                    {t('integrations.modal.fieldReferences')}
                  </label>
                  <input
                    type="text"
                    className={inputCls}
                    value={references}
                    onChange={(e) => setReferences(e.target.value)}
                  />
                </div>

                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">
                    {t('integrations.modal.fieldDescription')}
                  </label>
                  <textarea
                    rows={4}
                    className={`${inputCls} font-mono`}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>

                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">
                    {t('integrations.modal.fieldExtraNotes')}
                  </label>
                  <textarea
                    rows={2}
                    className={inputCls}
                    value={extraNotes}
                    onChange={(e) => setExtraNotes(e.target.value)}
                    placeholder={t('integrations.modal.extraNotesPlaceholder')}
                  />
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      {t('integrations.modal.fieldMitigation')}
                    </label>
                    <textarea
                      rows={2}
                      className={inputCls}
                      value={mitigation}
                      onChange={(e) => setMitigation(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-xs text-muted-foreground">
                      {t('integrations.modal.fieldImpact')}
                    </label>
                    <textarea
                      rows={2}
                      className={inputCls}
                      value={impact}
                      onChange={(e) => setImpact(e.target.value)}
                    />
                  </div>
                </div>

                <div className="flex flex-wrap gap-4 pt-1 text-xs">
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={active}
                      onChange={(e) => setActive(e.target.checked)}
                    />
                    active
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={verified}
                      onChange={(e) => setVerified(e.target.checked)}
                    />
                    verified
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={falsePositive}
                      onChange={(e) => setFalsePositive(e.target.checked)}
                    />
                    false_p
                  </label>
                  <label className="flex items-center gap-1.5">
                    <input
                      type="checkbox"
                      checked={outOfScope}
                      onChange={(e) => setOutOfScope(e.target.checked)}
                    />
                    out_of_scope
                  </label>
                </div>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">
                    {t('integrations.modal.fieldCustomJson')}
                  </label>
                  <textarea
                    rows={5}
                    className={`${inputCls} font-mono`}
                    value={customFieldsText}
                    onChange={(e) => setCustomFieldsText(e.target.value)}
                    placeholder='{"sla_days": 7, "team": "SOC"}'
                  />
                </div>

                <div>
                  <label className="mb-1 block text-xs text-muted-foreground">
                    {t('integrations.modal.wirePreview')}
                  </label>
                  <pre className="max-h-72 overflow-auto rounded-md border border-border bg-background/80 p-3 font-mono text-[11px] text-muted-foreground">
                    {JSON.stringify(wirePreview, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-5 py-3">
          <Button variant="outline" size="sm" onClick={onClose}>
            {t('integrations.modal.close')}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending || previewQuery.isLoading}
          >
            <Save className="h-4 w-4" />
            {t('integrations.modal.saveOverride')}
          </Button>
          <Button
            size="sm"
            onClick={() => pushMutation.mutate()}
            disabled={pushMutation.isPending || previewQuery.isLoading}
          >
            <Send className="h-4 w-4" />
            {t('integrations.modal.pushNow')}
          </Button>
        </div>
      </div>
    </div>
  );
}
