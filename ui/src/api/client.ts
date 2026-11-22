import createClient, { type Middleware } from 'openapi-fetch';

import type { components, paths } from './schema';

export type ApiProblem = components['schemas']['ProblemDetails'];
export type AuthUser = components['schemas']['AuthUser'];
export type Role = components['schemas']['Role'];
export type Permission = components['schemas']['Permission'];
export type AssetGroupDto = components['schemas']['AssetGroupDto'];
export type AssetGroupDetailDto = components['schemas']['AssetGroupDetailDto'];
export type AssetGroupMemberDto = components['schemas']['AssetGroupMemberDto'];
export type SetAssetGroupMembersRequest = components['schemas']['SetAssetGroupMembersRequest'];
export type ScanPolicyDto = components['schemas']['ScanPolicyDto'];
export type TargetType = components['schemas']['TargetType'];
export type IgnoredTargetDto = components['schemas']['IgnoredTargetDto'];
export type IgnoredTargetType = components['schemas']['IgnoredTargetType'];
export type UserSummary = components['schemas']['UserSummary'];
export type WorkerNodeDto = components['schemas']['WorkerNodeDto'];
export type CreateWorkerTokenResponse = components['schemas']['CreateWorkerTokenResponse'];
export type AuditLogDto = components['schemas']['AuditLogDto'];
export type ImportTargetsJsonResponse = components['schemas']['ImportTargetsJsonResponse'];
export type PreflightResponse = components['schemas']['PreflightResponse'];
export type ScanRunDto = components['schemas']['ScanRunDto'];
export type ScanChunkDto = components['schemas']['ScanChunkDto'];
export type ScanChunkDetailDto = components['schemas']['ScanChunkDetailDto'];
export type ScanHostSampleDto = components['schemas']['ScanHostSampleDto'];
export type ScanExplorationDto = components['schemas']['ScanExplorationDto'];
export type RecurringScanScheduleDto = components['schemas']['RecurringScanScheduleDto'];
export type UpdateRecurringScanRequest = components['schemas']['UpdateRecurringScanRequest'];
export type HostSummaryDto = components['schemas']['HostSummaryDto'];
export type HostDetailDto = components['schemas']['HostDetailDto'];
export type HostPortDto = components['schemas']['HostPortDto'];
export type HostCommentDto = components['schemas']['HostCommentDto'];
export type CreateHostCommentRequest = components['schemas']['CreateHostCommentRequest'];
export type DiffEventDto = components['schemas']['DiffEventDto'];
export type BulletItem = components['schemas']['BulletItem'];
export type DiffEventKind = components['schemas']['DiffEventKind'];
export type DiffSeverity = components['schemas']['DiffSeverity'];
export type HostStatus = components['schemas']['HostStatus'];
export type DashboardStatsDto = components['schemas']['DashboardStatsDto'];
export type DashboardAnalyticsDto = components['schemas']['DashboardAnalyticsDto'];
export type ScanAnalyticsPointDto = components['schemas']['ScanAnalyticsPointDto'];
export type PortCountDto = components['schemas']['PortCountDto'];
export type GroupInventoryStatDto = components['schemas']['GroupInventoryStatDto'];
export type ServiceRowDto = components['schemas']['ServiceRowDto'];
export type ServiceClusterDto = components['schemas']['ServiceClusterDto'];
export type ClusterKind = components['schemas']['ClusterKind'];
export type SignatureRuleDto = components['schemas']['SignatureRuleDto'];
export type ValidateSignatureResponse = components['schemas']['ValidateSignatureResponse'];
export type NotificationChannelDto = components['schemas']['NotificationChannelDto'];
export type NotificationChannelType = components['schemas']['NotificationChannelType'];
export type NotificationDeliveryDto = components['schemas']['NotificationDeliveryDto'];
export type DdFindingPayloadOverride = components['schemas']['DdFindingPayloadOverride'];
export type DdFindingPreviewDto = components['schemas']['DdFindingPreviewDto'];
export type DdFindingUpsert = components['schemas']['DdFindingUpsert'];
export type DdPushHostResponse = components['schemas']['DdPushHostResponse'];
export type DdRetryOutboxResponse = components['schemas']['DdRetryOutboxResponse'];
export type TriggerCustomWebhookRequest = components['schemas']['TriggerCustomWebhookRequest'];
export type QuickScanRequest = components['schemas']['QuickScanRequest'];
export type QuickScanResponse = components['schemas']['QuickScanResponse'];
export type ImportTargetsFlexibleRequest = components['schemas']['ImportTargetsFlexibleRequest'];
export type ImportTargetsFlexibleResponse = components['schemas']['ImportTargetsFlexibleResponse'];
export type ImportScanResultsRequest = components['schemas']['ImportScanResultsRequest'];
export type ImportScanResultsResponse = components['schemas']['ImportScanResultsResponse'];
export type ScanResultImportItem = components['schemas']['ScanResultImportItem'];

let accessToken: string | null = null;
let refreshInFlight: Promise<AuthUser | null> | null = null;

export function setAccessToken(token: string | null): void {
  accessToken = token;
}

export function getAccessToken(): string | null {
  return accessToken;
}

export const apiClient = createClient<paths>({
  baseUrl: '/',
  credentials: 'include',
});

/**
 * Single-flight refresh: wszystkie równoczesne wywołania (StrictMode, mount + interwał,
 * retry 401) dzielą JEDNO żądanie /auth/refresh — rotacja refresh tokena jest atomowa
 * po stronie API, więc drugi równoległy request dostałby "Concurrent refresh detected"
 * i unieważnił sesję.
 */
export function refreshSessionOnce(): Promise<AuthUser | null> {
  refreshInFlight ??= (async () => {
    try {
      const { data, error } = await apiClient.POST('/api/v1/auth/refresh');
      if (error || !data) {
        setAccessToken(null);
        return null;
      }
      setAccessToken(data.access_token);
      return data.user;
    } catch {
      setAccessToken(null);
      return null;
    } finally {
      refreshInFlight = null;
    }
  })();
  return refreshInFlight;
}

const authMiddleware: Middleware = {
  async onRequest({ request }) {
    if (accessToken) {
      request.headers.set('Authorization', `Bearer ${accessToken}`);
    }
    return request;
  },
  async onResponse({ request, response }) {
    // Access token wygasł (TTL 15 min) — odśwież sesję przez cookie i powtórz żądanie raz.
    if (response.status === 401 && accessToken && !request.url.includes('/api/v1/auth/')) {
      const user = await refreshSessionOnce();
      if (user) {
        const retry = request.clone();
        retry.headers.set('Authorization', `Bearer ${getAccessToken() ?? ''}`);
        return await fetch(retry);
      }
    }
    return response;
  },
};

apiClient.use(authMiddleware);

export function formatApiError(err: unknown, fallback: string): string {
  if (err && typeof err === 'object' && 'detail' in err) {
    const problem = err as Partial<ApiProblem>;
    const base = typeof problem.detail === 'string' && problem.detail ? problem.detail : fallback;
    if (Array.isArray(problem.violations) && problem.violations.length > 0) {
      const details = problem.violations
        .map((v) => `${v.field}: ${v.message}`)
        .slice(0, 3)
        .join('; ');
      return `${base} (${details})`;
    }
    return base;
  }
  return fallback;
}

export async function downloadAuthorizedFile(url: string, filename: string): Promise<void> {
  const makeHeaders = () => {
    const headers: Record<string, string> = {};
    if (accessToken) {
      headers.Authorization = `Bearer ${accessToken}`;
    }
    return headers;
  };

  let response = await fetch(url, {
    method: 'GET',
    headers: makeHeaders(),
    credentials: 'include',
  });

  if (response.status === 401 && accessToken) {
    const user = await refreshSessionOnce();
    if (user) {
      response = await fetch(url, {
        method: 'GET',
        headers: makeHeaders(),
        credentials: 'include',
      });
    }
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new Error(text || `Download failed with HTTP ${response.status}`);
  }

  const blob = await response.blob();
  const blobUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(blobUrl);
}
