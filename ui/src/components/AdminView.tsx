import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, KeyRound, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError, type Role } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { paginateItems, TablePagination } from '@/components/ui/pagination';
import { useAuth } from '@/context/AuthContext';

export function AdminView() {
  const { t } = useTranslation();
  const { user, hasPermission } = useAuth();
  const queryClient = useQueryClient();

  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('ReadOnly');

  const [workerName, setWorkerName] = useState('');
  const [workerSegment, setWorkerSegment] = useState('mock-lab');
  const [visibilityScope, setVisibilityScope] = useState<'all' | 'restricted'>('all');
  const [selectedGroupIds, setSelectedGroupIds] = useState<string[]>([]);
  const [selectedUserIds, setSelectedUserIds] = useState<string[]>([]);
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
  const [usersPage, setUsersPage] = useState(1);
  const [usersPerPage, setUsersPerPage] = useState(10);
  const [workersPage, setWorkersPage] = useState(1);
  const [workersPerPage, setWorkersPerPage] = useState(10);
  const [auditPage, setAuditPage] = useState(1);
  const [auditPerPage, setAuditPerPage] = useState(10);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const canManageUsers = hasPermission('manage_users_and_audit');
  const canManageWorkers = hasPermission('manage_workers');

  const usersQuery = useQuery({
    queryKey: ['admin-users'],
    enabled: canManageUsers,
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/users', {
        params: { query: { page: 1, per_page: 50 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load users.'));
      }
      return data;
    },
  });

  const workersQuery = useQuery({
    queryKey: ['admin-workers'],
    enabled: canManageWorkers,
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/workers', {
        params: { query: { page: 1, per_page: 50 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load workers.'));
      }
      return data;
    },
  });

  const assetGroupsQuery = useQuery({
    queryKey: ['asset-groups'],
    enabled: canManageWorkers,
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

  const directoryUsersQuery = useQuery({
    queryKey: ['users-directory'],
    enabled: canManageWorkers,
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/users/directory');
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load user directory.'));
      }
      return data;
    },
  });

  const auditQuery = useQuery({
    queryKey: ['admin-audit-logs'],
    enabled: canManageUsers,
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/audit-logs', {
        params: { query: { page: 1, per_page: 100 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load audit logs.'));
      }
      return data;
    },
  });

  const adminUserIds = (directoryUsersQuery.data ?? [])
    .filter((u) => u.role === 'Admin')
    .map((u) => u.id);
  const pagedUsers = paginateItems(usersQuery.data?.items ?? [], usersPage, usersPerPage);
  const pagedWorkers = paginateItems(workersQuery.data?.items ?? [], workersPage, workersPerPage);
  const pagedAudit = paginateItems(auditQuery.data?.items ?? [], auditPage, auditPerPage);

  const createUserMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/users', {
        body: {
          username,
          email,
          password,
          role,
          preferred_locale: 'pl',
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to create user.'));
      }
      return data;
    },
    onSuccess: () => {
      setErrorMsg(null);
      setUsername('');
      setEmail('');
      setPassword('');
      void queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      void queryClient.invalidateQueries({ queryKey: ['admin-audit-logs'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const deleteUserMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await apiClient.DELETE('/api/v1/users/{id}', {
        params: { path: { id } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to delete user.'));
      }
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['admin-users'] });
      void queryClient.invalidateQueries({ queryKey: ['admin-audit-logs'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const createWorkerTokenMutation = useMutation({
    mutationFn: async () => {
      const { data, error } = await apiClient.POST('/api/v1/workers/tokens', {
        body: {
          name: workerName,
          segment_tag: workerSegment || null,
          max_concurrency: 2,
          visibility_scope: visibilityScope,
          allowed_asset_group_ids: visibilityScope === 'restricted' ? selectedGroupIds : [],
          allowed_user_ids:
            visibilityScope === 'restricted'
              ? Array.from(new Set([...selectedUserIds, ...adminUserIds]))
              : [],
        },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to create worker token.'));
      }
      return data;
    },
    onSuccess: (created) => {
      setErrorMsg(null);
      setWorkerName('');
      setVisibilityScope('all');
      setSelectedGroupIds([]);
      setSelectedUserIds([]);
      setIssuedToken(created.token);
      void queryClient.invalidateQueries({ queryKey: ['admin-workers'] });
      void queryClient.invalidateQueries({ queryKey: ['admin-audit-logs'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const revokeWorkerMutation = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await apiClient.POST('/api/v1/workers/{id}/revoke', {
        params: { path: { id } },
      });
      if (error) {
        throw new Error(formatApiError(error, 'Failed to revoke worker.'));
      }
    },
    onSuccess: () => {
      setErrorMsg(null);
      void queryClient.invalidateQueries({ queryKey: ['admin-workers'] });
      void queryClient.invalidateQueries({ queryKey: ['admin-audit-logs'] });
    },
    onError: (err) => setErrorMsg(err.message),
  });

  const handleCreateUser = (e: FormEvent) => {
    e.preventDefault();
    createUserMutation.mutate();
  };

  const handleCreateWorker = (e: FormEvent) => {
    e.preventDefault();
    createWorkerTokenMutation.mutate();
  };

  return (
    <div className="space-y-6">
      {errorMsg ? (
        <div className="rounded-md border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-300">
          {errorMsg}
        </div>
      ) : null}

      {canManageUsers ? (
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.usersTitle')}</CardTitle>
            <CardDescription>{t('admin.usersSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <form onSubmit={handleCreateUser} className="grid gap-2 sm:grid-cols-5">
              <input
                type="text"
                required
                placeholder={t('auth.username')}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
              <input
                type="email"
                required
                placeholder={t('admin.email')}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
              <input
                type="password"
                required
                placeholder={t('auth.password')}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              />
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as Role)}
                className="rounded-md border border-border bg-background px-3 py-2 text-sm"
              >
                <option value="ReadOnly">ReadOnly</option>
                <option value="ReadWrite">ReadWrite</option>
                <option value="ReadWriteDelete">ReadWriteDelete</option>
                <option value="Admin">Admin</option>
              </select>
              <Button type="submit" size="sm" disabled={createUserMutation.isPending}>
                <Plus className="h-4 w-4" />
                {t('admin.createUser')}
              </Button>
            </form>

            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2">{t('auth.username')}</th>
                    <th className="px-3 py-2">{t('admin.email')}</th>
                    <th className="px-3 py-2">{t('admin.role')}</th>
                    <th className="px-3 py-2">{t('admin.status')}</th>
                    <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedUsers.items.map((u) => (
                    <tr key={u.id} className="border-b border-border/60 last:border-0">
                      <td className="px-3 py-2 font-medium">{u.username}</td>
                      <td className="px-3 py-2 text-muted-foreground">{u.email}</td>
                      <td className="px-3 py-2">
                        <Badge variant={u.role === 'Admin' ? 'warning' : 'outline'}>{u.role}</Badge>
                      </td>
                      <td className="px-3 py-2">
                        <Badge variant={u.is_active ? 'success' : 'destructive'}>
                          {u.is_active ? t('admin.active') : t('admin.inactive')}
                        </Badge>
                      </td>
                      <td className="px-3 py-2 text-right">
                        {u.id !== user?.id ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteUserMutation.mutate(u.id)}
                          >
                            <Trash2 className="h-4 w-4 text-red-400" />
                          </Button>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <TablePagination
              page={pagedUsers.safePage}
              perPage={usersPerPage}
              totalItems={pagedUsers.totalItems}
              onPageChange={setUsersPage}
              onPerPageChange={(n) => {
                setUsersPerPage(n);
                setUsersPage(1);
              }}
            />
          </CardContent>
        </Card>
      ) : null}

      {canManageWorkers ? (
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.workersTitle')}</CardTitle>
            <CardDescription>{t('admin.workersSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <form onSubmit={handleCreateWorker} className="space-y-3">
              <div className="grid gap-2 sm:grid-cols-4">
                <input
                  type="text"
                  required
                  placeholder={t('admin.workerName')}
                  value={workerName}
                  onChange={(e) => setWorkerName(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
                <input
                  type="text"
                  placeholder={t('admin.workerSegment')}
                  value={workerSegment}
                  onChange={(e) => setWorkerSegment(e.target.value)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                />
                <select
                  value={visibilityScope}
                  onChange={(e) => setVisibilityScope(e.target.value as 'all' | 'restricted')}
                  className="rounded-md border border-border bg-background px-3 py-2 text-sm"
                >
                  <option value="all">{t('admin.workerScopeAllOption')}</option>
                  <option value="restricted">{t('admin.workerScopeRestrictedOption')}</option>
                </select>
                <Button type="submit" size="sm" disabled={createWorkerTokenMutation.isPending}>
                  <KeyRound className="h-4 w-4" />
                  {t('admin.createWorkerToken')}
                </Button>
              </div>

              {visibilityScope === 'restricted' ? (
                <div className="grid gap-4 rounded-md border border-border bg-background/50 p-3 text-xs sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <div className="font-semibold text-muted-foreground">
                      {t('admin.workerAllowedGroupsLabel')}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {assetGroupsQuery.data?.items.map((g) => {
                        const checked = selectedGroupIds.includes(g.id);
                        return (
                          <label
                            key={g.id}
                            className="flex cursor-pointer items-center gap-1.5 rounded border border-border px-2 py-1 hover:bg-secondary/50"
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={(e) =>
                                setSelectedGroupIds((prev) =>
                                  e.target.checked
                                    ? [...prev, g.id]
                                    : prev.filter((id) => id !== g.id),
                                )
                              }
                            />
                            <span>{g.name}</span>
                          </label>
                        );
                      })}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <div className="font-semibold text-muted-foreground">
                      {t('admin.workerAllowedUsersLabel')}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {(directoryUsersQuery.data ?? []).map((u) => {
                        const isAdmin = u.role === 'Admin';
                        const checked = isAdmin || selectedUserIds.includes(u.id);
                        return (
                          <label
                            key={u.id}
                            className={
                              isAdmin
                                ? 'flex cursor-not-allowed items-center gap-1.5 rounded border border-primary bg-primary/50 px-2 py-1 text-foreground'
                                : 'flex cursor-pointer items-center gap-1.5 rounded border border-border px-2 py-1 hover:bg-secondary/50'
                            }
                          >
                            <input
                              type="checkbox"
                              checked={checked}
                              disabled={isAdmin}
                              onChange={(e) => {
                                if (isAdmin) return;
                                setSelectedUserIds((prev) =>
                                  e.target.checked
                                    ? [...prev, u.id]
                                    : prev.filter((id) => id !== u.id),
                                );
                              }}
                            />
                            <span>
                              {u.username} ({u.role})
                            </span>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                </div>
              ) : null}
            </form>

            {issuedToken ? (
              <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-amber-800 bg-amber-950/40 p-3 text-xs">
                <div>
                  <div className="font-semibold text-amber-200">{t('admin.oneTimeTokenNotice')}</div>
                  <code className="font-mono text-amber-100">{issuedToken}</code>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => void navigator.clipboard.writeText(issuedToken)}
                >
                  <Copy className="h-3.5 w-3.5" />
                  {t('common.copy')}
                </Button>
              </div>
            ) : null}

            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-border bg-secondary/40 text-xs uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2">{t('admin.workerName')}</th>
                    <th className="px-3 py-2">{t('admin.workerSegment')}</th>
                    <th className="px-3 py-2">{t('admin.workerVisibility')}</th>
                    <th className="px-3 py-2">{t('admin.status')}</th>
                    <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedWorkers.items.length ? (
                    pagedWorkers.items.map((w) => (
                      <tr key={w.id} className="border-b border-border/60 last:border-0">
                        <td className="px-3 py-2 font-medium">{w.name}</td>
                        <td className="px-3 py-2 text-muted-foreground">{w.segment_tag ?? '—'}</td>
                        <td className="px-3 py-2">
                          {w.visibility_scope === 'restricted' ? (
                            <Badge variant="warning">
                              {t('admin.scopeRestrictedCount', {
                                groups: w.allowed_asset_group_ids?.length ?? 0,
                                users: w.allowed_user_ids?.length ?? 0,
                              })}
                            </Badge>
                          ) : (
                            <Badge variant="outline">{t('admin.scopeAll')}</Badge>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <Badge variant={w.status === 'revoked' ? 'destructive' : 'outline'}>
                            {w.status}
                          </Badge>
                        </td>
                        <td className="px-3 py-2 text-right">
                          {w.status !== 'revoked' ? (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => revokeWorkerMutation.mutate(w.id)}
                            >
                              <ShieldAlert className="h-3.5 w-3.5" />
                              {t('admin.revokeWorker')}
                            </Button>
                          ) : null}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={5} className="px-3 py-4 text-center text-muted-foreground">
                        {t('admin.noWorkers')}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <TablePagination
              page={pagedWorkers.safePage}
              perPage={workersPerPage}
              totalItems={pagedWorkers.totalItems}
              onPageChange={setWorkersPage}
              onPerPageChange={(n) => {
                setWorkersPerPage(n);
                setWorkersPage(1);
              }}
            />
          </CardContent>
        </Card>
      ) : null}

      {canManageUsers ? (
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.auditTitle')}</CardTitle>
            <CardDescription>{t('admin.auditSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-border bg-secondary/40 uppercase text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2">{t('admin.auditTime')}</th>
                    <th className="px-3 py-2">{t('admin.auditActor')}</th>
                    <th className="px-3 py-2">{t('admin.auditAction')}</th>
                    <th className="px-3 py-2">{t('admin.auditResource')}</th>
                  </tr>
                </thead>
                <tbody>
                  {pagedAudit.items.map((entry) => (
                    <tr key={entry.id} className="border-b border-border/60 last:border-0">
                      <td className="px-3 py-2 font-mono">{entry.created_at}</td>
                      <td className="px-3 py-2">{entry.actor_type}</td>
                      <td className="px-3 py-2 font-mono text-primary">{entry.action}</td>
                      <td className="px-3 py-2">{entry.resource_type}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <TablePagination
              page={pagedAudit.safePage}
              perPage={auditPerPage}
              totalItems={pagedAudit.totalItems}
              onPageChange={setAuditPage}
              onPerPageChange={(n) => {
                setAuditPerPage(n);
                setAuditPage(1);
              }}
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
