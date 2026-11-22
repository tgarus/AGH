import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Copy, KeyRound, Plus, ShieldAlert, Trash2 } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { apiClient, formatApiError, type Role } from '@/api/client';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
  const [issuedToken, setIssuedToken] = useState<string | null>(null);
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

  const auditQuery = useQuery({
    queryKey: ['admin-audit-logs'],
    enabled: canManageUsers,
    queryFn: async () => {
      const { data, error } = await apiClient.GET('/api/v1/audit-logs', {
        params: { query: { page: 1, per_page: 20 } },
      });
      if (error || !data) {
        throw new Error(formatApiError(error, 'Failed to load audit logs.'));
      }
      return data;
    },
  });

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
                  {usersQuery.data?.items.map((u) => (
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
            <form onSubmit={handleCreateWorker} className="grid gap-2 sm:grid-cols-3">
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
              <Button type="submit" size="sm" disabled={createWorkerTokenMutation.isPending}>
                <KeyRound className="h-4 w-4" />
                {t('admin.createWorkerToken')}
              </Button>
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
                    <th className="px-3 py-2">{t('admin.status')}</th>
                    <th className="px-3 py-2 text-right">{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody>
                  {workersQuery.data?.items.length ? (
                    workersQuery.data.items.map((w) => (
                      <tr key={w.id} className="border-b border-border/60 last:border-0">
                        <td className="px-3 py-2 font-medium">{w.name}</td>
                        <td className="px-3 py-2 text-muted-foreground">{w.segment_tag ?? '—'}</td>
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
                      <td colSpan={4} className="px-3 py-4 text-center text-muted-foreground">
                        {t('admin.noWorkers')}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {canManageUsers ? (
        <Card>
          <CardHeader>
            <CardTitle>{t('admin.auditTitle')}</CardTitle>
            <CardDescription>{t('admin.auditSubtitle')}</CardDescription>
          </CardHeader>
          <CardContent>
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
                  {auditQuery.data?.items.map((entry) => (
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
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
