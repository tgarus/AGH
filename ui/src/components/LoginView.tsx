import { Shield } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { useTranslation } from 'react-i18next';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/context/AuthContext';

export function LoginView() {
  const { t, i18n } = useTranslation();
  const { login } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const currentLang = i18n.language.startsWith('en') ? 'en' : 'pl';

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    try {
      await login(username, password);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : t('auth.loginError'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-background p-4 text-foreground">
      <div className="mb-4 flex items-center gap-2">
        <Button
          size="sm"
          variant={currentLang === 'pl' ? 'default' : 'outline'}
          onClick={() => void i18n.changeLanguage('pl')}
        >
          {t('language.pl')}
        </Button>
        <Button
          size="sm"
          variant={currentLang === 'en' ? 'default' : 'outline'}
          onClick={() => void i18n.changeLanguage('en')}
        >
          {t('language.en')}
        </Button>
      </div>

      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center border border-border bg-background text-foreground">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <CardTitle className="text-sm normal-case tracking-normal text-foreground">
                {t('auth.loginTitle')}
              </CardTitle>
              <CardDescription>{t('app.subtitle')}</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={(e) => void handleSubmit(e)} className="space-y-4">
            <div className="space-y-1">
              <label className="text-sm font-medium" htmlFor="login-username">
                {t('auth.username')}
              </label>
              <input
                id="login-username"
                type="text"
                autoComplete="username"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none"
              />
            </div>

            <div className="space-y-1">
              <label className="text-sm font-medium" htmlFor="login-password">
                {t('auth.password')}
              </label>
              <input
                id="login-password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-primary focus:outline-none"
              />
            </div>

            {errorMsg ? (
              <div className="rounded-md border border-red-800 bg-red-950/40 px-3 py-2 text-xs text-red-300">
                {errorMsg}
              </div>
            ) : null}

            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? t('auth.loggingIn') : t('auth.loginButton')}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
