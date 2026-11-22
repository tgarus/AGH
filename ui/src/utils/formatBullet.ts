import type { TFunction } from 'i18next';

import type { BulletItem } from '@/api/client';

type ParamsRecord = Record<string, unknown>;

function strParam(params: ParamsRecord, key: string, fallback = '—'): string {
  const val = params[key];
  if (val === null || val === undefined || val === '') {
    return fallback;
  }
  return String(val);
}

function boolParam(params: ParamsRecord, key: string): string {
  const val = params[key];
  return val ? 'true' : 'false';
}

export function formatBullet(t: TFunction, item: BulletItem): string {
  const rawParams =
    item.params && typeof item.params === 'object' && !Array.isArray(item.params)
      ? (item.params as ParamsRecord)
      : {};

  switch (item.key) {
    case 'host_discovered':
      return t('bullets.host_discovered', {
        open_ports: strParam(rawParams, 'open_ports', '0'),
      });
    case 'host_reactivated':
      return t('bullets.host_reactivated', {
        open_ports: strParam(rawParams, 'open_ports', '0'),
      });
    case 'host_inactive':
      return t('bullets.host_inactive', {
        consecutive_misses: strParam(rawParams, 'consecutive_misses', '3'),
      });
    case 'probable_tarpit_detected':
      return t('bullets.probable_tarpit_detected', {
        open_port_count: strParam(rawParams, 'open_port_count', '>200'),
      });
    case 'service_added': {
      const service =
        strParam(rawParams, 'product', '') ||
        strParam(rawParams, 'service_name', 'unknown');
      const version = strParam(rawParams, 'version', '');
      return t('bullets.service_added', {
        port: strParam(rawParams, 'port', '?'),
        proto: strParam(rawParams, 'proto', 'tcp'),
        service: version ? `${service} ${version}` : service,
      });
    }
    case 'service_removed':
      return t('bullets.service_removed', {
        port: strParam(rawParams, 'port', '?'),
        proto: strParam(rawParams, 'proto', 'tcp'),
        service: strParam(rawParams, 'service_name', 'unknown'),
        consecutive_misses: strParam(rawParams, 'consecutive_misses', '3'),
      });
    case 'service_changed':
      return t('bullets.service_changed', {
        port: strParam(rawParams, 'port', '?'),
        proto: strParam(rawParams, 'proto', 'tcp'),
        before: strParam(rawParams, 'before'),
        after: strParam(rawParams, 'after'),
      });
    case 'tls_certificate_changed':
      return t('bullets.tls_certificate_changed', {
        port: strParam(rawParams, 'port', '443'),
        subject_cn: strParam(rawParams, 'subject_cn'),
        self_signed: boolParam(rawParams, 'is_self_signed'),
      });
    case 'vhost_discovered':
      return t('bullets.vhost_discovered', {
        port: strParam(rawParams, 'port', '?'),
        vhost: strParam(rawParams, 'vhost'),
        scheme: strParam(rawParams, 'scheme', 'http'),
        http_status: strParam(rawParams, 'http_status'),
      });
    case 'admin_panel_detected':
      return t('bullets.admin_panel_detected', {
        port: strParam(rawParams, 'port', '?'),
        vhost: strParam(rawParams, 'vhost'),
        path: strParam(rawParams, 'path', '/admin'),
      });
    case 'technology_detected':
      return t('bullets.technology_detected', {
        port: strParam(rawParams, 'port', '?'),
        vhost: strParam(rawParams, 'vhost'),
        technology: strParam(rawParams, 'technology'),
      });
    case 'title_changed':
      return t('bullets.title_changed', {
        port: strParam(rawParams, 'port', '?'),
        vhost: strParam(rawParams, 'vhost'),
        before: strParam(rawParams, 'before'),
        after: strParam(rawParams, 'after'),
      });
    case 'http_status_changed':
      return t('bullets.http_status_changed', {
        port: strParam(rawParams, 'port', '?'),
        vhost: strParam(rawParams, 'vhost'),
        before_status: strParam(rawParams, 'before_status'),
        after_status: strParam(rawParams, 'after_status'),
      });
    case 'favicon_changed':
      return t('bullets.favicon_changed', {
        port: strParam(rawParams, 'port', '?'),
        vhost: strParam(rawParams, 'vhost'),
        before: strParam(rawParams, 'before'),
        after: strParam(rawParams, 'after'),
      });
    case 'cookie_changed':
      return t('bullets.cookie_changed', {
        port: strParam(rawParams, 'port', '?'),
        vhost: strParam(rawParams, 'vhost'),
        cookie: strParam(rawParams, 'cookie'),
        http_only: boolParam(rawParams, 'http_only'),
        secure: boolParam(rawParams, 'secure'),
      });
    case 'diurnal_variance':
      return t('bullets.diurnal_variance', {
        active_hours: strParam(rawParams, 'active_hours', 'intermittent'),
        transitions: strParam(rawParams, 'transitions', '2'),
      });
    case 'port_flapping':
      return t('bullets.port_flapping', {
        port: strParam(rawParams, 'port', '?'),
        proto: strParam(rawParams, 'proto', 'tcp'),
        state: strParam(rawParams, 'state', 'flapping'),
      });
    default:
      return `${item.key}: ${JSON.stringify(rawParams)}`;
  }
}
