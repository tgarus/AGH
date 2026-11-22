import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';

import { getAccessToken } from '@/api/client';

export type LiveEventsStatus = 'connected' | 'reconnecting' | 'disconnected';

interface ParsedSseEvent {
  id: string | null;
  event: string;
  data: string;
}

function parseSseBlock(block: string): ParsedSseEvent | null {
  const lines = block.split('\n');
  let id: string | null = null;
  let eventName = 'message';
  const dataLines: string[] = [];

  for (const line of lines) {
    if (!line || line.startsWith(':')) {
      continue;
    }
    if (line.startsWith('id:')) {
      id = line.slice(3).trim();
    } else if (line.startsWith('event:')) {
      eventName = line.slice(6).trim();
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart());
    }
  }

  if (dataLines.length === 0) {
    return null;
  }
  return {
    id,
    event: eventName,
    data: dataLines.join('\n'),
  };
}

export function useLiveEvents(enabled: boolean): LiveEventsStatus {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<LiveEventsStatus>('disconnected');
  const lastEventIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    let backoffMs = 2000;
    let activeController: AbortController | null = null;

    const handleEvent = (ev: ParsedSseEvent) => {
      if (ev.id) {
        lastEventIdRef.current = ev.id;
      }
      if (ev.event === 'scan.progress' || ev.event === 'scan.status_changed') {
        void queryClient.invalidateQueries({ queryKey: ['scans'] });
        void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
      } else if (ev.event === 'diff.detected') {
        void queryClient.invalidateQueries({ queryKey: ['diffs'] });
        void queryClient.invalidateQueries({ queryKey: ['hosts'] });
        void queryClient.invalidateQueries({ queryKey: ['host-detail'] });
        void queryClient.invalidateQueries({ queryKey: ['clusters'] });
        void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
        void queryClient.invalidateQueries({ queryKey: ['notification-deliveries'] });
      } else if (ev.event === 'host.anomaly') {
        void queryClient.invalidateQueries({ queryKey: ['hosts'] });
        void queryClient.invalidateQueries({ queryKey: ['host-detail'] });
        void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
      } else if (ev.event === 'worker.status') {
        void queryClient.invalidateQueries({ queryKey: ['admin-workers'] });
        void queryClient.invalidateQueries({ queryKey: ['dashboard-summary'] });
      }
    };

    const connectLoop = async () => {
      while (!cancelled) {
        const token = getAccessToken();
        if (!token) {
          setStatus('reconnecting');
          await new Promise((resolve) => window.setTimeout(resolve, 1000));
          continue;
        }

        activeController = new AbortController();
        const headers: Record<string, string> = {
          Accept: 'text/event-stream',
          Authorization: `Bearer ${token}`,
        };
        if (lastEventIdRef.current) {
          headers['Last-Event-ID'] = lastEventIdRef.current;
        }

        try {
          const response = await fetch('/api/v1/events/stream', {
            method: 'GET',
            headers,
            credentials: 'include',
            signal: activeController.signal,
          });

          if (!response.ok || !response.body) {
            throw new Error(`SSE status ${response.status}`);
          }

          setStatus('connected');
          backoffMs = 2000;

          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';

          while (!cancelled) {
            const { value, done } = await reader.read();
            if (done) {
              break;
            }
            buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');

            let sepIdx = buffer.indexOf('\n\n');
            while (sepIdx !== -1) {
              const rawBlock = buffer.slice(0, sepIdx);
              buffer = buffer.slice(sepIdx + 2);
              const parsed = parseSseBlock(rawBlock);
              if (parsed) {
                handleEvent(parsed);
              }
              sepIdx = buffer.indexOf('\n\n');
            }
          }
        } catch {
          if (cancelled) {
            break;
          }
        }

        if (!cancelled) {
          setStatus('reconnecting');
          await new Promise((resolve) => window.setTimeout(resolve, backoffMs));
          backoffMs = Math.min(backoffMs * 2, 10_000);
        }
      }
    };

    void connectLoop();

    return () => {
      cancelled = true;
      activeController?.abort();
      setStatus('disconnected');
    };
  }, [enabled, queryClient]);

  return enabled ? status : 'disconnected';
}
