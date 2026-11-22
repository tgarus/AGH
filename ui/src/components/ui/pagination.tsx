/* eslint-disable react-refresh/only-export-components */
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { Button } from '@/components/ui/button';

export interface TablePaginationProps {
  page: number;
  perPage: number;
  totalItems: number;
  onPageChange: (nextPage: number) => void;
  onPerPageChange?: (nextPerPage: number) => void;
  perPageOptions?: number[];
}

export function paginateItems<T>(
  items: readonly T[],
  page: number,
  perPage: number,
): { items: T[]; totalItems: number; safePage: number } {
  const safePerPage = Math.max(1, perPage);
  const totalItems = items.length;
  const totalPages = Math.max(1, Math.ceil(totalItems / safePerPage));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const start = (safePage - 1) * safePerPage;
  return {
    items: items.slice(start, start + safePerPage),
    totalItems,
    safePage,
  };
}

function buildPageSlots(safePage: number, totalPages: number): Array<number | 'ellipsis'> {
  if (totalPages <= 7) {
    return Array.from({ length: totalPages }, (_, idx) => idx + 1);
  }
  const pages = new Set<number>([1, totalPages, safePage - 1, safePage, safePage + 1]);
  const sorted = Array.from(pages)
    .filter((p) => p >= 1 && p <= totalPages)
    .sort((a, b) => a - b);

  const out: Array<number | 'ellipsis'> = [];
  for (let i = 0; i < sorted.length; i += 1) {
    const cur = sorted[i];
    if (cur === undefined) {
      continue;
    }
    const prev = i > 0 ? sorted[i - 1] : undefined;
    if (prev !== undefined && cur - prev > 1) {
      out.push('ellipsis');
    }
    out.push(cur);
  }
  return out;
}

export function TablePagination({
  page,
  perPage,
  totalItems,
  onPageChange,
  onPerPageChange,
  perPageOptions = [10, 25, 50, 100],
}: TablePaginationProps) {
  const { t } = useTranslation();

  const safePerPage = Math.max(1, perPage);
  const totalPages = Math.max(1, Math.ceil(totalItems / safePerPage));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const from = totalItems === 0 ? 0 : (safePage - 1) * safePerPage + 1;
  const to = Math.min(totalItems, safePage * safePerPage);
  const slots = buildPageSlots(safePage, totalPages);

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border/70 pt-2.5 text-xs text-muted-foreground">
      <div>
        {totalItems > 0
          ? t('pagination.showing', { from, to, total: totalItems })
          : t('pagination.empty')}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {onPerPageChange ? (
          <label className="flex items-center gap-1.5">
            <span>{t('pagination.perPage')}</span>
            <select
              value={safePerPage}
              onChange={(e) => {
                onPerPageChange(Number(e.target.value) || 10);
                onPageChange(1);
              }}
              className="rounded border border-border bg-background px-2 py-1 text-xs text-foreground"
            >
              {perPageOptions.map((opt) => (
                <option key={opt} value={opt}>
                  {opt}
                </option>
              ))}
            </select>
          </label>
        ) : null}

        <div className="flex items-center gap-1">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onPageChange(Math.max(1, safePage - 1))}
            disabled={safePage <= 1 || totalItems === 0}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            {t('pagination.prev')}
          </Button>

          {slots.map((slot, idx) =>
            slot === 'ellipsis' ? (
              <span key={`e-${idx}`} className="px-1.5 font-mono">
                …
              </span>
            ) : (
              <Button
                key={slot}
                type="button"
                variant={slot === safePage ? 'default' : 'outline'}
                size="sm"
                className="min-w-7 px-2 font-mono"
                onClick={() => onPageChange(slot)}
                disabled={totalItems === 0}
              >
                {slot}
              </Button>
            ),
          )}

          <span className="px-1.5 font-mono">
            {t('pagination.pageOf', { page: safePage, pages: totalPages })}
          </span>

          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => onPageChange(Math.min(totalPages, safePage + 1))}
            disabled={safePage >= totalPages || totalItems === 0}
          >
            {t('pagination.next')}
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </div>
  );
}
