/* eslint-disable react-refresh/only-export-components */
import { cva, type VariantProps } from 'class-variance-authority';
import * as React from 'react';

import { cn } from '@/lib/utils';

export const badgeVariants = cva(
  'inline-flex items-center border px-1.5 py-px font-mono text-[11px] leading-4',
  {
    variants: {
      variant: {
        default: 'border-primary/60 bg-transparent text-primary',
        success: 'border-emerald-600 bg-transparent text-emerald-400',
        warning: 'border-amber-600 bg-transparent text-amber-400',
        destructive: 'border-red-600 bg-transparent text-red-400',
        outline: 'border-border bg-transparent text-muted-foreground',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}
