/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { SeverityLevel } from '../../types';
import { AlertCircle, AlertTriangle, Info, ShieldAlert, CheckCircle2 } from 'lucide-react';

interface SeverityBadgeProps {
  severity: SeverityLevel;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
}) => {
  const configs: Record<
    SeverityLevel,
    { label: string; bg: string; text: string; border: string; icon: React.ReactNode }
  > = {
    critical: {
      label: 'CRITICAL',
      bg: 'bg-red-950/70',
      text: 'text-red-300',
      border: 'border-red-800/80',
      icon: <ShieldAlert className="w-3.5 h-3.5 text-red-400" aria-hidden="true" />,
    },
    high: {
      label: 'HIGH',
      bg: 'bg-rose-950/60',
      text: 'text-rose-300',
      border: 'border-rose-800/70',
      icon: <AlertCircle className="w-3.5 h-3.5 text-rose-400" aria-hidden="true" />,
    },
    medium: {
      label: 'MEDIUM',
      bg: 'bg-amber-950/60',
      text: 'text-amber-300',
      border: 'border-amber-700/60',
      icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-400" aria-hidden="true" />,
    },
    low: {
      label: 'LOW',
      bg: 'bg-blue-950/60',
      text: 'text-blue-300',
      border: 'border-blue-800/60',
      icon: <Info className="w-3.5 h-3.5 text-blue-400" aria-hidden="true" />,
    },
    info: {
      label: 'INFO',
      bg: 'bg-emerald-950/50',
      text: 'text-emerald-300',
      border: 'border-emerald-800/60',
      icon: <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" aria-hidden="true" />,
    },
  };

  const current = configs[severity] || configs.info;
  const sizeClasses =
    size === 'sm'
      ? 'px-2 py-0.5 text-xs font-semibold'
      : size === 'lg'
      ? 'px-3 py-1.5 text-sm font-semibold tracking-wider'
      : 'px-2.5 py-1 text-xs font-semibold tracking-wide';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border font-mono uppercase ${current.bg} ${current.text} ${current.border} ${sizeClasses}`}
      role="status"
      aria-label={`Severity level: ${current.label}`}
    >
      {showIcon && current.icon}
      <span>{current.label}</span>
    </span>
  );
};
