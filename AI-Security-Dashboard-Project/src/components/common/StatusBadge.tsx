/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { IncidentStatus } from '../../types';

interface StatusBadgeProps {
  status: IncidentStatus;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  const configs: Record<IncidentStatus, { label: string; bg: string; text: string; border: string }> = {
    new: {
      label: 'NEW',
      bg: 'bg-zinc-800/80',
      text: 'text-zinc-200',
      border: 'border-zinc-700',
    },
    investigating: {
      label: 'INVESTIGATING',
      bg: 'bg-amber-950/50',
      text: 'text-amber-300',
      border: 'border-amber-800/60',
    },
    contained: {
      label: 'CONTAINED',
      bg: 'bg-indigo-950/50',
      text: 'text-indigo-300',
      border: 'border-indigo-800/60',
    },
    resolved: {
      label: 'RESOLVED',
      bg: 'bg-emerald-950/50',
      text: 'text-emerald-300',
      border: 'border-emerald-800/60',
    },
    false_positive: {
      label: 'FALSE POSITIVE',
      bg: 'bg-zinc-900',
      text: 'text-zinc-400',
      border: 'border-zinc-800',
    },
  };

  const item = configs[status] || configs.new;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium border ${item.bg} ${item.text} ${item.border}`}
      role="status"
      aria-label={`Incident status: ${item.label}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current mr-1.5 opacity-80" aria-hidden="true" />
      {item.label}
    </span>
  );
};
