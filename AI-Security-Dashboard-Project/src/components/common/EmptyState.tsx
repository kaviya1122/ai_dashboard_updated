/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { Shield } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  actionText?: string;
  onAction?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon,
  actionText,
  onAction,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-zinc-800 rounded-lg bg-zinc-900/40">
      <div className="p-3 bg-zinc-800/80 rounded-full text-zinc-400 mb-4">
        {icon || <Shield className="w-6 h-6" />}
      </div>
      <h3 className="text-sm font-semibold text-zinc-200">{title}</h3>
      <p className="mt-1 text-xs text-zinc-400 max-w-sm">{description}</p>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="mt-4 px-3 py-1.5 text-xs font-medium rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500"
        >
          {actionText}
        </button>
      )}
    </div>
  );
};
