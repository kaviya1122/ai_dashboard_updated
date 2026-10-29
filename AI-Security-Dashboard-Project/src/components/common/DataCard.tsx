/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';

interface DataCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  badge?: React.ReactNode;
  icon?: React.ReactNode;
  trend?: {
    direction: 'up' | 'down' | 'neutral';
    text: string;
    isPositive?: boolean; // In security, fewer incidents is positive!
  };
  onClick?: () => void;
  accentColor?: 'red' | 'amber' | 'emerald' | 'blue' | 'zinc';
}

export const DataCard: React.FC<DataCardProps> = ({
  title,
  value,
  subtitle,
  badge,
  icon,
  trend,
  onClick,
  accentColor = 'zinc',
}) => {
  const accentBorders = {
    red: 'border-l-4 border-l-red-500',
    amber: 'border-l-4 border-l-amber-500',
    emerald: 'border-l-4 border-l-emerald-500',
    blue: 'border-l-4 border-l-blue-500',
    zinc: 'border-l-4 border-l-zinc-600',
  };

  const Component = onClick ? 'button' : 'div';

  return (
    <Component
      onClick={onClick}
      className={`w-full text-left bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-sm transition-all duration-150 ${accentBorders[accentColor]} ${
        onClick ? 'hover:bg-zinc-850 hover:border-zinc-700 cursor-pointer focus:outline-none focus:ring-2 focus:ring-cyan-500/50' : ''
      }`}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">{title}</span>
        <div className="flex items-center gap-2">
          {badge}
          {icon && <span className="text-zinc-400">{icon}</span>}
        </div>
      </div>

      <div className="flex items-baseline gap-3">
        <span className="text-2xl sm:text-3xl font-bold font-mono text-zinc-100 tracking-tight">
          {value}
        </span>
        {trend && (
          <span
            className={`text-xs font-medium inline-flex items-center gap-0.5 ${
              trend.isPositive ? 'text-emerald-400' : 'text-rose-400'
            }`}
          >
            {trend.direction === 'up' ? '↑' : trend.direction === 'down' ? '↓' : '→'}{' '}
            {trend.text}
          </span>
        )}
      </div>

      {subtitle && <p className="mt-1.5 text-xs text-zinc-400">{subtitle}</p>}
    </Component>
  );
};
