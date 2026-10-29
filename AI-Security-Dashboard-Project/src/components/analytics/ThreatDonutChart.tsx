/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { SeverityLevel } from '../../types';

interface DonutSlice {
  severity: SeverityLevel;
  label: string;
  count: number;
  percentage: number;
  color: string;
  stroke: string;
}

export const ThreatDonutChart: React.FC = () => {
  const slices: DonutSlice[] = [
    { severity: 'critical', label: 'Critical Severity', count: 1, percentage: 20, color: '#dc2626', stroke: '#ef4444' },
    { severity: 'high', label: 'High Severity', count: 1, percentage: 20, color: '#f43f5e', stroke: '#fb7185' },
    { severity: 'medium', label: 'Medium Severity', count: 1, percentage: 20, color: '#f59e0b', stroke: '#fbbf24' },
    { severity: 'low', label: 'Low Severity', count: 1, percentage: 20, color: '#3b82f6', stroke: '#60a5fa' },
    { severity: 'info', label: 'Informational', count: 1, percentage: 20, color: '#10b981', stroke: '#34d399' },
  ];

  const [activeSlice, setActiveSlice] = useState<DonutSlice | null>(slices[0]);

  const size = 200;
  const strokeWidth = 26;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  let accumulatedPercent = 0;

  return (
    <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs space-y-4 flex flex-col justify-between">
      <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 uppercase tracking-wider">
            Severity Distribution Donut
          </h2>
          <p className="text-xs text-zinc-400">Proportional classification share</p>
        </div>
        <span className="text-[11px] font-mono text-cyan-400">DONUT CHART</span>
      </div>

      <div className="flex flex-col sm:flex-row items-center justify-around gap-6">
        {/* SVG Donut */}
        <div className="relative shrink-0 flex items-center justify-center">
          <svg width={size} height={size} className="transform -rotate-90">
            {slices.map((slice, i) => {
              const strokeDasharray = `${(slice.percentage / 100) * circumference} ${circumference}`;
              const strokeDashoffset = -((accumulatedPercent / 100) * circumference);
              accumulatedPercent += slice.percentage;

              const isHovered = activeSlice?.severity === slice.severity;

              return (
                <circle
                  key={i}
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="transparent"
                  stroke={slice.color}
                  strokeWidth={isHovered ? strokeWidth + 4 : strokeWidth}
                  strokeDasharray={strokeDasharray}
                  strokeDashoffset={strokeDashoffset}
                  className="transition-all duration-200 cursor-pointer hover:opacity-90"
                  onMouseEnter={() => setActiveSlice(slice)}
                />
              );
            })}
          </svg>

          {/* Center Readout */}
          <div className="absolute text-center pointer-events-none">
            <span className="text-xs font-mono text-zinc-400 uppercase block">Selected</span>
            <span className="text-xl font-bold font-mono text-zinc-100">
              {activeSlice ? `${activeSlice.percentage}%` : '5 Total'}
            </span>
            <span className="text-[10px] font-mono text-zinc-500 block uppercase">
              {activeSlice ? activeSlice.severity : 'Events'}
            </span>
          </div>
        </div>

        {/* Legend list */}
        <div className="space-y-1.5 w-full max-w-xs text-xs">
          {slices.map((slice) => {
            const isHovered = activeSlice?.severity === slice.severity;
            return (
              <div
                key={slice.severity}
                onMouseEnter={() => setActiveSlice(slice)}
                className={`p-1.5 rounded transition-all cursor-pointer flex items-center justify-between ${
                  isHovered ? 'bg-zinc-800' : 'hover:bg-zinc-950'
                }`}
              >
                <div className="flex items-center gap-2">
                  <span
                    className="w-2.5 h-2.5 rounded-full shrink-0"
                    style={{ backgroundColor: slice.color }}
                  />
                  <span className={`font-medium ${isHovered ? 'text-zinc-100 font-semibold' : 'text-zinc-300'}`}>
                    {slice.label}
                  </span>
                </div>
                <span className="font-mono text-zinc-400">
                  {slice.count} ({slice.percentage}%)
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
