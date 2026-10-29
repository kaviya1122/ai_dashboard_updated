/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { ShieldAlert, ShieldCheck, Info } from 'lucide-react';

interface RadarAxis {
  label: string;
  value: number; // 0 to 100
  target: number; // 0 to 100
  status: 'critical' | 'warning' | 'healthy';
  description: string;
}

export const AttackSurfaceRadar: React.FC = () => {
  const axes: RadarAxis[] = [
    { label: 'Perimeter Defense', value: 82, target: 90, status: 'warning', description: 'Firewall rules active; non-standard port 2222 observed.' },
    { label: 'Identity & IAM', value: 64, target: 95, status: 'critical', description: 'Kerberos password spraying detected against admin accounts.' },
    { label: 'Endpoint EDR', value: 91, target: 90, status: 'healthy', description: 'Falcon sensors deployed across 98% of monitored hosts.' },
    { label: 'Database Vault', value: 74, target: 95, status: 'warning', description: 'DB-PROD-01 host isolated following C2 beaconing pattern.' },
    { label: 'Egress Filtering', value: 58, target: 90, status: 'critical', description: 'Outbound heartbeat traffic to 198.51.100.89 escaped perimeter.' },
  ];

  const [activeAxisIndex, setActiveAxisIndex] = useState<number | null>(null);

  const size = 320;
  const center = size / 2;
  const radius = center - 45;
  const count = axes.length;

  // Helper to convert polar to cartesian
  const getCoordinates = (value: number, index: number) => {
    const angle = (Math.PI * 2 / count) * index - Math.PI / 2;
    const r = (value / 100) * radius;
    return {
      x: center + r * Math.cos(angle),
      y: center + r * Math.sin(angle),
    };
  };

  // Generate polygon points
  const currentPoints = axes.map((a, i) => {
    const c = getCoordinates(a.value, i);
    return `${c.x},${c.y}`;
  }).join(' ');

  const targetPoints = axes.map((a, i) => {
    const c = getCoordinates(a.target, i);
    return `${c.x},${c.y}`;
  }).join(' ');

  const activeAxis = activeAxisIndex !== null ? axes[activeAxisIndex] : null;

  return (
    <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
        <div>
          <h2 className="text-sm font-semibold text-zinc-100 uppercase tracking-wider">
            Enterprise Attack Surface Radar
          </h2>
          <p className="text-xs text-zinc-400">
            5-pillar visual posture rating (Current Defense vs Target SLA)
          </p>
        </div>
        <span className="text-[11px] font-mono text-cyan-400">VISUAL RADAR</span>
      </div>

      {/* SVG Canvas & Axis Cards */}
      <div className="flex flex-col md:flex-row items-center justify-around gap-6">
        {/* SVG Polygon Graph */}
        <div className="relative shrink-0">
          <svg width={size} height={size} className="overflow-visible select-none">
            {/* Concentric rings */}
            {[25, 50, 75, 100].map((ring) => {
              const r = (ring / 100) * radius;
              return (
                <circle
                  key={ring}
                  cx={center}
                  cy={center}
                  r={r}
                  fill="none"
                  stroke="#27272a"
                  strokeWidth="1"
                  strokeDasharray={ring === 100 ? 'none' : '2,2'}
                />
              );
            })}

            {/* Radial axes spokes */}
            {axes.map((_, i) => {
              const edge = getCoordinates(100, i);
              return (
                <line
                  key={i}
                  x1={center}
                  y1={center}
                  x2={edge.x}
                  y2={edge.y}
                  stroke="#27272a"
                  strokeWidth="1"
                />
              );
            })}

            {/* Target SLA polygon (dashed cyan outline) */}
            <polygon
              points={targetPoints}
              fill="none"
              stroke="#06b6d4"
              strokeWidth="1.5"
              strokeDasharray="4,4"
              opacity="0.6"
            />

            {/* Current posture polygon (filled red/amber) */}
            <polygon
              points={currentPoints}
              fill="rgba(244, 63, 94, 0.25)"
              stroke="#f43f5e"
              strokeWidth="2.5"
            />

            {/* Axis Node Points */}
            {axes.map((axis, i) => {
              const pt = getCoordinates(axis.value, i);
              const isHovered = activeAxisIndex === i;
              return (
                <g
                  key={i}
                  onMouseEnter={() => setActiveAxisIndex(i)}
                  onMouseLeave={() => setActiveAxisIndex(null)}
                  className="cursor-pointer"
                >
                  <circle
                    cx={pt.x}
                    cy={pt.y}
                    r={isHovered ? 7 : 5}
                    fill={axis.value < 70 ? '#ef4444' : axis.value < 85 ? '#f59e0b' : '#10b981'}
                    stroke="#09090b"
                    strokeWidth="2"
                    className="transition-all duration-150"
                  />
                </g>
              );
            })}

            {/* Axis Text Labels */}
            {axes.map((axis, i) => {
              const labelCoord = getCoordinates(118, i);
              const isHovered = activeAxisIndex === i;
              return (
                <text
                  key={i}
                  x={labelCoord.x}
                  y={labelCoord.y}
                  textAnchor="middle"
                  dominantBaseline="central"
                  className={`text-[10px] font-mono font-semibold transition-colors cursor-pointer ${
                    isHovered ? 'fill-cyan-300 font-bold' : 'fill-zinc-400 hover:fill-zinc-200'
                  }`}
                  onClick={() => setActiveAxisIndex(i)}
                >
                  {axis.label} ({axis.value}%)
                </text>
              );
            })}
          </svg>
        </div>

        {/* Dynamic Detail Card for selected Axis */}
        <div className="w-full max-w-sm space-y-2.5 text-xs">
          <div className="flex items-center justify-between pb-1.5 border-b border-zinc-800">
            <span className="font-mono text-[11px] text-zinc-400 uppercase">Posture Pillar Analysis</span>
            <span className="text-[10px] text-zinc-500 font-mono">Hover node to inspect</span>
          </div>

          <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-bold text-sm text-zinc-100">
                {activeAxis ? activeAxis.label : 'Overall Defense Index'}
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                  (activeAxis ? activeAxis.value : 73.8) < 70
                    ? 'bg-red-950 text-red-300 border border-red-800'
                    : 'bg-amber-950 text-amber-300 border border-amber-800'
                }`}
              >
                {activeAxis ? `${activeAxis.value}% / 100%` : '73.8% AGGREGATE'}
              </span>
            </div>

            <p className="text-zinc-300 leading-relaxed text-xs">
              {activeAxis ? activeAxis.description : 'Egress filtering and IAM credential boundaries exhibit elevated vulnerability from the active Cobalt Strike campaign. Endpoint EDR remains resilient.'}
            </p>

            <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px] font-mono text-zinc-400">
              <span>Target Standard: ≥90%</span>
              <span className="text-rose-400">
                Delta: -{90 - (activeAxis ? activeAxis.value : 74)}%
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4 text-[11px] font-mono text-zinc-400 px-1">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-xs bg-rose-500" /> Active Posture
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-xs border border-cyan-400 border-dashed" /> Target SLA
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
