/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  Globe,
  Package,
  Terminal,
  Key,
  Network,
  Radio,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';

export interface KillchainStage {
  id: string;
  number: number;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
  status: 'active_breach' | 'contained' | 'monitored' | 'clean';
  threatCount: number;
  mitreCode: string;
  leadIndicator: string;
  targetAsset: string;
  description: string;
}

export const VisualKillchain: React.FC = () => {
  const { openAlertModal, alerts } = useSecurity();

  const [selectedStageId, setSelectedStageId] = useState<string>('c2');

  const stages: KillchainStage[] = [
    {
      id: 'recon',
      number: 1,
      name: 'Reconnaissance',
      icon: Globe,
      status: 'monitored',
      threatCount: 3,
      mitreCode: 'TA0043',
      leadIndicator: 'Port scanning on edge gateway 10.240.1.2',
      targetAsset: 'GW-EDGE-02',
      description: 'Adversary performed TCP SYN sweep over perimeter IP blocks to discover listening services.',
    },
    {
      id: 'delivery',
      number: 2,
      name: 'Weaponized Delivery',
      icon: Package,
      status: 'contained',
      threatCount: 1,
      mitreCode: 'TA0001',
      leadIndicator: 'Phishing lure invoice_stage2.exe attachment',
      targetAsset: 'WS-FINANCE-04',
      description: 'Spear-phishing attachment delivered with executable wrapper and lure branding.',
    },
    {
      id: 'exploitation',
      number: 3,
      name: 'Exploitation',
      icon: Terminal,
      status: 'contained',
      threatCount: 2,
      mitreCode: 'TA0002',
      leadIndicator: 'rundll32.exe injected into lsass.exe (PID 684)',
      targetAsset: 'WS-FINANCE-04',
      description: 'Memory read access requested to extract Kerberos tickets and password hashes.',
    },
    {
      id: 'privilege',
      number: 4,
      name: 'Credential Abuse',
      icon: Key,
      status: 'contained',
      threatCount: 1,
      mitreCode: 'TA0006',
      leadIndicator: 'Kerberos pre-auth spray across 6 admin accounts',
      targetAsset: 'DC-CORE-01',
      description: 'Failed pre-authentication bursts attempting administrative account compromise.',
    },
    {
      id: 'lateral',
      number: 5,
      name: 'Lateral Movement',
      icon: Network,
      status: 'active_breach',
      threatCount: 2,
      mitreCode: 'TA0008',
      leadIndicator: 'SMB Port 445 RPC sessions to DB-PROD-01',
      targetAsset: 'DB-PROD-01',
      description: 'Pivoting from compromised workstation to internal PostgreSQL production database.',
    },
    {
      id: 'c2',
      number: 6,
      name: 'C2 & Exfiltration',
      icon: Radio,
      status: 'active_breach',
      threatCount: 4,
      mitreCode: 'TA0011',
      leadIndicator: 'Cobalt Strike TLS beaconing to 198.51.100.89:443',
      targetAsset: 'DB-PROD-01',
      description: 'Periodic heartbeats transmitting encrypted telemetry to external command node.',
    },
  ];

  const currentStage = stages.find((s) => s.id === selectedStageId) || stages[5];

  const getStatusColor = (status: KillchainStage['status']) => {
    switch (status) {
      case 'active_breach':
        return {
          border: 'border-red-500',
          bg: 'bg-red-950/60',
          text: 'text-red-400',
          badge: 'bg-red-950 border-red-800 text-red-300',
          label: 'CRITICAL BREACH',
          pulse: 'bg-red-500',
        };
      case 'contained':
        return {
          border: 'border-amber-500',
          bg: 'bg-amber-950/50',
          text: 'text-amber-400',
          badge: 'bg-amber-950 border-amber-800 text-amber-300',
          label: 'CONTAINED',
          pulse: 'bg-amber-500',
        };
      case 'monitored':
        return {
          border: 'border-blue-500',
          bg: 'bg-blue-950/40',
          text: 'text-blue-400',
          badge: 'bg-blue-950 border-blue-800 text-blue-300',
          label: 'SUSPICIOUS',
          pulse: 'bg-blue-500',
        };
      default:
        return {
          border: 'border-emerald-500',
          bg: 'bg-emerald-950/40',
          text: 'text-emerald-400',
          badge: 'bg-emerald-950 border-emerald-800 text-emerald-300',
          label: 'CLEAN',
          pulse: 'bg-emerald-500',
        };
    }
  };

  return (
    <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="font-mono text-xs font-bold text-cyan-400 uppercase tracking-widest">
              KILLCHAIN TOPOLOGY
            </span>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-zinc-800 text-zinc-300">
              MITRE E*STAGES
            </span>
          </div>
          <h2 className="text-base font-bold text-zinc-100">
            Adversary Attack Progression & Killchain Stages
          </h2>
          <p className="text-xs text-zinc-400">
            Visual killchain pipeline tracking adversary lateral infiltration from delivery to C2 beaconing
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto font-mono text-xs">
          <span className="flex items-center gap-1.5 text-red-400">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
            2 Active Breach Stages
          </span>
        </div>
      </div>

      {/* Visual Pipeline Track */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {stages.map((stage, idx) => {
          const Icon = stage.icon;
          const isSelected = selectedStageId === stage.id;
          const styling = getStatusColor(stage.status);

          return (
            <button
              key={stage.id}
              onClick={() => setSelectedStageId(stage.id)}
              className={`text-left p-3.5 rounded-lg border transition-all duration-150 flex flex-col justify-between space-y-3 relative group ${
                isSelected
                  ? `${styling.border} ${styling.bg} shadow-md shadow-zinc-950 ring-1 ring-cyan-500/50`
                  : 'bg-zinc-950/80 border-zinc-800/90 hover:border-zinc-700 hover:bg-zinc-900'
              }`}
            >
              {/* Top Badge: Stage # & Pulse */}
              <div className="flex items-center justify-between w-full">
                <span className="font-mono text-[10px] font-bold text-zinc-400">
                  STEP 0{stage.number}
                </span>
                <span className={`w-2 h-2 rounded-full ${styling.pulse} ${stage.status === 'active_breach' ? 'animate-ping' : ''}`} />
              </div>

              {/* Icon & Name */}
              <div className="space-y-1">
                <div className={`w-8 h-8 rounded-md flex items-center justify-center ${isSelected ? styling.bg : 'bg-zinc-900'} border border-zinc-800`}>
                  <Icon className={`w-4 h-4 ${isSelected ? styling.text : 'text-zinc-400'}`} />
                </div>
                <h3 className="font-semibold text-xs text-zinc-200 line-clamp-1">
                  {stage.name}
                </h3>
                <span className="font-mono text-[10px] text-zinc-500 block">
                  {stage.mitreCode}
                </span>
              </div>

              {/* Status Pill */}
              <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between w-full">
                <span className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase border ${styling.badge}`}>
                  {styling.label}
                </span>
                <span className="font-mono text-[11px] font-bold text-zinc-300">
                  {stage.threatCount}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Selected Stage Deep-Dive Card */}
      <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-zinc-800/80">
          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-bold text-cyan-400">
              STAGE 0{currentStage.number}: {currentStage.name.toUpperCase()}
            </span>
            <span className="font-mono text-xs text-zinc-500">({currentStage.mitreCode})</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-400">Target Host:</span>
            <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-zinc-900 text-zinc-200 border border-zinc-800">
              {currentStage.targetAsset}
            </span>
          </div>
        </div>

        <p className="text-xs text-zinc-300 leading-relaxed">
          {currentStage.description}
        </p>

        <div className="p-3 rounded bg-zinc-900/60 border border-zinc-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="space-y-0.5">
            <span className="text-[10px] uppercase font-mono text-zinc-500 block">Lead Observable Telemetry Indicator</span>
            <span className="font-mono text-zinc-200 font-semibold">{currentStage.leadIndicator}</span>
          </div>

          <button
            onClick={() => {
              const matchedAlert = alerts.find((a) => a.affectedAsset === currentStage.targetAsset) || alerts[0];
              openAlertModal(matchedAlert);
            }}
            className="px-3 py-1.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold transition-colors flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
          >
            <span>Investigate Telemetry Artifact</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
