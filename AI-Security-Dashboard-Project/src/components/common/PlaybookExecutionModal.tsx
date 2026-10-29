/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  X,
  Server,
  Network,
  Key,
  Terminal,
  Clock,
} from 'lucide-react';
import { useSecurity } from '../../context/SecurityContext';

export interface PlaybookExecutionModalProps {
  isOpen: boolean;
  onClose: () => void;
  targetAssetDefault?: string;
}

export const PlaybookExecutionModal: React.FC<PlaybookExecutionModalProps> = ({
  isOpen,
  onClose,
  targetAssetDefault = 'DB-PROD-01',
}) => {
  const { logActivity, assets } = useSecurity();

  const [selectedPlaybook, setSelectedPlaybook] = useState<'quarantine' | 'sinkhole' | 'kerberos_revoke' | 'ram_dump'>('quarantine');
  const [targetAsset, setTargetAsset] = useState<string>(targetAssetDefault);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [isCompleted, setIsCompleted] = useState(false);

  if (!isOpen) return null;

  const playbooks = [
    {
      id: 'quarantine' as const,
      name: 'SOAR-PB-01: Endpoint VLAN Isolation',
      icon: Server,
      desc: 'Sever non-management VLAN switch ports and enforce zero-trust endpoint quarantine.',
      steps: ['Identify switch port & MAC address', 'Apply quarantine VLAN tag 999', 'Verify ping cutoff', 'Notify NOC duty officer'],
    },
    {
      id: 'sinkhole' as const,
      name: 'SOAR-PB-02: BGP Null-Route & DNS Sinkhole',
      icon: Network,
      desc: 'Blackhole destination IP 198.51.100.89 at perimeter routers and redirect DNS to honeynet.',
      steps: ['BGP community announcement (RFC 7999)', 'Bind IP to null0 interface', 'Update DNS resolver response-policy zone', 'Flush local DNS cache'],
    },
    {
      id: 'kerberos_revoke' as const,
      name: 'SOAR-PB-03: Kerberos TGT Ticket Invalidation',
      icon: Key,
      desc: 'Force immediate Kerberos krbtgt rotation and reset targeted administrator account hashes.',
      steps: ['Query DC-CORE-01 Kerberos state', 'Purge active TGT sessions for flagged accounts', 'Force password change flag in Active Directory', 'Log to Security Event 4768 audit'],
    },
    {
      id: 'ram_dump' as const,
      name: 'SOAR-PB-04: Volatile RAM Forensics Capture',
      icon: Terminal,
      desc: 'Stream raw memory dump via LiME kernel module or WinPmem to secure forensic storage.',
      steps: ['Verify agent RAM write permissions', 'Initialize memory acquisition snapshot', 'Compute SHA256 dump checksum', 'Transfer raw memory to GCP Storage Vault'],
    },
  ];

  const activePB = playbooks.find((p) => p.id === selectedPlaybook) || playbooks[0];

  const handleRunPlaybook = () => {
    setIsRunning(true);
    setProgress(15);
    setIsCompleted(false);
    setConsoleLogs([`[SOAR Orchestrator] Initializing ${activePB.name}...`, `[Target Scope] Target: ${targetAsset}`]);

    setTimeout(() => {
      setProgress(40);
      setConsoleLogs((prev) => [...prev, `[Step 1] ${activePB.steps[0]} - Completed.`]);
    }, 600);

    setTimeout(() => {
      setProgress(75);
      setConsoleLogs((prev) => [...prev, `[Step 2] ${activePB.steps[1]} - Completed.`, `[Step 3] ${activePB.steps[2]} - Completed.`]);
    }, 1200);

    setTimeout(() => {
      setProgress(100);
      setConsoleLogs((prev) => [
        ...prev,
        `[Step 4] ${activePB.steps[3]} - Completed.`,
        `[SUCCESS] Playbook ${activePB.name} executed successfully. Containment verified.`,
      ]);
      setIsRunning(false);
      setIsCompleted(true);
      logActivity(`Executed automated playbook ${activePB.name} on ${targetAsset}`, 'SOAR Playbooks', 'critical');
    }, 1800);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs overflow-y-auto"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-full max-w-2xl bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden flex flex-col my-auto">
        {/* Header */}
        <div className="px-6 py-4 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <div>
              <h2 className="text-sm font-bold text-zinc-100 uppercase tracking-wider">
                Automated Containment & SOAR Playbooks
              </h2>
              <p className="text-[11px] text-zinc-400">
                1-Click instant defensive actions executed via agent orchestrator
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            aria-label="Close Playbook Modal"
            className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 text-xs">
          {/* Target Selection */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="font-semibold text-zinc-300">Target Host / IP</label>
              <select
                value={targetAsset}
                onChange={(e) => setTargetAsset(e.target.value)}
                className="w-full bg-zinc-900 border border-zinc-800 rounded px-3 py-2 text-zinc-200 font-mono focus:outline-none focus:border-cyan-500"
              >
                {assets.map((a) => (
                  <option key={a.id} value={a.name}>
                    {a.name} ({a.ip}) - {a.criticality.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1">
              <label className="font-semibold text-zinc-300">Approval Authorization</label>
              <div className="p-2 rounded bg-zinc-900/60 border border-zinc-800 font-mono text-[11px] text-zinc-300 flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>Pre-Approved SOC Emergency ROE</span>
              </div>
            </div>
          </div>

          {/* Playbook Cards Grid */}
          <div className="space-y-2">
            <span className="font-mono text-[10px] uppercase font-bold text-zinc-400">
              Select Defensive Action Playbook
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {playbooks.map((pb) => {
                const Icon = pb.icon;
                const isSelected = selectedPlaybook === pb.id;
                return (
                  <button
                    key={pb.id}
                    type="button"
                    onClick={() => {
                      setSelectedPlaybook(pb.id);
                      setIsCompleted(false);
                      setConsoleLogs([]);
                    }}
                    className={`text-left p-3 rounded-lg border transition-all ${
                      isSelected
                        ? 'bg-zinc-850 border-cyan-500/80 shadow-md ring-1 ring-cyan-500/40'
                        : 'bg-zinc-900/60 border-zinc-800 hover:bg-zinc-850 hover:border-zinc-700'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Icon className={`w-4 h-4 ${isSelected ? 'text-cyan-400' : 'text-zinc-400'}`} />
                      <span className="font-bold text-zinc-200 text-xs truncate">{pb.name}</span>
                    </div>
                    <p className="text-[11px] text-zinc-400 line-clamp-2 leading-relaxed">{pb.desc}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Playbook Steps Preview */}
          <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 space-y-2 font-mono text-xs">
            <span className="text-[10px] text-zinc-500 uppercase block">Execution Workflow</span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
              {activePB.steps.map((st, i) => (
                <div key={i} className="p-2 rounded bg-zinc-900 border border-zinc-800/80 space-y-1">
                  <span className="text-cyan-400 font-bold block">0{i + 1}</span>
                  <span className="text-zinc-300 line-clamp-2">{st}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Real-time Execution Console Output */}
          {consoleLogs.length > 0 && (
            <div className="p-3 rounded-lg bg-black border border-zinc-800 font-mono text-[11px] space-y-1 max-h-36 overflow-y-auto">
              {consoleLogs.map((log, i) => (
                <p key={i} className={log.includes('SUCCESS') ? 'text-emerald-400 font-bold' : 'text-zinc-300'}>
                  {log}
                </p>
              ))}
            </div>
          )}

          {/* Progress bar */}
          {isRunning && (
            <div className="space-y-1">
              <div className="flex justify-between text-[11px] font-mono text-zinc-400">
                <span>Executing Automated Containment Pipeline...</span>
                <span>{progress}%</span>
              </div>
              <div className="h-2 w-full bg-zinc-900 rounded-full overflow-hidden border border-zinc-800">
                <div style={{ width: `${progress}%` }} className="h-full bg-cyan-500 transition-all duration-300" />
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-zinc-900 border-t border-zinc-800 flex items-center justify-between">
          <span className="text-[11px] font-mono text-zinc-500">
            Audit logging: Permanent SOC ledger
          </span>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs"
            >
              Close
            </button>

            <button
              type="button"
              disabled={isRunning || isCompleted}
              onClick={handleRunPlaybook}
              className="px-4 py-1.5 rounded-md bg-red-600 hover:bg-red-500 text-white font-semibold text-xs flex items-center gap-1.5 shadow-md shadow-red-950 disabled:opacity-50"
            >
              {isRunning ? (
                <>
                  <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                  <span>Executing...</span>
                </>
              ) : isCompleted ? (
                <>
                  <CheckCircle2 className="w-3.5 h-3.5 text-white" />
                  <span>Containment Active</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Execute Playbook Now</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
