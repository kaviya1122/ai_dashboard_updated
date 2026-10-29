/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { ShieldCheck, Info, AlertTriangle } from 'lucide-react';

interface NoticeBannerProps {
  type?: 'demo' | 'scope' | 'ai_disclaimer' | 'verified' | 'source';
  customMessage?: string;
}

export const NoticeBanner: React.FC<NoticeBannerProps> = ({
  type = 'demo',
  customMessage,
}) => {
  if (type === 'demo') {
    return (
      <div className="flex items-center gap-2.5 px-3.5 py-2 bg-zinc-900 border border-zinc-800 text-xs text-zinc-300 rounded-md">
        <span className="px-1.5 py-0.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider bg-zinc-800 text-zinc-300 border border-zinc-700">
          DEMO DATA
        </span>
        <span className="text-zinc-400">
          {customMessage ||
            'Showing realistic SOC incident telemetry and simulated asset records for analyst demonstration.'}
        </span>
      </div>
    );
  }

  if (type === 'source') {
    return (
      <div className="flex items-center gap-2.5 px-3.5 py-2 bg-cyan-950/30 border border-cyan-900/50 text-xs text-cyan-100 rounded-md">
        <Info className="w-4 h-4 text-cyan-300 shrink-0" aria-hidden="true" />
        <span className="px-1.5 py-0.5 rounded font-mono text-[10px] font-bold uppercase tracking-wider bg-cyan-950 text-cyan-200 border border-cyan-800">PUBLIC SOURCE</span>
        <span className="text-zinc-300">{customMessage || 'Information retrieved from a public threat-intelligence source.'}</span>
      </div>
    );
  }

  if (type === 'scope') {
    return (
      <div className="flex items-start gap-2.5 px-3.5 py-2.5 bg-amber-950/30 border border-amber-900/50 text-xs text-amber-200/90 rounded-md">
        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" aria-hidden="true" />
        <div>
          <span className="font-semibold text-amber-300">Target Authorization Bound: </span>
          <span>
            {customMessage ||
              'Inspection is restricted to explicitly authorized targets: RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), localhost (127.0.0.1), or sandbox lab ranges (198.51.100.0/24). Public internet IP ranges are strictly prohibited without written consent.'}
          </span>
        </div>
      </div>
    );
  }

  if (type === 'ai_disclaimer') {
    return (
      <div className="flex items-start gap-2.5 px-3.5 py-2.5 bg-blue-950/30 border border-blue-900/50 text-xs text-blue-200/90 rounded-md">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" aria-hidden="true" />
        <div>
          <span className="font-semibold text-blue-300">AI Assistance Operational Notice: </span>
          <span>
            {customMessage ||
              'AI Security Copilot provides heuristic triage assistance and containment hypotheses. AI output does not constitute authoritative legal or forensic verdicts; on-duty analysts must verify raw telemetry prior to executing operational isolation.'}
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2.5 px-3.5 py-2 bg-emerald-950/30 border border-emerald-900/50 text-xs text-emerald-200 rounded-md">
      <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" aria-hidden="true" />
      <span>{customMessage || 'Verified SOC telemetry pipeline active.'}</span>
    </div>
  );
};
