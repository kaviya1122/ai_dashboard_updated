import React from 'react';
import { PlugZap, ShieldAlert } from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { NoticeBanner } from '../components/common/NoticeBanner';

export const Assets: React.FC = () => {
  const { assets } = useSecurity();
  return <div className="space-y-6">
    <NoticeBanner type="demo" customMessage="Live device protection is not connected. This page lists only devices reported by a connected endpoint or cloud security integration; it will not invent sample devices." />
    <div><h1 className="text-lg font-bold text-zinc-100">Protected Devices</h1><p className="text-xs text-zinc-400">Verified device inventory and protection state from connected sources.</p></div>
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="text-xs text-zinc-400">Connected devices</div><div className="text-2xl font-bold text-zinc-100">{assets.length}</div></div>
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="text-xs text-zinc-400">Protected</div><div className="text-2xl font-bold text-emerald-300">Not connected</div></div>
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="text-xs text-zinc-400">Containment actions confirmed</div><div className="text-2xl font-bold text-zinc-100">Not connected</div></div>
    </div>
    {assets.length ? <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden"><table className="w-full text-left text-xs"><thead className="bg-zinc-950 text-zinc-400"><tr><th className="p-3">Device</th><th className="p-3">Address</th><th className="p-3">Status</th><th className="p-3">Last seen</th></tr></thead><tbody>{assets.map(a=><tr key={a.id} className="border-t border-zinc-800"><td className="p-3 text-zinc-100">{a.name}</td><td className="p-3 font-mono">{a.ip}</td><td className="p-3">{a.status}</td><td className="p-3">{a.lastSeen}</td></tr>)}</tbody></table></div> : <div className="bg-zinc-900/70 border border-zinc-800 rounded-xl p-8 text-center space-y-3"><PlugZap className="w-8 h-8 text-cyan-400 mx-auto"/><h2 className="text-sm font-semibold text-zinc-100">No live device source connected</h2><p className="text-xs text-zinc-400 max-w-xl mx-auto">The deployed website cannot discover or protect your devices by itself. Connect an EDR/MDM or cloud inventory integration and send authenticated device events to a persistent backend before device counts, protection status, or containment actions can be reported.</p><div className="inline-flex gap-2 items-center text-[11px] text-amber-300"><ShieldAlert className="w-4 h-4"/> No device protection is currently verified by this dashboard.</div></div>}
  </div>;
};
