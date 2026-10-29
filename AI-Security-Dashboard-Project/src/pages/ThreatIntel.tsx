import React, { useEffect, useState } from 'react';
import { AlertTriangle, Clock3, ExternalLink, LoaderCircle, RefreshCw, Search, ShieldAlert } from 'lucide-react';
import { NoticeBanner } from '../components/common/NoticeBanner';

interface KevItem { cveID: string; vendorProject: string; product: string; vulnerabilityName: string; dateAdded: string; shortDescription: string; requiredAction: string; dueDate: string; knownRansomwareCampaignUse: string; }
interface KevFeed { source: string; sourceUrl: string; catalogVersion: string | null; sourceReleasedAt: string | null; totalEntries: number; fetchedAt: string; vulnerabilities: KevItem[]; }
const dateLabel = (value?: string | null) => value ? new Date(value).toLocaleString() : 'Not provided by source';

export const ThreatIntel: React.FC = () => {
  const [feed, setFeed] = useState<KevFeed | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const refresh = async () => {
    try {
      const response = await fetch('/api/threat-intel', { cache: 'no-store' });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not load the CISA catalog.');
      setFeed(data as KevFeed);
      setError('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not load public threat intelligence.');
    } finally { setLoading(false); }
  };
  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15 * 60 * 1000);
    return () => window.clearInterval(timer);
  }, []);

  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const recentCount = feed?.vulnerabilities.filter(x => new Date(x.dateAdded).getTime() >= cutoff).length ?? 0;
  const ransomwareCount = feed?.vulnerabilities.filter(x => x.knownRansomwareCampaignUse.toLowerCase() === 'known').length ?? 0;
  const filtered = (feed?.vulnerabilities || []).filter(x => {
    if (ransomwareOnly && x.knownRansomwareCampaignUse.toLowerCase() !== 'known') return false;
    return `${x.cveID} ${x.vendorProject} ${x.product} ${x.vulnerabilityName} ${x.shortDescription}`.toLowerCase().includes(query.trim().toLowerCase());
  }).sort((a,b) => b.dateAdded.localeCompare(a.dateAdded));

  return <div className="space-y-6">
    <NoticeBanner type="source" customMessage="Live public threat intelligence from CISA. The catalog describes vulnerabilities exploited somewhere in the wild; it does not monitor your devices or confirm that your systems are affected." />
    <div className="flex flex-col md:flex-row md:items-end md:justify-between gap-3">
      <div><h1 className="text-lg font-bold text-zinc-100">Global Threat Intelligence</h1><p className="text-xs text-zinc-400 mt-1">CISA Known Exploited Vulnerabilities catalog. Refresh checks for newer upstream data.</p></div>
      <button type="button" onClick={() => { setLoading(true); void refresh(); }} disabled={loading} className="inline-flex items-center gap-2 px-3 py-2 rounded border border-zinc-700 bg-zinc-900 text-xs text-zinc-200 disabled:opacity-60">
        {loading ? <LoaderCircle className="w-3.5 h-3.5 animate-spin"/> : <RefreshCw className="w-3.5 h-3.5"/>} Refresh catalog
      </button>
    </div>
    {error && <div className="flex gap-2 items-start rounded border border-amber-800 bg-amber-950/30 p-3 text-xs text-amber-200"><AlertTriangle className="w-4 h-4 shrink-0"/><div><div className="font-semibold">Public catalog unavailable</div><div className="mt-1">{error}</div></div></div>}
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="text-xs text-zinc-400">Catalog entries</div><div className="text-2xl font-bold text-zinc-100 mt-2">{feed?.totalEntries ?? '—'}</div><div className="text-[11px] text-zinc-500 mt-1">CISA known exploited vulnerabilities</div></div>
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="text-xs text-zinc-400">Added in last 7 days</div><div className="text-2xl font-bold text-amber-300 mt-2">{feed ? recentCount : '—'}</div><div className="text-[11px] text-zinc-500 mt-1">Based on CISA dateAdded</div></div>
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4"><div className="text-xs text-zinc-400">Known ransomware use</div><div className="text-2xl font-bold text-rose-300 mt-2">{feed ? ransomwareCount : '—'}</div><div className="text-[11px] text-zinc-500 mt-1">Entries flagged by CISA</div></div>
    </div>
    <div className="bg-cyan-950/20 border border-cyan-900/50 rounded-lg p-4 flex gap-3"><ShieldAlert className="w-5 h-5 text-cyan-300 shrink-0 mt-0.5"/><div><h2 className="text-xs font-semibold text-cyan-200">Rule-based feed analysis</h2><p className="text-xs text-zinc-300 mt-1">{feed ? `${recentCount} catalog entries were added in the last 7 days. ${ransomwareCount} are marked as associated with known ransomware campaigns. Check your actual software inventory before treating any entry as applicable to you.` : 'Load the public catalog to calculate recent additions and ransomware-associated entries.'}</p></div></div>
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="p-4 border-b border-zinc-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2"><div><h2 className="text-sm font-semibold text-zinc-100">Known Exploited Vulnerabilities</h2><p className="text-[11px] text-zinc-500 mt-1">Catalog version {feed?.catalogVersion || '—'} · released {dateLabel(feed?.sourceReleasedAt)}</p></div><div className="text-[10px] text-zinc-500 inline-flex items-center gap-1"><Clock3 className="w-3 h-3"/>Retrieved {dateLabel(feed?.fetchedAt)}</div></div>
        <div className="flex flex-col sm:flex-row gap-2"><label className="flex flex-1 items-center gap-2 px-3 py-2 rounded bg-zinc-950 border border-zinc-800"><Search className="w-4 h-4 text-zinc-500"/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Search CVE, vendor, product..." className="bg-transparent outline-none text-xs text-zinc-100 w-full"/></label><button type="button" onClick={()=>setRansomwareOnly(v=>!v)} className={`px-3 py-2 rounded border text-xs ${ransomwareOnly?'border-rose-700 bg-rose-950/50 text-rose-200':'border-zinc-700 bg-zinc-950 text-zinc-300'}`}>{ransomwareOnly?'Showing ransomware-related':'Filter ransomware-related'}</button></div>
      </div>
      <div className="divide-y divide-zinc-800">
        {filtered.slice(0,100).map(item=><article key={item.cveID} className="p-4 space-y-2">
          <div className="flex flex-wrap items-center gap-2"><span className="font-mono font-bold text-cyan-300 text-xs">{item.cveID}</span><span className="text-[10px] px-2 py-0.5 rounded border border-red-900 bg-red-950/40 text-red-300">Known exploited</span>{item.knownRansomwareCampaignUse.toLowerCase()==='known'&&<span className="text-[10px] px-2 py-0.5 rounded border border-rose-900 bg-rose-950/40 text-rose-300">Known ransomware use</span>}<span className="ml-auto text-[10px] text-zinc-500">Added {item.dateAdded}</span></div>
          <h3 className="text-sm font-semibold text-zinc-100">{item.vulnerabilityName}</h3><p className="text-xs text-zinc-400">{item.vendorProject} · {item.product}</p><p className="text-xs text-zinc-300 leading-relaxed">{item.shortDescription}</p><p className="text-[11px] text-amber-200"><strong>Recommended action:</strong> {item.requiredAction}</p><p className="text-[10px] text-zinc-500">CISA remediation due date: {item.dueDate}</p>
        </article>)}
        {loading && !feed && <div className="p-8 text-center text-xs text-zinc-400">Loading public catalog…</div>}
        {!loading && feed && filtered.length===0 && <div className="p-8 text-center text-xs text-zinc-500">No entries match this search.</div>}
      </div>
      {feed && filtered.length>100 && <div className="p-3 text-center text-[11px] text-zinc-500 border-t border-zinc-800">Showing 100 of {filtered.length} matching entries. Refine your search to find a specific item.</div>}
    </div>
    <div className="text-[11px] text-zinc-500">Source: <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noreferrer" className="text-cyan-300 hover:underline">CISA KEV Catalog <ExternalLink className="inline w-3 h-3"/></a>. This dataset does not replace endpoint monitoring or a scan of your own software.</div>
  </div>;
};
