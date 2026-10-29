import React, { useEffect, useState } from 'react';
import { Radio, ArrowRight, LoaderCircle } from 'lucide-react';
import { Link } from 'react-router-dom';

interface FeedSummary {
  catalogVersion: string | null;
  totalEntries: number;
  vulnerabilities: Array<{ cveID: string; vulnerabilityName: string; dateAdded: string }>;
}

export const LiveThreatStream: React.FC = () => {
  const [feed, setFeed] = useState<FeedSummary | null>(null);
  const [unavailable, setUnavailable] = useState(false);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const response = await fetch('/api/threat-intel', { cache: 'no-store' });
        if (!response.ok) throw new Error('Feed unavailable');
        const data = await response.json();
        if (active) {
          setFeed(data);
          setUnavailable(false);
        }
      } catch {
        if (active) setUnavailable(true);
      }
    };
    void load();
    const timer = window.setInterval(() => void load(), 15 * 60 * 1000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);

  const newest = feed?.vulnerabilities?.slice().sort((a,b) => b.dateAdded.localeCompare(a.dateAdded))[0];

  return (
    <div className="bg-zinc-950 border-y border-zinc-800/80 px-4 py-2 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs">
      <div className="flex items-center gap-2 text-cyan-300 shrink-0">
        {unavailable ? <Radio className="w-4 h-4 text-amber-400"/> : feed ? <Radio className="w-4 h-4"/> : <LoaderCircle className="w-4 h-4 animate-spin"/>}
        <span className="font-bold tracking-wider">{unavailable ? 'PUBLIC FEED UNAVAILABLE' : 'CISA PUBLIC THREAT FEED'}</span>
      </div>
      <p className="text-zinc-300 text-center truncate">
        {newest ? `Latest catalog item: ${newest.cveID} — ${newest.vulnerabilityName} · ${feed?.totalEntries} known exploited vulnerabilities in catalog` : unavailable ? 'CISA catalog could not be reached. Retry on the Global Threat Intelligence page.' : 'Loading current CISA Known Exploited Vulnerabilities catalog…'}
      </p>
      <Link to="/threat-intel" className="shrink-0 text-cyan-300 hover:text-cyan-200 inline-flex items-center gap-1">View intelligence <ArrowRight className="w-3 h-3"/></Link>
    </div>
  );
};
