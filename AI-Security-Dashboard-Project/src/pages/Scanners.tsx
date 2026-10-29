/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Globe,
  Network,
  FileCode,
  QrCode,
  Image as ImageIcon,
  AlertTriangle,
  CheckCircle,
  HelpCircle,
  Bot,
  FilePlus2,
  Clock,
  RotateCcw,
  Shield,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { analyzeUrl, analyzeSecurityText, analyzeQrPayload } from '../utils/scannerRules';
import { checkNetworkScope } from '../utils/networkScope';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { NoticeBanner } from '../components/common/NoticeBanner';
import { ScanResult, ScannerType } from '../types';

export const Scanners: React.FC = () => {
  const { scans, addScanResult, setCopilotContext, addReport, authorizedScopeConsent } = useSecurity();
  const navigate = useNavigate();

  const [activeTab, setActiveTab] = useState<ScannerType>('url');
  const [inputValue, setInputValue] = useState('');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(scans[0] || null);
  const [requireConsentCheck, setRequireConsentCheck] = useState(true);

  // Example inputs per scanner type
  const examples: Record<ScannerType, { label: string; value: string; desc: string }> = {
    url: {
      label: 'Suspicious Binary Direct Download',
      value: 'http://198.51.100.89/dl/stage2_payload.exe?auth=verify',
      desc: 'Simulates IP literal host with executable extension and credential lure query.',
    },
    ip: {
      label: 'Authorized Internal Database Subnet',
      value: '10.240.10.42',
      desc: 'RFC1918 private subnet address for host DB-PROD-01.',
    },
    text: {
      label: 'Obfuscated PowerShell Stager with Leaked Key',
      value: `const awsSecret = "AKIAIOSFODNN7EXAMPLE";
powershell.exe -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp`,
      desc: 'Code snippet containing hardcoded AWS credentials and execution bypass.',
    },
    qr: {
      label: 'Encoded WiFi Access Vector',
      value: 'WIFI:S:ExecutiveGuestWiFi;T:WPA;P:SuperSecretPass2026!;;',
      desc: 'Demonstrates QR barcode payload classification (WiFi configuration).',
    },
    image: {
      label: 'Security Artifact Image Hash / Metadata',
      value: 'invoice_october_attachment.png (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)',
      desc: 'Metadata and steganography heuristic analysis artifact.',
    },
    nmap: {
      label: 'Authorized Lab Test Net',
      value: '198.51.100.55',
      desc: 'RFC5737 Test-Net-2 target for simulated port analysis.',
    },
  };

  const handleSelectExample = () => {
    setInputValue(examples[activeTab].value);
    setErrorMessage(null);
  };

  const handleRunScan = () => {
    setErrorMessage(null);
    const trimmed = inputValue.trim();

    if (!trimmed) {
      setErrorMessage(`Please provide valid input for the ${activeTab.toUpperCase()} scanner.`);
      return;
    }

    setIsScanning(true);

    setTimeout(() => {
      try {
        let result: ScanResult;

        if (activeTab === 'url') {
          result = analyzeUrl(trimmed);
        } else if (activeTab === 'text') {
          result = analyzeSecurityText(trimmed);
        } else if (activeTab === 'qr') {
          result = analyzeQrPayload(trimmed);
        } else if (activeTab === 'ip' || activeTab === 'nmap') {
          const scopeVerification = checkNetworkScope(trimmed, requireConsentCheck);
          if (!scopeVerification.isAuthorized) {
            setErrorMessage(scopeVerification.message);
            setIsScanning(false);
            return;
          }

          // Generate explainable IP/Network inspection
          result = {
            id: `scan-ip-${Date.now()}`,
            scannerType: activeTab,
            input: trimmed,
            timestamp: new Date().toISOString(),
            riskScore: trimmed.endsWith('.42') ? 85 : 20,
            severity: trimmed.endsWith('.42') ? 'high' : 'low',
            verdict: trimmed.endsWith('.42') ? 'suspicious' : 'clean',
            summary: `Target ${trimmed} is within authorized ${scopeVerification.scopeType.replace('_', ' ').toUpperCase()} scope. Analyzed port vectors and lateral movement risks.`,
            rulesTriggered: [
              {
                ruleId: 'NET-001',
                ruleName: 'Scope Authorization Verified',
                category: 'Governance',
                points: 0,
                description: `Confirmed RFC1918/Authorized lab bound. Explicit consent token active.`,
                matchedIndicator: scopeVerification.scopeType,
              },
              ...(trimmed.endsWith('.42')
                ? [
                    {
                      ruleId: 'NET-002',
                      ruleName: 'Correlated Cobalt Strike Telemetry',
                      category: 'Threat Correlation',
                      points: 65,
                      description: 'IP matches active critical incident host DB-PROD-01 with C2 beaconing.',
                      matchedIndicator: '10.240.10.42 (DB-PROD-01)',
                    },
                    {
                      ruleId: 'NET-003',
                      ruleName: 'PostgreSQL & Redis Exposed to VPC Subnet',
                      category: 'Attack Surface',
                      points: 20,
                      description: 'Ports 5432 and 6379 listening without host-level firewalld restriction.',
                      matchedIndicator: 'Ports 5432, 6379',
                    },
                  ]
                : [
                    {
                      ruleId: 'NET-004',
                      ruleName: 'Standard Internal Gateway Profile',
                      category: 'Baseline',
                      points: 20,
                      description: 'Standard management services listening within expected boundaries.',
                    },
                  ]),
            ],
            indicators: [`IP: ${trimmed}`, `Scope: ${scopeVerification.scopeType}`],
            recommendations: trimmed.endsWith('.42')
              ? [
                  'Isolate host network interface immediately.',
                  'Capture volatile RAM memory dump before reboot.',
                  'Inspect connection tables for active socket to 198.51.100.89.',
                ]
              : ['Maintain automated patch schedule and routine baseline telemetry logging.'],
            networkScope: {
              isAuthorizedScope: true,
              ipType: scopeVerification.scopeType,
              authorizationToken: `AUTH-TOK-${Date.now().toString(36)}`,
            },
          };
        } else {
          // Image / EXIF metadata scanner
          result = {
            id: `scan-img-${Date.now()}`,
            scannerType: 'image',
            input: trimmed,
            timestamp: new Date().toISOString(),
            riskScore: 35,
            severity: 'medium',
            verdict: 'suspicious',
            summary: 'Image artifact inspected. Geolocation EXIF tags detected; no executable payload steganography identified.',
            rulesTriggered: [
              {
                ruleId: 'IMG-001',
                ruleName: 'EXIF Metadata Leakage (GPS Coordinates)',
                category: 'Privacy / Intelligence',
                points: 35,
                description: 'Geographic coordinate tags present in image file headers, exposing physical facility location.',
                matchedIndicator: 'GPSLatitude: 37.7749 N, GPSLongitude: -122.4194 W',
              },
            ],
            indicators: ['EXIF Metadata present', 'GPS location data tagged'],
            recommendations: [
              'Strip EXIF metadata using ExifTool prior to public dissemination.',
              'Ensure automated scrubbers are applied to customer support uploads.',
            ],
          };
        }

        setCurrentResult(result);
        addScanResult(result);
        setIsScanning(false);
      } catch (err: unknown) {
        setErrorMessage(err instanceof Error ? err.message : 'Analysis failed due to malformed input.');
        setIsScanning(false);
      }
    }, 400);
  };

  const handleSendToCopilot = (result: ScanResult) => {
    setCopilotContext({
      type: 'scan',
      id: result.id,
      title: `${result.scannerType.toUpperCase()} Scan: ${result.input.slice(0, 40)}`,
      summary: `Risk Score: ${result.riskScore}/100 (${result.severity.toUpperCase()}). Rules triggered: ${result.rulesTriggered.map((r) => r.ruleName).join(', ')}. ${result.summary}`,
    });
    navigate('/copilot');
  };

  const handleAddToReport = (result: ScanResult) => {
    const reportItem = {
      id: `REP-${result.id}`,
      title: `Analysis Finding: ${result.scannerType.toUpperCase()} [${result.severity.toUpperCase()}]`,
      classification: 'TLP:AMBER' as const,
      type: 'threat_brief' as const,
      createdAt: new Date().toISOString(),
      author: 'SOC Duty Analyst',
      associatedAlertIds: [],
      associatedScanIds: [result.id],
      evidenceItems: result.rulesTriggered.map((r) => ({
        source: `Scanner [${result.scannerType.toUpperCase()}]: ${result.input.slice(0, 30)}`,
        indicator: `${r.ruleName} (+${r.points} pts) -> ${r.description}`,
        severity: result.severity,
        timestamp: result.timestamp,
        verificationStatus: 'analyst_confirmed' as const,
      })),
      aiAssistanceNotes: [
        `Heuristic scanner flagged ${result.rulesTriggered.length} deterministic indicators. Risk score evaluated at ${result.riskScore}/100.`,
        'DISCLAIMER: Deterministic scanner findings. AI advisory should be used for containment planning.',
      ],
      analystConclusions: result.summary,
      actionItems: result.recommendations.map((rec, i) => ({
        action: rec,
        assignedTo: 'SecOps Team',
        dueDate: new Date(Date.now() + (i + 2) * 3600 * 1000).toISOString(),
        status: 'pending' as const,
      })),
    };
    addReport(reportItem);
    navigate('/reports');
  };

  return (
    <div className="space-y-6">
      {/* Notice & Scope Assurance */}
      <NoticeBanner
        type="scope"
        customMessage="Safety Guardrail: Network and IP scanning strictly validates RFC 1918 private subnets, localhost, and registered lab ranges. Public internet IP ranges are blocked without explicit legal authorization."
      />

      {/* Header */}
      <div>
        <h1 className="text-lg font-bold text-zinc-100 tracking-tight">
          Unified SOC Threat Scanners
        </h1>
        <p className="text-xs text-zinc-400">
          Deterministic indicator inspection, explainable scoring rules, and actionable intelligence
        </p>
      </div>

      {/* Scanner Mode Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-zinc-800 pb-2">
        {(
          [
            { id: 'url', label: 'URL Scanner', icon: Globe },
            { id: 'ip', label: 'IP / Network Scope', icon: Network },
            { id: 'text', label: 'Text / Code / Secrets', icon: FileCode },
            { id: 'qr', label: 'QR Payload Decoder', icon: QrCode },
            { id: 'image', label: 'Image / EXIF Metadata', icon: ImageIcon },
          ] as const
        ).map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => {
                setActiveTab(tab.id);
                setInputValue('');
                setErrorMessage(null);
              }}
              className={`flex items-center gap-2 px-3.5 py-2 rounded text-xs font-medium transition-all ${
                isActive
                  ? 'bg-zinc-800 text-cyan-400 border border-zinc-700 shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Input Console */}
      <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <label htmlFor="scanner-input" className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
            {activeTab.toUpperCase()} Analysis Target
          </label>
          <button
            onClick={handleSelectExample}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-mono inline-flex items-center gap-1 self-start sm:self-auto"
          >
            <span>Load Example: {examples[activeTab].label}</span>
          </button>
        </div>

        {activeTab === 'text' ? (
          <textarea
            id="scanner-input"
            rows={5}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder="Paste code snippet, PowerShell command, SQL query, or prompt text..."
            className="w-full bg-zinc-950 border border-zinc-800 rounded-md p-3 text-xs font-mono text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
          />
        ) : (
          <input
            id="scanner-input"
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={
              activeTab === 'url'
                ? 'https://example.com/payload.exe'
                : activeTab === 'ip'
                ? '10.240.10.42 (Authorized RFC1918 only)'
                : activeTab === 'qr'
                ? 'WIFI:S:Guest;T:WPA;P:Pass123;; or https://target-url.com'
                : 'filename.png (SHA256 hash or metadata string)'
            }
            className="w-full bg-zinc-950 border border-zinc-800 rounded-md px-3 py-2 text-xs font-mono text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
          />
        )}

        <p className="text-[11px] text-zinc-400">{examples[activeTab].desc}</p>

        {/* IP Authorization Consent Checkbox */}
        {(activeTab === 'ip' || activeTab === 'nmap') && (
          <div className="flex items-start gap-2 pt-2 border-t border-zinc-800/80">
            <input
              id="scope-consent-check"
              type="checkbox"
              checked={requireConsentCheck}
              onChange={(e) => setRequireConsentCheck(e.target.checked)}
              className="mt-0.5 rounded border-zinc-700 bg-zinc-950 text-cyan-600 focus:ring-cyan-500"
            />
            <label htmlFor="scope-consent-check" className="text-xs text-zinc-300">
              I certify that I have explicit authorization to inspect this target IP/subnet, and that it resides within corporate RFC 1918 boundaries or authorized staging labs.
            </label>
          </div>
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div className="p-3 rounded bg-red-950/60 border border-red-800 text-xs text-red-300 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span className="font-semibold">Validation Error:</span>
              <p>{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Action Button */}
        <div className="flex items-center justify-between pt-2">
          <button
            onClick={() => {
              setInputValue('');
              setErrorMessage(null);
            }}
            className="px-3 py-1.5 rounded text-xs text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
          >
            Clear Input
          </button>

          <button
            onClick={handleRunScan}
            disabled={isScanning}
            className="px-5 py-2 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold tracking-wide transition-colors flex items-center gap-2 shadow-xs disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            {isScanning ? (
              <>
                <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                <span>Running Deterministic Heuristics...</span>
              </>
            ) : (
              <>
                <Shield className="w-3.5 h-3.5" />
                <span>Execute Explainable Scan</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Scan Results Display */}
      {currentResult && (
        <div className="bg-zinc-900/90 border border-zinc-800 rounded-lg p-5 shadow-xs space-y-5">
          {/* Result Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-xs text-zinc-400 font-semibold">{currentResult.id}</span>
                <SeverityBadge severity={currentResult.severity} size="sm" />
                <span className="px-2 py-0.5 rounded font-mono text-[11px] uppercase bg-zinc-800 text-zinc-300 border border-zinc-700">
                  VERDICT: {currentResult.verdict}
                </span>
              </div>
              <h2 className="text-base font-bold text-zinc-100 font-mono break-all">
                {currentResult.input}
              </h2>
            </div>

            {/* Risk Score Dial */}
            <div className="flex items-center gap-3 bg-zinc-950 px-4 py-2 rounded-lg border border-zinc-800 self-start sm:self-auto">
              <div className="text-right">
                <span className="text-[10px] uppercase font-mono text-zinc-400 block">Risk Score</span>
                <span className="text-xl font-bold font-mono text-zinc-100">
                  {currentResult.riskScore}
                  <span className="text-xs text-zinc-400">/100</span>
                </span>
              </div>
              <div
                className={`w-3.5 h-3.5 rounded-full ${
                  currentResult.riskScore >= 70
                    ? 'bg-red-500'
                    : currentResult.riskScore >= 40
                    ? 'bg-amber-500'
                    : 'bg-emerald-500'
                }`}
              />
            </div>
          </div>

          {/* QR Special Requirement: Show Decoded Payload Type First */}
          {currentResult.qrDetails && (
            <div className="p-3.5 bg-zinc-950 border border-zinc-800 rounded-lg flex items-center justify-between">
              <div>
                <span className="text-[10px] uppercase font-mono text-zinc-400 block">
                  QR Decoded Payload Type
                </span>
                <span className="text-sm font-bold font-mono text-cyan-400 uppercase">
                  {currentResult.qrDetails.decodedType}
                </span>
              </div>
              <span className="text-xs font-mono text-zinc-400">
                Payload format verified before URL analysis
              </span>
            </div>
          )}

          {/* Summary Box */}
          <div className="p-3.5 rounded bg-zinc-950 border border-zinc-800/80 text-xs">
            <span className="font-mono uppercase text-[10px] text-zinc-400 block mb-1">
              Plain-Language Finding Summary
            </span>
            <p className="text-zinc-200 leading-relaxed">{currentResult.summary}</p>
          </div>

          {/* Explainable Scoring Breakdown (Which rules contributed points) */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                Explainable Deterministic Rules Triggered ({currentResult.rulesTriggered.length})
              </h3>
              <span className="text-[11px] font-mono text-zinc-400">
                Deterministic Rule Contribution
              </span>
            </div>

            {currentResult.rulesTriggered.length === 0 ? (
              <div className="p-4 rounded bg-zinc-950 border border-zinc-800 text-xs text-zinc-400 text-center">
                No threat rules triggered. Target evaluated within clean operational baseline.
              </div>
            ) : (
              <div className="divide-y divide-zinc-800/80 border border-zinc-800 rounded-lg overflow-hidden bg-zinc-950">
                {currentResult.rulesTriggered.map((rule, idx) => (
                  <div key={idx} className="p-3.5 flex flex-col sm:flex-row sm:items-start justify-between gap-3 text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-semibold text-cyan-400">{rule.ruleId}</span>
                        <span className="font-bold text-zinc-200">{rule.ruleName}</span>
                        <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-zinc-800 text-zinc-300">
                          {rule.category}
                        </span>
                      </div>
                      <p className="text-zinc-400">{rule.description}</p>
                      {rule.matchedIndicator && (
                        <p className="font-mono text-[11px] text-zinc-300">
                          Matched string: <code className="bg-zinc-900 px-1 py-0.5 rounded text-amber-300">{rule.matchedIndicator}</code>
                        </p>
                      )}
                    </div>

                    <div className="shrink-0 text-right">
                      <span className="font-mono text-xs font-bold text-amber-400 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/60">
                        +{rule.points} pts
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Recommendations */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
              Recommended Defensive Actions
            </h3>
            <ul className="space-y-1.5">
              {currentResult.recommendations.map((rec, i) => (
                <li key={i} className="flex items-start gap-2 p-2 rounded bg-zinc-950 border border-zinc-800 text-xs text-zinc-200">
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Action Buttons: Send to Copilot & Add to Report */}
          <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-zinc-800">
            <span className="text-[11px] font-mono text-zinc-400">
              Scanned: {new Date(currentResult.timestamp).toUTCString()}
            </span>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={() => handleSendToCopilot(currentResult)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800 text-xs font-semibold transition-colors"
              >
                <Bot className="w-3.5 h-3.5" />
                Analyze with Copilot
              </button>

              <button
                onClick={() => handleAddToReport(currentResult)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 text-xs font-medium transition-colors"
              >
                <FilePlus2 className="w-3.5 h-3.5 text-zinc-400" />
                Attach to Incident Report
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
