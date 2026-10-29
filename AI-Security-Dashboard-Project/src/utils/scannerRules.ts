/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { RuleMatch, ScanResult, ScannerType, SeverityLevel } from '../types';

/**
 * Calculates severity level based on a normalized 0-100 risk score
 */
export function scoreToSeverity(score: number): SeverityLevel {
  if (score >= 90) return 'critical';
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 15) return 'low';
  return 'info';
}

/**
 * Derives a categorical verdict from score and triggered rules
 */
export function scoreToVerdict(score: number): 'clean' | 'suspicious' | 'malicious' | 'unknown' {
  if (score >= 70) return 'malicious';
  if (score >= 35) return 'suspicious';
  return 'clean';
}

/**
 * Analyzes a URL with explainable deterministic rules
 */
export function analyzeUrl(rawUrl: string): ScanResult {
  const rules: RuleMatch[] = [];
  const indicators: string[] = [];
  const recommendations: string[] = [];

  let normalized = rawUrl.trim();
  if (!normalized) {
    throw new Error('URL input cannot be empty.');
  }

  // Prepend protocol if missing to parse safely
  if (!/^https?:\/\//i.test(normalized)) {
    normalized = 'http://' + normalized;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error('Invalid URL format. Please provide a valid hostname or web address.');
  }

  const hostname = parsed.hostname.toLowerCase();
  const pathname = parsed.pathname.toLowerCase();
  const search = parsed.search.toLowerCase();
  const full = parsed.href.toLowerCase();

  // Rule 1: IP Literal Hostname (often used to evade domain blocklists)
  const isIpv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  if (isIpv4) {
    rules.push({
      ruleId: 'URL-001',
      ruleName: 'IP Literal Host',
      category: 'Evasion',
      points: 40,
      description: 'Host is an IP address instead of a domain name, commonly used in drive-by downloads and phishing.',
      matchedIndicator: hostname,
    });
    indicators.push(`Direct IP access: ${hostname}`);
    recommendations.push('Block direct IP destination in perimeter proxy; enforce FQDN resolution.');
  }

  // Rule 2: High-risk TLDs
  const suspiciousTlds = ['.top', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.click', '.loan', '.country'];
  const matchedTld = suspiciousTlds.find((tld) => hostname.endsWith(tld));
  if (matchedTld) {
    rules.push({
      ruleId: 'URL-002',
      ruleName: 'High Abuse TLD',
      category: 'Reputation',
      points: 25,
      description: `Domain uses top-level domain ${matchedTld} with elevated incidence of disposable malicious campaigns.`,
      matchedIndicator: matchedTld,
    });
    indicators.push(`Suspicious TLD: ${matchedTld}`);
  }

  // Rule 3: Phishing / Credential Harvesting Keywords
  const credKeywords = ['login', 'signin', 'verify', 'account', 'banking', 'secure', 'wallet', 'update', 'portal', 'auth', 'recover'];
  const matchedCreds = credKeywords.filter((kw) => hostname.includes(kw) || pathname.includes(kw));
  if (matchedCreds.length > 0 && !hostname.includes('google.com') && !hostname.includes('microsoft.com') && !hostname.includes('apple.com')) {
    rules.push({
      ruleId: 'URL-003',
      ruleName: 'Credential Lure Keywords',
      category: 'Phishing',
      points: Math.min(35, matchedCreds.length * 15),
      description: `Target contains authentication lure keywords (${matchedCreds.join(', ')}) on an unverified domain.`,
      matchedIndicator: matchedCreds.join(', '),
    });
    indicators.push(`Lure keywords: ${matchedCreds.join(', ')}`);
    recommendations.push('Inspect domain WHOIS age and enforce Multi-Factor Authentication if accessed by corporate staff.');
  }

  // Rule 4: Suspicious executable or script file extensions in path
  const dangerousExts = ['.exe', '.scr', '.vbs', '.bat', '.ps1', '.iso', '.zip', '.tar.gz', '.dll', '.hta'];
  const matchedExt = dangerousExts.find((ext) => pathname.endsWith(ext));
  if (matchedExt) {
    rules.push({
      ruleId: 'URL-004',
      ruleName: 'Direct Binary / Script Payload Target',
      category: 'Malware Delivery',
      points: 45,
      description: `Path points directly to an executable or archive extension (${matchedExt}).`,
      matchedIndicator: matchedExt,
    });
    indicators.push(`Payload extension: ${matchedExt}`);
    recommendations.push('Quarantine download artifact; perform sandbox dynamic behavioral inspection before execution.');
  }

  // Rule 5: Open redirect parameters
  const redirectParams = ['redirect=', 'url=', 'next=', 'dest=', 'target=', 'return='];
  const matchedRedirect = redirectParams.find((param) => search.includes(param));
  if (matchedRedirect) {
    rules.push({
      ruleId: 'URL-005',
      ruleName: 'Potential Open Redirect Vector',
      category: 'Web Vulnerability',
      points: 20,
      description: `URL contains redirection parameter (${matchedRedirect}) susceptible to bypass phishing filters.`,
      matchedIndicator: matchedRedirect,
    });
    indicators.push(`Redirect parameter detected: ${matchedRedirect}`);
  }

  // Rule 6: Excessive Subdomain Depth or High Entropy (excluding IP literals)
  const subdomains = hostname.split('.');
  if (!isIpv4 && subdomains.length >= 4) {
    rules.push({
      ruleId: 'URL-006',
      ruleName: 'Deep Subdomain Nesting',
      category: 'Obfuscation',
      points: 15,
      description: 'Domain exhibits deep subdomain hierarchy often used for Domain Generation Algorithms (DGA) or tracking bypass.',
      matchedIndicator: `${subdomains.length} segments`,
    });
  }

  // Calculate score capped at 100
  const totalScore = Math.min(100, rules.reduce((acc, r) => acc + r.points, 0));
  const severity = scoreToSeverity(totalScore);
  const verdict = scoreToVerdict(totalScore);

  if (recommendations.length === 0) {
    recommendations.push('No critical malicious indicators identified under standard heuristics. Monitor normal web gateway logs.');
  }

  return {
    id: `scan-url-${Date.now()}`,
    scannerType: 'url',
    input: rawUrl,
    timestamp: new Date().toISOString(),
    riskScore: totalScore,
    severity,
    verdict,
    summary:
      totalScore >= 70
        ? `High-risk URL flagged with ${rules.length} critical indicators including ${rules.map((r) => r.ruleName).join(', ')}.`
        : totalScore >= 35
        ? `Suspicious URL detected. ${rules.length} heuristic rules matched.`
        : `Benign URL profile. No known malicious signatures identified.`,
    rulesTriggered: rules,
    indicators,
    recommendations,
    rawDetails: {
      hostname,
      protocol: parsed.protocol,
      pathname,
      hasPort: !!parsed.port,
    },
  };
}

/**
 * Analyzes Text / Code Snippets for security vulnerabilities, injection, and secrets
 */
export function analyzeSecurityText(content: string): ScanResult {
  const rules: RuleMatch[] = [];
  const indicators: string[] = [];
  const recommendations: string[] = [];

  const text = content.trim();
  if (!text) {
    throw new Error('Analysis content cannot be empty.');
  }

  // 1. Secret / Credential Leakage
  if (/(?:AKIA[0-9A-Z]{16})/.test(text)) {
    rules.push({
      ruleId: 'TXT-001',
      ruleName: 'Exposed AWS Access Key',
      category: 'Credential Exposure',
      points: 50,
      description: 'Hardcoded standard AWS Access Key ID pattern detected.',
    });
    indicators.push('AWS Access Key ID pattern');
    recommendations.push('Revoke the exposed key immediately via AWS IAM and rotate credentials.');
  }

  if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(text)) {
    rules.push({
      ruleId: 'TXT-002',
      ruleName: 'Private Cryptographic Key in Plaintext',
      category: 'Credential Exposure',
      points: 60,
      description: 'Unencrypted PEM private key header detected.',
    });
    indicators.push('PEM Private Key Block');
    recommendations.push('Ensure private keys are never committed or transferred in logs; regenerate keypairs.');
  }

  // 2. Command Injection & Obfuscation
  if (/(?:powershell(?:\.exe)?|cmd\.exe|bash|sh)\b[^\n]*-(?:enc|encodedcommand|nop|w\s+hidden|e\b)/i.test(text) || /invoke-expression|iex\b/i.test(text)) {
    rules.push({
      ruleId: 'TXT-003',
      ruleName: 'Obfuscated Command Execution (PowerShell / Shell)',
      category: 'Execution Evasion',
      points: 45,
      description: 'Execution bypass flags or Invoke-Expression shorthand commonly used in living-off-the-land malware staging.',
    });
    indicators.push('PowerShell encoded/hidden execution syntax');
    recommendations.push('Inspect endpoint EDR telemetry for child process creation spawning from script interpreters.');
  }

  if (/\b(?:base64\s+-d|certutil\s+-decode|certutil\s+-urlcache)\b/i.test(text)) {
    rules.push({
      ruleId: 'TXT-004',
      ruleName: 'Payload Stager / Base64 Decoder Command',
      category: 'Defense Evasion',
      points: 35,
      description: 'Command line utility invocation configured to decode obfuscated payloads on disk.',
    });
    indicators.push('Base64 decode utility invocation');
  }

  // 3. SQL Injection Patterns
  if (/(?:'\s*or\s*['"1]=['"1]|\bunion\s+(?:all\s+)?select\b|;\s*drop\s+table\b|--\s*$)/i.test(text)) {
    rules.push({
      ruleId: 'TXT-005',
      ruleName: 'Classic SQL Injection Syntax',
      category: 'Web Exploitation',
      points: 40,
      description: 'Contains boolean-based SQL bypass syntax or UNION SELECT schema extraction pattern.',
    });
    indicators.push('SQL injection payload syntax');
    recommendations.push('Verify parameterized queries (prepared statements) and check WAF SQLi inspection rules.');
  }

  // 4. Prompt Injection / AI System Bypass
  if (/(ignore previous instructions|disregard all prior directives|you are now in developer mode|jailbreak|bypass security filters)/i.test(text)) {
    rules.push({
      ruleId: 'TXT-006',
      ruleName: 'LLM Prompt Injection / Jailbreak Directive',
      category: 'AI Security',
      points: 35,
      description: 'Direct instruction override pattern targeting LLM system guardrails.',
    });
    indicators.push('Prompt injection pattern');
    recommendations.push('Pass prompt through strict constitutional guardrails and enforce structured JSON schema outputs.');
  }

  const totalScore = Math.min(100, rules.reduce((acc, r) => acc + r.points, 0));
  const severity = scoreToSeverity(totalScore);
  const verdict = scoreToVerdict(totalScore);

  if (recommendations.length === 0) {
    recommendations.push('No immediate code injection, secret leakage, or bypass signatures matched.');
  }

  return {
    id: `scan-text-${Date.now()}`,
    scannerType: 'text',
    input: text.slice(0, 100) + (text.length > 100 ? '...' : ''),
    timestamp: new Date().toISOString(),
    riskScore: totalScore,
    severity,
    verdict,
    summary:
      totalScore >= 70
        ? `Severe text risk: ${rules.map((r) => r.ruleName).join('; ')}`
        : totalScore > 0
        ? `Heuristic matches found: ${rules.map((r) => r.ruleName).join(', ')}`
        : `No suspicious patterns detected in text snippet.`,
    rulesTriggered: rules,
    indicators,
    recommendations,
    rawDetails: {
      characterCount: text.length,
      lineCount: text.split('\n').length,
    },
  };
}

/**
 * QR Code payload classifier & analyzer
 * Enforces requirement: "QR analysis should show the decoded payload type before showing any URL-related checks."
 */
export function analyzeQrPayload(payload: string): ScanResult {
  const trimmed = payload.trim();
  if (!trimmed) {
    throw new Error('QR payload cannot be empty.');
  }

  let decodedType: 'url' | 'wifi' | 'text' | 'command' | 'other' = 'text';

  // 1. Detect Payload Type First
  if (/^https?:\/\//i.test(trimmed) || /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/.*)?$/i.test(trimmed)) {
    decodedType = 'url';
  } else if (/^WIFI:S:.*?;T:.*?;P:.*?;/i.test(trimmed)) {
    decodedType = 'wifi';
  } else if (/^(?:sh|bash|powershell|cmd|sudo|curl|wget)\b/i.test(trimmed)) {
    decodedType = 'command';
  }

  const rules: RuleMatch[] = [];
  const indicators: string[] = [`Decoded Type: ${decodedType.toUpperCase()}`];
  const recommendations: string[] = [];

  if (decodedType === 'command') {
    rules.push({
      ruleId: 'QR-001',
      ruleName: 'Executable Command in QR Code',
      category: 'Terminal Exploitation',
      points: 85,
      description: 'QR barcode decodes directly to shell or script interpreter commands (e.g. bash, powershell).',
      matchedIndicator: trimmed.slice(0, 40),
    });
    recommendations.push('Do not paste or execute QR terminal string into any shell or automated terminal.');
  } else if (decodedType === 'wifi') {
    rules.push({
      ruleId: 'QR-002',
      ruleName: 'Wireless Network Auto-Connect Payload',
      category: 'Physical / Wireless',
      points: 25,
      description: 'QR contains pre-configured SSID and authentication keys.',
      matchedIndicator: 'WIFI configuration',
    });
    recommendations.push('Verify wireless BSSID before associating to avoid Evil Twin rogue access points.');
  } else if (decodedType === 'url') {
    // Run URL analysis on the extracted target
    const urlResult = analyzeUrl(trimmed);
    rules.push(...urlResult.rulesTriggered);
    indicators.push(...urlResult.indicators);
    recommendations.push(...urlResult.recommendations);
  }

  const totalScore = Math.min(100, rules.reduce((acc, r) => acc + r.points, 0));

  return {
    id: `scan-qr-${Date.now()}`,
    scannerType: 'qr',
    input: trimmed,
    timestamp: new Date().toISOString(),
    riskScore: totalScore,
    severity: scoreToSeverity(totalScore),
    verdict: scoreToVerdict(totalScore),
    summary: `QR decoded as [${decodedType.toUpperCase()}]. Risk score: ${totalScore}/100.`,
    rulesTriggered: rules,
    indicators,
    recommendations: recommendations.length > 0 ? recommendations : ['Standard plaintext payload with no known threat vectors.'],
    qrDetails: {
      decodedType,
      rawPayload: trimmed,
      hasPotentialObfuscation: decodedType === 'command' || rules.length > 0,
    },
  };
}
