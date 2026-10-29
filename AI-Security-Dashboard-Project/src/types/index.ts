/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type IncidentStatus = 'new' | 'investigating' | 'contained' | 'resolved' | 'false_positive';

export interface UserProfile {
  id: string;
  name: string;
  email: string;
  role: string;
  tier?: string;
  clearanceLevel?: string;
  avatarInitials: string;
  sessionToken?: string;
  loginTime: string;
  ipAddress?: string;
  createdAt?: string;
}

export interface StoredUserAccount extends UserProfile {
  passwordHash: string;
}

export interface Alert {
  id: string;
  title: string;
  category: 'malware' | 'exfiltration' | 'credential_access' | 'command_and_control' | 'reconnaissance' | 'phishing' | 'policy_violation';
  severity: SeverityLevel;
  status: IncidentStatus;
  affectedAsset: string;
  assetIp: string;
  timestamp: string;
  source: string;
  confidence: number; // 0-100
  mitreTechnique?: string;
  description: string;
  evidence: {
    key: string;
    value: string;
    note?: string;
  }[];
  timeline: {
    time: string;
    event: string;
    analyst?: string;
  }[];
  recommendedActions: string[];
}

export interface Asset {
  id: string;
  name: string;
  ip: string;
  mac?: string;
  type: 'server' | 'workstation' | 'firewall' | 'database' | 'cloud_instance' | 'iot';
  os: string;
  criticality: 'mission_critical' | 'high' | 'medium' | 'low';
  owner: string;
  location: string;
  status: 'active' | 'quarantined' | 'offline' | 'compromised';
  lastSeen: string;
  openPorts: number[];
  vulnerabilitiesCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export type ScannerType = 'url' | 'ip' | 'text' | 'image' | 'qr' | 'nmap';

export interface RuleMatch {
  ruleId: string;
  ruleName: string;
  category: string;
  points: number;
  description: string;
  matchedIndicator?: string;
}

export interface ScanResult {
  id: string;
  scannerType: ScannerType;
  input: string;
  timestamp: string;
  riskScore: number; // 0-100
  severity: SeverityLevel;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  summary: string;
  rulesTriggered: RuleMatch[];
  indicators: string[];
  recommendations: string[];
  rawDetails?: Record<string, unknown>;
  qrDetails?: {
    decodedType: 'url' | 'wifi' | 'text' | 'command' | 'other';
    rawPayload: string;
    hasPotentialObfuscation: boolean;
  };
  networkScope?: {
    isAuthorizedScope: boolean;
    ipType: 'private_rfc1918' | 'loopback' | 'authorized_lab' | 'unauthorized_public';
    authorizationToken?: string;
  };
}

export interface CsvValidationRow {
  rowNumber: number;
  isValid: boolean;
  data: Record<string, string>;
  errors: string[];
  extractedIocs: {
    type: 'ip' | 'domain' | 'sha256' | 'cve';
    value: string;
  }[];
}

export interface CsvValidationResult {
  fileName: string;
  totalRows: number;
  validRows: number;
  invalidRows: number;
  headers: string[];
  rows: CsvValidationRow[];
  extractedIocsSummary: {
    ips: string[];
    domains: string[];
    hashes: string[];
    cves: string[];
  };
}

export interface ReportItem {
  id: string;
  title: string;
  classification: 'TLP:AMBER' | 'TLP:CLEAR' | 'TLP:GREEN' | 'TLP:RED';
  type: 'executive_summary' | 'incident_triage' | 'threat_brief' | 'forensic_analysis';
  createdAt: string;
  author: string;
  associatedAlertIds: string[];
  associatedScanIds: string[];
  evidenceItems: {
    source: string;
    indicator: string;
    severity: SeverityLevel;
    timestamp: string;
    verificationStatus: 'verified_telemetry' | 'sample_data' | 'analyst_confirmed' | 'uploaded_file_analysis';
  }[];
  aiAssistanceNotes: string[];
  analystConclusions: string;
  actionItems: {
    action: string;
    assignedTo: string;
    dueDate: string;
    status: 'pending' | 'in_progress' | 'completed' | 'not_performed';
  }[];
}

export interface CopilotMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  attachedContext?: {
    type: 'alert' | 'scan' | 'asset' | 'custom';
    id: string;
    title: string;
    summary: string;
  };
  aiDisclaimerAcknowledged?: boolean;
}
