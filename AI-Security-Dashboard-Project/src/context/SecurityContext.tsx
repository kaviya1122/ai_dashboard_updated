/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { Alert, Asset, IncidentStatus, ReportItem, ScanResult, SeverityLevel, UserProfile } from '../types';
import { UniversalFileAnalysis } from '../utils/fileAnalyzer';

export interface ActivityLog {
  id: string;
  timestamp: string;
  analyst: string;
  action: string;
  module: string;
  severity?: SeverityLevel;
}

interface SecurityContextType {
  currentUser: UserProfile | null;
  isAuthenticated: boolean;
  login: (email: string, password?: string) => Promise<{ success: boolean; error?: string }>;
  register: (email: string, password: string, name?: string, role?: string) => Promise<{ success: boolean; error?: string }>;
  updateUserProfile: (updates: { name?: string; role?: string }) => Promise<boolean>;
  logout: () => void;
  alerts: Alert[];
  assets: Asset[];
  scans: ScanResult[];
  reports: ReportItem[];
  uploadedFiles: UniversalFileAnalysis[];
  addUploadedFile: (file: UniversalFileAnalysis) => void;
  activityLogs: ActivityLog[];
  activeAlertForModal: Alert | null;
  copilotAttachedContext: { type: 'alert' | 'scan' | 'asset'; id: string; title: string; summary: string } | null;
  openAlertModal: (alert: Alert) => void;
  closeAlertModal: () => void;
  updateAlertStatus: (id: string, status: IncidentStatus) => void;
  addScanResult: (result: ScanResult) => void;
  addReport: (report: ReportItem) => void;
  updateReport: (report: ReportItem) => void;
  setCopilotContext: (ctx: { type: 'alert' | 'scan' | 'asset'; id: string; title: string; summary: string } | null) => void;
  logActivity: (action: string, module: string, severity?: SeverityLevel) => void;
  authorizedScopeConsent: boolean;
  setAuthorizedScopeConsent: (consent: boolean) => void;
}

const initialAlerts: Alert[] = [
  {
    id: 'ALT-9041',
    title: 'Cobalt Strike Beaconing Pattern Detected',
    category: 'command_and_control',
    severity: 'critical',
    status: 'investigating',
    affectedAsset: 'DB-PROD-01',
    assetIp: '10.240.10.42',
    timestamp: new Date(Date.now() - 14 * 60 * 1000).toISOString(),
    source: 'Suricata NIDS / Zeek Egress Monitor',
    confidence: 94,
    mitreTechnique: 'T1071.001 - Web Protocols',
    description: 'Periodic TLS heartbeats with low jitter (10s ±5%) destined to unclassified external IP. User-agent string matches known Cobalt Strike malleable C2 profile.',
    evidence: [
      { key: 'Destination IP', value: '198.51.100.89 (Designated sandbox test range)', note: 'Egress alert triggered' },
      { key: 'SSL JA3 Fingerprint', value: 'a0e9f5d64349fb13191bc781f81f42e1', note: 'Matches Cobalt Strike 4.8 default' },
      { key: 'Beacon Jitter', value: '4.8% variance over 120 polling intervals' },
    ],
    timeline: [
      { time: '10:41 UTC', event: 'First suspicious handshake observed by Suricata rule #2024810' },
      { time: '10:44 UTC', event: 'Repeated 128-byte payload POST observed without referer header' },
      { time: '10:52 UTC', event: 'Alert escalated to SOC Critical Incident Queue by automated correlator' },
    ],
    recommendedActions: [
      'Isolate DB-PROD-01 from internal database subnet immediately.',
      'Dump volatile memory using WinPmem / LiME for process injection verification.',
      'Blackhole destination IP at border BGP routers.',
    ],
  },
  {
    id: 'ALT-8812',
    title: 'Suspected LSASS Memory Injection Attempt',
    category: 'credential_access',
    severity: 'high',
    status: 'new',
    affectedAsset: 'WS-FINANCE-04',
    assetIp: '10.240.14.88',
    timestamp: new Date(Date.now() - 48 * 60 * 1000).toISOString(),
    source: 'CrowdStrike Falcon Sensor / EDR',
    confidence: 89,
    mitreTechnique: 'T1003.001 - LSASS Memory',
    description: 'Non-system binary `rundll32.exe` requested PROCESS_VM_READ access to `lsass.exe` PID 684.',
    evidence: [
      { key: 'Source Process', value: 'C:\\Users\\Finance\\AppData\\Local\\Temp\\updater.exe' },
      { key: 'Target Process', value: 'C:\\Windows\\System32\\lsass.exe (PID 684)' },
      { key: 'Granted Access Mask', value: '0x1410 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)' },
    ],
    timeline: [
      { time: '10:11 UTC', event: 'Phishing attachment executed from Microsoft Outlook' },
      { time: '10:12 UTC', event: 'Process spawned temp executable updater.exe' },
      { time: '10:14 UTC', event: 'Blocked open process handle call to LSASS' },
    ],
    recommendedActions: [
      'Trigger automated host network quarantine via EDR sensor.',
      'Revoke Kerberos TGT tickets for user finance.lead@corp.local.',
      'Collect quarantine file artifact for sandbox analysis.',
    ],
  },
  {
    id: 'ALT-7734',
    title: 'Anomalous Outbound SSH Tunneling',
    category: 'exfiltration',
    severity: 'medium',
    status: 'investigating',
    affectedAsset: 'GW-EDGE-02',
    assetIp: '10.240.1.2',
    timestamp: new Date(Date.now() - 110 * 60 * 1000).toISOString(),
    source: 'Palo Alto Networks Next-Gen Firewall',
    confidence: 76,
    mitreTechnique: 'T1048.002 - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol',
    description: 'High-volume SSH session lasting >90 minutes transferring 4.2 GB of payload data outside scheduled backup window.',
    evidence: [
      { key: 'Session Duration', value: '5,420 seconds uninterrupted' },
      { key: 'Bytes Sent', value: '4,294,967,296 bytes (4.0 GB)' },
      { key: 'Target Port', value: '2222 (Non-standard SSH)' },
    ],
    timeline: [
      { time: '09:05 UTC', event: 'SSH tunnel opened to external IP' },
      { time: '09:40 UTC', event: 'Data egress rate exceeded baseline threshold (>50MB/min)' },
    ],
    recommendedActions: [
      'Review firewall rule #41 permitting egress on TCP port 2222.',
      'Correlate initiating user account in PAM (Privileged Access Management) logs.',
    ],
  },
  {
    id: 'ALT-6621',
    title: 'Multiple Failed Kerberos Pre-Authentications',
    category: 'credential_access',
    severity: 'low',
    status: 'contained',
    affectedAsset: 'DC-CORE-01',
    assetIp: '10.240.5.10',
    timestamp: new Date(Date.now() - 190 * 60 * 1000).toISOString(),
    source: 'Active Directory Security Log (Event 4768)',
    confidence: 68,
    mitreTechnique: 'T1110.003 - Password Spraying',
    description: '18 failed Kerberos authentication requests with error code 0x18 across 6 unique administrative user accounts from a single workstation.',
    evidence: [
      { key: 'Failure Code', value: '0x18 (KDC_ERR_PREAUTH_FAILED)' },
      { key: 'Target Accounts', value: 'adm_backup, adm_deploy, adm_svc, root_admin' },
      { key: 'Originating Host', value: '10.240.14.22 (WS-DEV-12)' },
    ],
    timeline: [
      { time: '07:45 UTC', event: 'Burst of 18 authentication queries within 45 seconds' },
      { time: '07:50 UTC', event: 'Automated Account Lockout policy triggered on 3 accounts' },
    ],
    recommendedActions: [
      'Contact user of WS-DEV-12 to check for misconfigured background build scripts.',
      'Reset passwords for the targeted administrative service accounts.',
    ],
  },
  {
    id: 'ALT-5510',
    title: 'Perimeter TLS Certificate Expiration in 7 Days',
    category: 'policy_violation',
    severity: 'info',
    status: 'resolved',
    affectedAsset: 'APP-CLUSTER-01',
    assetIp: '10.240.20.15',
    timestamp: new Date(Date.now() - 360 * 60 * 1000).toISOString(),
    source: 'Qualys SSL Labs Sentinel',
    confidence: 100,
    mitreTechnique: 'N/A - Compliance & Hardening',
    description: 'Wildcard public certificate `*.api.internal-cloud.net` expires on Nov 4, 2026. Auto-renewal webhook succeeded.',
    evidence: [
      { key: 'Serial Number', value: '04:7A:BC:88:12:F0:99' },
      { key: 'Issuer', value: "Let's Encrypt Authority X3" },
      { key: 'Status', value: 'New certificate deployed via ACME cert-manager' },
    ],
    timeline: [
      { time: '05:00 UTC', event: 'Automated certificate audit scan executed' },
      { time: '05:05 UTC', event: 'Kubernetes cert-manager issued valid renewal' },
    ],
    recommendedActions: [
      'No further action required; renewal confirmed across all ingress pods.',
    ],
  },
];

const initialAssets: Asset[] = [];

const initialScans: ScanResult[] = [
  {
    id: 'scan-url-init1',
    scannerType: 'url',
    input: 'http://198.51.100.89/dl/stage2_payload.exe',
    timestamp: new Date(Date.now() - 35 * 60 * 1000).toISOString(),
    riskScore: 85,
    severity: 'high',
    verdict: 'malicious',
    summary: 'High-risk URL flagged with IP literal host and direct executable payload download.',
    rulesTriggered: [
      {
        ruleId: 'URL-001',
        ruleName: 'IP Literal Host',
        category: 'Evasion',
        points: 40,
        description: 'Direct IP destination used instead of registered DNS domain.',
        matchedIndicator: '198.51.100.89',
      },
      {
        ruleId: 'URL-004',
        ruleName: 'Direct Binary Payload Target',
        category: 'Malware Delivery',
        points: 45,
        description: 'Target path ends in executable extension .exe.',
        matchedIndicator: '.exe',
      },
    ],
    indicators: ['Direct IP access: 198.51.100.89', 'Payload extension: .exe'],
    recommendations: ['Block IP at firewall perimeter', 'Submit binary hash to VirusTotal'],
  },
];

const initialReports: ReportItem[] = [];

const initialActivity: ActivityLog[] = [];

const initialUploadedFiles: UniversalFileAnalysis[] = [];

const SecurityContext = createContext<SecurityContextType | undefined>(undefined);

export const SecurityProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(() => {
    try {
      const stored = localStorage.getItem('aegis_soc_user');
      if (stored && stored !== 'null') {
        return JSON.parse(stored);
      }
    } catch {
      // fallback
    }
    return null;
  });

  const [alerts, setAlerts] = useState<Alert[]>(initialAlerts);
  const [assets, setAssets] = useState<Asset[]>(initialAssets);
  const [scans, setScans] = useState<ScanResult[]>(initialScans);
  const [reports, setReports] = useState<ReportItem[]>(initialReports);
  const [uploadedFiles, setUploadedFiles] = useState<UniversalFileAnalysis[]>(initialUploadedFiles);
  const [activityLogs, setActivityLogs] = useState<ActivityLog[]>(initialActivity);
  const [activeAlertForModal, setActiveAlertForModal] = useState<Alert | null>(null);
  const [copilotAttachedContext, setCopilotAttachedContext] = useState<{
    type: 'alert' | 'scan' | 'asset';
    id: string;
    title: string;
    summary: string;
  } | null>(null);
  const [authorizedScopeConsent, setAuthorizedScopeConsent] = useState<boolean>(true);

  // Helper to get local registered accounts
  const getStoredAccounts = (): Record<string, { email: string; passwordHash: string; name: string; role: string; createdAt: string }> => {
    try {
      const raw = localStorage.getItem('aegis_registered_accounts');
      if (raw) return JSON.parse(raw);
    } catch {
      // ignore
    }
    return {};
  };

  const saveStoredAccounts = (accounts: Record<string, { email: string; passwordHash: string; name: string; role: string; createdAt: string }>) => {
    try {
      localStorage.setItem('aegis_registered_accounts', JSON.stringify(accounts));
    } catch {
      // ignore
    }
  };

  /**
   * Register a new user
   * Strictly enforces: Once an account is created with an email, you CANNOT create another account with the same email.
   */
  const register = async (
    email: string,
    password: string,
    name?: string,
    role?: string
  ): Promise<{ success: boolean; error?: string }> => {
    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      return { success: false, error: 'Please enter a valid email address.' };
    }

    if (!password || password.length < 6) {
      return { success: false, error: 'Password must be at least 6 characters long.' };
    }

    // 1. Check local registry first
    const localAccounts = getStoredAccounts();
    if (localAccounts[normalizedEmail]) {
      return {
        success: false,
        error: 'An account with this email address already exists. Please sign in instead.',
      };
    }

    // 2. Call backend register API
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: normalizedEmail, password, name, role }),
      });

      const data = await res.json();

      if (!res.ok) {
        return {
          success: false,
          error: data.error || 'Failed to create account.',
        };
      }

      // Save user to state & local storage
      const userProfile: UserProfile = data.user;
      setCurrentUser(userProfile);
      localStorage.setItem('aegis_soc_user', JSON.stringify(userProfile));

      // Record in local persistent accounts database
      localAccounts[normalizedEmail] = {
        email: normalizedEmail,
        passwordHash: btoa(password + '_salt_simple'),
        name: userProfile.name,
        role: userProfile.role,
        createdAt: userProfile.createdAt || new Date().toISOString(),
      };
      saveStoredAccounts(localAccounts);

      logActivity(`New user "${userProfile.name}" created an account with ${userProfile.email}`, 'Account');
      return { success: true };
    } catch {
      // Offline fallback registration
      const displayName = (name && name.trim()) || normalizedEmail.split('@')[0].replace('.', ' ').replace(/\b\w/g, (c) => c.toUpperCase());
      const initials = displayName
        .split(' ')
        .filter(Boolean)
        .slice(0, 2)
        .map((p) => p[0].toUpperCase())
        .join('') || displayName.slice(0, 2).toUpperCase();

      const userProfile: UserProfile = {
        id: `usr-${Date.now().toString(36)}`,
        name: displayName,
        email: normalizedEmail,
        role: role || 'Security Analyst',
        avatarInitials: initials,
        sessionToken: `SOC-${Math.random().toString(36).slice(2)}`,
        loginTime: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
        createdAt: new Date().toISOString(),
      };

      localAccounts[normalizedEmail] = {
        email: normalizedEmail,
        passwordHash: btoa(password + '_salt_simple'),
        name: userProfile.name,
        role: userProfile.role,
        createdAt: userProfile.createdAt || new Date().toISOString(),
      };
      saveStoredAccounts(localAccounts);

      setCurrentUser(userProfile);
      localStorage.setItem('aegis_soc_user', JSON.stringify(userProfile));
      logActivity(`Created new account for ${userProfile.name} (${userProfile.email})`, 'Account');
      return { success: true };
    }
  };

  /**
   * Log in an existing user
   */
  const login = async (
    email: string,
    password?: string
  ): Promise<{ success: boolean; error?: string }> => {
    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail || !normalizedEmail.includes('@')) {
      return { success: false, error: 'Please enter your email address.' };
    }

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: normalizedEmail, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        // If not found on backend, check local storage
        if (res.status === 404) {
          const localAccounts = getStoredAccounts();
          const localUser = localAccounts[normalizedEmail];
          if (localUser) {
            // Verify password
            if (password && btoa(password + '_salt_simple') !== localUser.passwordHash) {
              return { success: false, error: 'Incorrect password. Please verify and try again.' };
            }

            const restoredUser: UserProfile = {
              id: `usr-${Date.now().toString(36)}`,
              name: localUser.name,
              email: localUser.email,
              role: localUser.role,
              avatarInitials: localUser.name.slice(0, 2).toUpperCase(),
              sessionToken: `SOC-${Math.random().toString(36).slice(2)}`,
              loginTime: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
              createdAt: localUser.createdAt,
            };

            setCurrentUser(restoredUser);
            localStorage.setItem('aegis_soc_user', JSON.stringify(restoredUser));
            logActivity(`User ${restoredUser.name} signed in successfully`, 'Account');
            return { success: true };
          }
        }

        return {
          success: false,
          error: data.error || 'Failed to sign in. Please check your credentials.',
        };
      }

      const userProfile: UserProfile = data.user;
      setCurrentUser(userProfile);
      localStorage.setItem('aegis_soc_user', JSON.stringify(userProfile));
      logActivity(`User ${userProfile.name} signed in successfully`, 'Account');
      return { success: true };
    } catch {
      // Local check
      const localAccounts = getStoredAccounts();
      const localUser = localAccounts[normalizedEmail];

      if (!localUser) {
        return {
          success: false,
          error: 'No account found with this email. Please click "Create Account" below to register.',
        };
      }

      if (password && btoa(password + '_salt_simple') !== localUser.passwordHash) {
        return { success: false, error: 'Incorrect password. Please verify and try again.' };
      }

      const restoredUser: UserProfile = {
        id: `usr-${Date.now().toString(36)}`,
        name: localUser.name,
        email: localUser.email,
        role: localUser.role,
        avatarInitials: localUser.name.slice(0, 2).toUpperCase(),
        sessionToken: `SOC-${Math.random().toString(36).slice(2)}`,
        loginTime: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
        createdAt: localUser.createdAt,
      };

      setCurrentUser(restoredUser);
      localStorage.setItem('aegis_soc_user', JSON.stringify(restoredUser));
      logActivity(`User ${restoredUser.name} signed in`, 'Account');
      return { success: true };
    }
  };

  /**
   * Update Profile Details
   */
  const updateUserProfile = async (updates: { name?: string; role?: string }): Promise<boolean> => {
    if (!currentUser) return false;

    const updated: UserProfile = {
      ...currentUser,
      name: updates.name || currentUser.name,
      role: updates.role || currentUser.role,
      avatarInitials: (updates.name || currentUser.name).slice(0, 2).toUpperCase(),
    };

    setCurrentUser(updated);
    localStorage.setItem('aegis_soc_user', JSON.stringify(updated));

    // Update in local accounts database too
    const localAccounts = getStoredAccounts();
    if (localAccounts[currentUser.email.toLowerCase()]) {
      localAccounts[currentUser.email.toLowerCase()].name = updated.name;
      localAccounts[currentUser.email.toLowerCase()].role = updated.role;
      saveStoredAccounts(localAccounts);
    }

    fetch('/api/auth/update-profile', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: currentUser.email, name: updated.name, role: updated.role }),
    }).catch(() => {});

    logActivity(`Updated profile details for ${updated.name}`, 'Account');
    return true;
  };

  const logout = () => {
    fetch('/api/auth/logout', { method: 'POST' }).catch(() => {});
    logActivity(`User ${currentUser?.name || 'User'} logged out`, 'Account');
    setCurrentUser(null);
    localStorage.removeItem('aegis_soc_user');
  };

  const addUploadedFile = (file: UniversalFileAnalysis) => {
    setUploadedFiles((prev) => [file, ...prev]);
    logActivity(
      `Uploaded file "${file.fileName}" (${file.fileSizeFormatted}) -> Saved to cloud vault`,
      'Upload Center',
      file.threatSignaturesMatched.length > 0 ? 'high' : 'info'
    );
  };

  const openAlertModal = (alert: Alert) => {
    setActiveAlertForModal(alert);
  };

  const closeAlertModal = () => {
    setActiveAlertForModal(null);
  };

  const updateAlertStatus = (id: string, status: IncidentStatus) => {
    setAlerts((prev) =>
      prev.map((alert) => (alert.id === id ? { ...alert, status } : alert))
    );
    logActivity(`Updated alert status: ${id} is now ${status.toUpperCase()}`, 'Alerts');
  };

  const addScanResult = (result: ScanResult) => {
    setScans((prev) => [result, ...prev]);
    logActivity(
      `Completed ${result.scannerType.toUpperCase()} scan on "${result.input.slice(0, 30)}" -> Risk ${result.riskScore}/100`,
      'Scanners',
      result.severity
    );
  };

  const addReport = (report: ReportItem) => {
    setReports((prev) => [report, ...prev]);
    logActivity(`Generated security report: ${report.title}`, 'Reports');
  };

  const updateReport = (report: ReportItem) => {
    setReports((prev) => prev.map((item) => item.id === report.id ? report : item));
    logActivity(`Updated recorded response status in ${report.id}`, 'Reports');
  };

  const logActivity = (action: string, module: string, severity?: SeverityLevel) => {
    const newLog: ActivityLog = {
      id: `act-${Date.now()}`,
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
      analyst: currentUser ? currentUser.name : 'System',
      action,
      module,
      severity,
    };
    setActivityLogs((prev) => [newLog, ...prev.slice(0, 49)]);
  };

  return (
    <SecurityContext.Provider
      value={{
        currentUser,
        isAuthenticated: currentUser !== null,
        login,
        register,
        updateUserProfile,
        logout,
        alerts,
        assets,
        scans,
        reports,
        uploadedFiles,
        addUploadedFile,
        activityLogs,
        activeAlertForModal,
        copilotAttachedContext,
        openAlertModal,
        closeAlertModal,
        updateAlertStatus,
        addScanResult,
        addReport,
        updateReport,
        setCopilotContext: setCopilotAttachedContext,
        logActivity,
        authorizedScopeConsent,
        setAuthorizedScopeConsent,
      }}
    >
      {children}
    </SecurityContext.Provider>
  );
};

export function useSecurity() {
  const context = useContext(SecurityContext);
  if (!context) {
    throw new Error('useSecurity must be used within a SecurityProvider');
  }
  return context;
}
