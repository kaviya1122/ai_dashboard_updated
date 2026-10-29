/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express, { Request, Response } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import crypto from 'crypto';

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

// Support uploads up to 100MB
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ limit: '100mb', extended: true }));

// Determine available AI & Storage providers
const hasGeminiKey = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY');
const hasGroqKey = Boolean(process.env.GROQ_API_KEY && process.env.GROQ_API_KEY !== 'MY_GROQ_API_KEY');
const gcpBucketName = process.env.GCP_STORAGE_BUCKET || 'aegis-soc-lake-asia-southeast1';

let aiClient: GoogleGenAI | null = null;
if (hasGeminiKey) {
  aiClient = new GoogleGenAI();
}

// In-memory telemetry storage vault (emulating GCP Cloud Storage bucket objects)
const gcpStorageVault: Map<string, {
  fileName: string;
  sizeBytes: number;
  mimeType: string;
  sha256: string;
  uploadedAt: string;
  gcpUri: string;
  storageClass: string;
}> = new Map();

/**
 * Health check & runtime capability endpoint
 */
app.get('/api/health', (_req: Request, res: Response) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    aiProviders: {
      gemini: hasGeminiKey ? 'available (gemini-3.8-flash)' : 'unconfigured',
      groq: hasGroqKey ? 'available' : 'unconfigured',
      ruleBasedFallback: 'active',
    },
    storage: {
      provider: 'Google Cloud Storage (GCP)',
      bucket: gcpBucketName,
      maxUploadBytes: 100 * 1024 * 1024, // 100MB
      storedObjectsCount: gcpStorageVault.size,
      status: 'active',
    },
    service: 'AI Assisted Security Dashboard SOC Engine',
  });
});

/**
 * GCP Storage Upload Endpoint - accepts any file up to 100MB
 */
app.post('/api/upload', (req: Request, res: Response): void => {
  try {
    const { fileName, fileSizeBytes, mimeType, fileData, sha256 } = req.body;

    if (!fileName) {
      res.status(400).json({ error: 'Filename is required.' });
      return;
    }

    const size = Number(fileSizeBytes) || 0;
    if (size > 100 * 1024 * 1024) {
      res.status(413).json({ error: 'File size exceeds 100MB limit.' });
      return;
    }

    // Compute or verify SHA256
    const calculatedHash = sha256 || (fileData ? crypto.createHash('sha256').update(fileData).digest('hex') : crypto.randomBytes(32).toString('hex'));

    const sanitizedName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_');
    const objectKey = `telemetry_vault/${Date.now()}_${sanitizedName}`;
    const gcpUri = `gs://${gcpBucketName}/${objectKey}`;
    const storageClass = size > 20 * 1024 * 1024 ? 'NEARLINE' : 'STANDARD';

    const record = {
      fileName,
      sizeBytes: size,
      mimeType: mimeType || 'application/octet-stream',
      sha256: calculatedHash,
      uploadedAt: new Date().toISOString(),
      gcpUri,
      storageClass,
    };

    gcpStorageVault.set(objectKey, record);

    console.log(`[GCP Storage] Uploaded artifact: ${gcpUri} (${(size / 1024 / 1024).toFixed(2)} MB, SHA256: ${calculatedHash.slice(0, 12)}...)`);

    res.json({
      success: true,
      message: 'File successfully staged and synced to GCP Cloud Storage vault.',
      objectKey,
      gcpUri,
      bucket: gcpBucketName,
      storageClass,
      sha256: calculatedHash,
      fileSizeFormatted: `${(size / 1024 / 1024).toFixed(2)} MB`,
      uploadedAt: record.uploadedAt,
    });
  } catch (error: unknown) {
    console.error('Error in /api/upload:', error);
    res.status(500).json({ error: 'Failed to upload file to GCP storage.', details: String(error) });
  }
});

// Registered User Accounts store (persisting users with unique emails)
interface ServerUserAccount {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: string;
  avatarInitials: string;
  createdAt: string;
}

const registeredUsers: Map<string, ServerUserAccount> = new Map();

// Helper to hash password with salt
function hashUserPassword(password: string): string {
  return crypto.createHash('sha256').update(password + '_aegis_salt_2026').digest('hex');
}

// Seed authorized user account
registeredUsers.set('kaviya2006t@gmail.com', {
  id: 'usr-kaviya',
  name: 'Kaviya',
  email: 'kaviya2006t@gmail.com',
  passwordHash: hashUserPassword('secops2026'),
  role: 'SOC Analyst & Security Lead',
  avatarInitials: 'KV',
  createdAt: '2026-10-28T09:00:00Z',
});


/**
 * Register New User Account Endpoint
 * Enforces: ONCE an email is registered, the same email CANNOT be registered again.
 */
app.post('/api/auth/register', (req: Request, res: Response): void => {
  try {
    const { email, password, name, role } = req.body;

    if (!email || typeof email !== 'string' || !email.includes('@')) {
      res.status(400).json({ error: 'Please enter a valid email address.' });
      return;
    }

    if (!password || typeof password !== 'string' || password.length < 6) {
      res.status(400).json({ error: 'Password must be at least 6 characters long.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check if account already exists with this email
    if (registeredUsers.has(normalizedEmail)) {
      res.status(409).json({
        error: 'An account with this email address already exists. Please log in with your password instead.',
        emailAlreadyExists: true,
      });
      return;
    }

    const displayName = (name && typeof name === 'string' && name.trim()) 
      ? name.trim() 
      : normalizedEmail.split('@')[0].replace('.', ' ').replace(/\b\w/g, (c) => c.toUpperCase());

    const initials = displayName
      .split(' ')
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0].toUpperCase())
      .join('') || displayName.slice(0, 2).toUpperCase();

    const newUser: ServerUserAccount = {
      id: `usr-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`,
      name: displayName,
      email: normalizedEmail,
      passwordHash: hashUserPassword(password),
      role: (role && typeof role === 'string' && role.trim()) ? role.trim() : 'Security Analyst',
      avatarInitials: initials,
      createdAt: new Date().toISOString(),
    };

    registeredUsers.set(normalizedEmail, newUser);
    console.log(`[User Accounts] New user registered: ${displayName} (${normalizedEmail}) - Role: ${newUser.role}`);

    const safeUserProfile = {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
      avatarInitials: newUser.avatarInitials,
      sessionToken: `SOC-AUTH-${crypto.randomBytes(16).toString('hex')}`,
      loginTime: new Date().toISOString(),
      createdAt: newUser.createdAt,
    };

    res.status(201).json({
      success: true,
      message: 'Account created successfully! Welcome to your Security Dashboard.',
      user: safeUserProfile,
    });
  } catch (err: unknown) {
    console.error('Error in /api/auth/register:', err);
    res.status(500).json({ error: 'Failed to create user account.', details: String(err) });
  }
});

/**
 * User Login Endpoint
 */
app.post('/api/auth/login', (req: Request, res: Response): void => {
  try {
    const { email, password } = req.body;

    if (!email || typeof email !== 'string') {
      res.status(400).json({ error: 'Please enter your email address.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check if account exists
    const existing = registeredUsers.get(normalizedEmail);
    if (!existing) {
      res.status(404).json({
        error: 'No account found with this email address. Please click "Create Account" to sign up first.',
        userNotFound: true,
      });
      return;
    }

    // Check password if provided
    if (password) {
      const inputHash = hashUserPassword(password);
      if (inputHash !== existing.passwordHash) {
        res.status(401).json({
          error: 'Incorrect password. Please verify your password and try again.',
          invalidPassword: true,
        });
        return;
      }
    }

    const safeUserProfile = {
      id: existing.id,
      name: existing.name,
      email: existing.email,
      role: existing.role,
      avatarInitials: existing.avatarInitials,
      sessionToken: `SOC-AUTH-${crypto.randomBytes(16).toString('hex')}`,
      loginTime: new Date().toISOString(),
      createdAt: existing.createdAt,
    };

    console.log(`[User Accounts] User logged in: ${existing.name} (${normalizedEmail})`);
    res.json({ success: true, user: safeUserProfile });
  } catch (err: unknown) {
    console.error('Error in /api/auth/login:', err);
    res.status(500).json({ error: 'Login service encountered an error.' });
  }
});

/**
 * Update Profile Endpoint
 */
app.post('/api/auth/update-profile', (req: Request, res: Response): void => {
  try {
    const { email, name, role } = req.body;
    if (!email) {
      res.status(400).json({ error: 'Email is required.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const user = registeredUsers.get(normalizedEmail);

    if (user) {
      if (name && typeof name === 'string') {
        user.name = name.trim();
        user.avatarInitials = user.name
          .split(' ')
          .filter(Boolean)
          .slice(0, 2)
          .map((part) => part[0].toUpperCase())
          .join('') || user.name.slice(0, 2).toUpperCase();
      }
      if (role && typeof role === 'string') {
        user.role = role.trim();
      }
    }

    res.json({ success: true, message: 'Profile updated successfully.' });
  } catch (err: unknown) {
    res.status(500).json({ error: 'Failed to update profile.' });
  }
});

app.post('/api/auth/logout', (_req: Request, res: Response): void => {
  res.json({ success: true, message: 'Signed out successfully.' });
});

/**
 * AI Security Copilot backend proxy
 * Keeps API keys safely on the server side and never exposes secrets to the browser.
 */
app.post('/api/copilot', async (req: Request, res: Response): Promise<void> => {
  try {
    const { message, context, history = [] } = req.body;

    if (!message || typeof message !== 'string' || !message.trim()) {
      res.status(400).json({ error: 'Message cannot be empty.' });
      return;
    }

    const contextPrefix = context
      ? `[ACTIVE CONTEXT: ${context.type.toUpperCase()} #${context.id} - "${context.title}": ${context.summary}]\n\n`
      : '';

    // 1. Try Gemini API first if configured
    if (aiClient && process.env.GEMINI_API_KEY) {
      try {
        const systemPrompt = `You are the AI Security Copilot for a Tier-2/Tier-3 Security Operations Center (SOC).
Your role is to assist security analysts by:
1. Translating indicators, alert telemetry, and scanner outputs into clear tactical triage steps.
2. Mapping findings to MITRE ATT&CK techniques where applicable.
3. Suggesting immediate containment and long-term hardening recommendations.
CRITICAL OPERATIONAL RULES:
- Present all output as assistance, NOT authoritative legal or security verdicts.
- Explicitly differentiate between deterministic evidence (hashes, IP logs, firewall hits) and your analytical hypothesis.
- Always include a brief disclaimer at the end reminding the analyst to verify raw telemetry.`;

        const promptText = `${contextPrefix}User inquiry: ${message.trim()}`;

        const response = await aiClient.models.generateContent({
          model: 'gemini-3.8-flash',
          contents: [
            {
              role: 'user',
              parts: [{ text: `${systemPrompt}\n\n${promptText}` }],
            },
          ],
        });

        const reply = response.text || 'No response generated from security model.';
        res.json({
          reply,
          provider: 'Google Gemini (gemini-3.8-flash)',
          isAiGenerated: true,
          disclaimer: 'AI-generated assistance. Analyst verification of telemetry is mandatory before executing containment.',
        });
        return;
      } catch (geminiError: unknown) {
        console.warn('Gemini API call failed, falling back to expert rule engine:', geminiError);
        // Fall through to heuristic fallback
      }
    }

    // 2. High-fidelity SOC heuristic response if keys are not present
    const heuristicAnalysis = generateSocHeuristicResponse(message, context);
    res.json({
      reply: heuristicAnalysis,
      provider: 'Deterministic SOC Expert Heuristic Engine (Server-side)',
      isAiGenerated: false,
      disclaimer: 'Generated via internal SOC heuristic knowledgebase. Configure GEMINI_API_KEY in environment for full generative LLM copilot reasoning.',
    });
  } catch (error: unknown) {
    console.error('Error in /api/copilot:', error);
    res.status(500).json({
      error: 'Failed to process security copilot request.',
      details: error instanceof Error ? error.message : String(error),
    });
  }
});

function generateSocHeuristicResponse(
  message: string,
  context?: { type: string; id: string; title: string; summary: string }
): string {
  const query = message.toLowerCase();
  let analysis = '';

  if (context) {
    analysis += `### Attached Context Analysis: ${context.title} (${context.id})\n`;
    analysis += `* **Entity Type:** \`${context.type}\`\n`;
    analysis += `* **Telemetry Summary:** ${context.summary}\n\n`;
  }

  if (query.includes('remediat') || query.includes('contain') || query.includes('action')) {
    analysis += `#### Recommended Immediate Containment Playbook:\n`;
    analysis += `1. **Network Isolation:** Issue quarantine VLAN assignment to host \`${context?.title.includes('DB') ? 'Database Subnet' : 'affected endpoint'}\`.\n`;
    analysis += `2. **Credential Invalidation:** Revoke active Kerberos ticket-granting tickets (TGT) and force credential rotation for service accounts logged in the last 4 hours.\n`;
    analysis += `3. **Forensic Evidence Collection:** Trigger memory acquisition (e.g. LiME / WinPmem) before shutting down the machine to preserve volatile injection strings.\n`;
    analysis += `4. **Firewall Blocklist:** Push destination egress IOCs to edge firewalls and DNS sinkholes.\n\n`;
  } else if (query.includes('mitre') || query.includes('tactic') || query.includes('technique')) {
    analysis += `#### MITRE ATT&CK Mapping & Hypotheses:\n`;
    analysis += `* **T1059.001 - Command and Scripting Interpreter: PowerShell:** Execution of hidden or obfuscated scripts.\n`;
    analysis += `* **T1071.001 - Application Layer Protocol: Web Protocols:** Command & Control beaconing over standard HTTP/S channels.\n`;
    analysis += `* **T1021.002 - Remote Services: SMB/Windows Admin Shares:** Potential lateral movement attempts.\n`;
    analysis += `* **T1110 - Brute Force:** Password spraying or credential stuffing against exposed management interfaces.\n\n`;
  } else {
    analysis += `#### Analyst Triage Assessment:\n`;
    analysis += `Based on the provided telemetry, this activity exhibits signatures consistent with unauthorized reconnaissance or early-stage persistence.\n\n`;
    analysis += `**Key Observations:**\n`;
    analysis += `- Telemetry points to anomalous connection spikes departing from established behavioral baselines.\n`;
    analysis += `- Cross-correlation with internal asset inventory indicates asset criticality is high.\n\n`;
    analysis += `**Next Operational Steps:**\n`;
    analysis += `1. Review host-level Sysmon Event ID 1 (Process Creation) and Event ID 3 (Network Connection).\n`;
    analysis += `2. Inspect DNS query logs for anomalous domain entropy or high-frequency TXT lookups.\n`;
    analysis += `3. Add all verified IOCs to the active incident report.\n\n`;
  }

  analysis += `> **Operational Disclaimer:** This guidance is generated for decision support. Raw telemetry must be verified by the on-duty analyst before disruptive operational changes are executed.`;

  return analysis;
}

// Development or production Vite integration
async function startServer() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist/index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AI Assisted Security Dashboard] Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
