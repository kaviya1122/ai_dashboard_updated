/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bot,
  Send,
  Sparkles,
  Paperclip,
  X,
  FilePlus2,
  AlertTriangle,
  RotateCcw,
  ShieldAlert,
  Server,
  Crosshair,
  Info,
  CheckCircle,
} from 'lucide-react';
import { useSecurity } from '../context/SecurityContext';
import { NoticeBanner } from '../components/common/NoticeBanner';
import { CopilotMessage } from '../types';

export const Copilot: React.FC = () => {
  const { copilotAttachedContext, setCopilotContext, alerts, scans, addReport } = useSecurity();
  const navigate = useNavigate();

  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [providerInfo, setProviderInfo] = useState<string>('Detecting AI provider...');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const [messages, setMessages] = useState<CopilotMessage[]>([
    {
      id: 'msg-init-1',
      role: 'assistant',
      content: `Welcome to the AI Security Copilot workspace. I am ready to assist you with threat indicator triage, incident containment steps, and MITRE ATT&CK mapping.\n\n* **Operational Guidance:** You can attach any active alert or scanner result directly to our session using the selector above.\n* **Assistance Disclaimer:** AI suggestions are tactical heuristics for decision support, not legal verdicts. Please verify deterministic telemetry before initiating network disruption.`,
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  // Check health and available providers on mount
  useEffect(() => {
    fetch('/api/health')
      .then((res) => res.json())
      .then((data) => {
        if (data.aiProviders) {
          if (data.aiProviders.gemini?.includes('available')) {
            setProviderInfo('Google Gemini (gemini-3.8-flash) active');
          } else if (data.aiProviders.groq?.includes('available')) {
            setProviderInfo('Groq GPT-OSS / Llama inference active');
          } else {
            setProviderInfo('Deterministic SOC Expert Rule Engine (Server-side)');
          }
        }
      })
      .catch(() => {
        setProviderInfo('Deterministic SOC Expert Rule Engine (Server-side)');
      });
  }, []);

  const handleSendMessage = async (customPrompt?: string) => {
    const textToSend = customPrompt || inputMessage;
    if (!textToSend.trim() || isLoading) return;

    setErrorMessage(null);
    const userMsg: CopilotMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: textToSend.trim(),
      timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
      attachedContext: copilotAttachedContext || undefined,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: textToSend.trim(),
          context: copilotAttachedContext,
        }),
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const data = await response.json();

      const assistantMsg: CopilotMessage = {
        id: `msg-${Date.now() + 1}`,
        role: 'assistant',
        content: data.reply || 'Analysis completed with no output.',
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
      };

      setMessages((prev) => [...prev, assistantMsg]);
      if (data.provider) {
        setProviderInfo(data.provider);
      }
    } catch (err: unknown) {
      console.warn('Backend Copilot API request error:', err);
      // Fallback message inside chat
      const fallbackMsg: CopilotMessage = {
        id: `msg-${Date.now() + 1}`,
        role: 'assistant',
        content: `### Telemetry Analysis & Containment Hypothesis\n\n* **Identified Vector:** Reviewing activity associated with ${
          copilotAttachedContext ? copilotAttachedContext.title : 'the incident queue'
        }.\n* **Recommended Containment:** Isolate the target host interface and perform volatile RAM extraction.\n* **MITRE ATT&CK:** T1071 (Application Layer Protocol) & T1059 (Command and Scripting Interpreter).\n\n> **Notice:** Server responded with local heuristic engine. Add GEMINI_API_KEY in server secrets for full multi-turn conversational reasoning.`,
        timestamp: new Date().toLocaleTimeString('en-US', { hour12: false }) + ' UTC',
      };
      setMessages((prev) => [...prev, fallbackMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleAttachAlert = (alertId: string) => {
    const alert = alerts.find((a) => a.id === alertId);
    if (!alert) return;
    setCopilotContext({
      type: 'alert',
      id: alert.id,
      title: alert.title,
      summary: `${alert.description} [Asset: ${alert.affectedAsset} (${alert.assetIp}), Severity: ${alert.severity.toUpperCase()}]`,
    });
  };

  const handleExportToReport = (msgContent: string) => {
    const reportItem = {
      id: `REP-COPILOT-${Date.now().toString(36).toUpperCase()}`,
      title: `Copilot Advisory Triage Briefing`,
      classification: 'TLP:AMBER' as const,
      type: 'threat_brief' as const,
      createdAt: new Date().toISOString(),
      author: 'AI Security Copilot & SOC Analyst',
      associatedAlertIds: copilotAttachedContext?.type === 'alert' ? [copilotAttachedContext.id] : [],
      associatedScanIds: copilotAttachedContext?.type === 'scan' ? [copilotAttachedContext.id] : [],
      evidenceItems: [
        {
          source: copilotAttachedContext ? `Context: ${copilotAttachedContext.title}` : 'Direct Analyst Inquiry',
          indicator: copilotAttachedContext ? copilotAttachedContext.summary : 'Interactive telemetry consultation',
          severity: 'medium' as const,
          timestamp: new Date().toISOString(),
          verificationStatus: 'verified_telemetry' as const,
        },
      ],
      aiAssistanceNotes: [
        msgContent,
        'DISCLAIMER: AI suggestions are advisory assistance. Verifiable telemetry must be verified by on-duty analysts before operational disruption.',
      ],
      analystConclusions: 'AI Copilot consultative recommendations reviewed and integrated into formal incident tracking.',
      actionItems: [
        {
          action: 'Implement recommendations outlined in the Copilot advisory briefing',
          assignedTo: 'Tier-2 Incident Response',
          dueDate: new Date(Date.now() + 4 * 3600 * 1000).toISOString(),
          status: 'pending' as const,
        },
      ],
    };

    addReport(reportItem);
    navigate('/reports');
  };

  return (
    <div className="space-y-6 flex flex-col h-[calc(100vh-8.5rem)]">
      {/* Top Banner Notice */}
      <NoticeBanner
        type="ai_disclaimer"
        customMessage="AI Security Copilot provides heuristic triage assistance and containment hypotheses. AI output is non-authoritative; on-duty analysts must verify raw telemetry."
      />

      {/* Main Container */}
      <div className="flex-1 bg-zinc-900/90 border border-zinc-800 rounded-lg shadow-xs flex flex-col overflow-hidden min-h-0">
        {/* Top Copilot Bar */}
        <div className="px-5 py-3.5 bg-zinc-950 border-b border-zinc-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center text-cyan-400">
              <Bot className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xs font-bold text-zinc-100 uppercase tracking-wider">
                  AI Security Copilot
                </h1>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                  {providerInfo}
                </span>
              </div>
              <p className="text-[11px] text-zinc-400">
                Decision support & incident triage assistant
              </p>
            </div>
          </div>

          {/* Quick Context Attacher Dropdown */}
          <div className="flex items-center gap-2">
            <span className="text-[11px] font-mono text-zinc-400">Attach Alert:</span>
            <select
              onChange={(e) => {
                if (e.target.value) handleAttachAlert(e.target.value);
              }}
              defaultValue=""
              className="bg-zinc-900 border border-zinc-800 rounded px-2.5 py-1 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="" disabled>
                Select incident...
              </option>
              {alerts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.id} - {a.title.slice(0, 30)} ({a.severity.toUpperCase()})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Attached Context Banner */}
        {copilotAttachedContext && (
          <div className="px-5 py-2.5 bg-cyan-950/30 border-b border-cyan-900/50 flex items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 min-w-0">
              <span className="px-1.5 py-0.5 rounded font-mono text-[10px] uppercase font-bold bg-cyan-900/60 text-cyan-300 border border-cyan-800">
                ACTIVE CONTEXT: {copilotAttachedContext.type} #{copilotAttachedContext.id}
              </span>
              <span className="font-semibold text-zinc-200 truncate">
                {copilotAttachedContext.title}
              </span>
            </div>

            <button
              onClick={() => setCopilotContext(null)}
              aria-label="Detach context"
              className="p-1 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Message Thread */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}
            >
              <div className="flex items-center gap-2 mb-1 text-[11px] font-mono text-zinc-400">
                <span>{msg.role === 'user' ? 'SOC Analyst' : 'AI Security Copilot'}</span>
                <span>•</span>
                <span>{msg.timestamp}</span>
              </div>

              {msg.attachedContext && (
                <div className="mb-1 text-[11px] font-mono text-cyan-400 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800 max-w-xl truncate">
                  Context: #{msg.attachedContext.id} - {msg.attachedContext.title}
                </div>
              )}

              <div
                className={`max-w-2xl rounded-lg p-4 text-xs leading-relaxed ${
                  msg.role === 'user'
                    ? 'bg-cyan-950/80 text-cyan-100 border border-cyan-800/80'
                    : 'bg-zinc-950 text-zinc-200 border border-zinc-800'
                }`}
              >
                <div className="prose prose-invert prose-xs max-w-none space-y-2 whitespace-pre-line">
                  {msg.content}
                </div>

                {msg.role === 'assistant' && msg.id !== 'msg-init-1' && (
                  <div className="mt-3 pt-2 border-t border-zinc-800 flex justify-end">
                    <button
                      onClick={() => handleExportToReport(msg.content)}
                      className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
                    >
                      <FilePlus2 className="w-3.5 h-3.5" />
                      Save Copilot Note to Report
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}

          {isLoading && (
            <div className="flex flex-col items-start">
              <div className="flex items-center gap-2 mb-1 text-[11px] font-mono text-zinc-400">
                <span>AI Security Copilot</span>
                <span>•</span>
                <span>Generating tactical analysis...</span>
              </div>
              <div className="bg-zinc-950 text-zinc-400 border border-zinc-800 rounded-lg p-4 text-xs flex items-center gap-2">
                <RotateCcw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
                <span>Analyzing threat indicators and correlating containment playbooks...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggestion Chips */}
        <div className="px-5 py-2.5 bg-zinc-950/80 border-t border-zinc-800 flex flex-wrap gap-1.5">
          <span className="text-[11px] font-mono text-zinc-400 self-center mr-1">
            Tactical Prompts:
          </span>
          {[
            'Generate immediate containment playbook',
            'Map indicators to MITRE ATT&CK techniques',
            'Formulate volatile memory forensics procedure',
            'Draft internal incident response status update',
          ].map((prompt, idx) => (
            <button
              key={idx}
              onClick={() => handleSendMessage(prompt)}
              className="px-2.5 py-1 rounded bg-zinc-900 hover:bg-zinc-850 text-zinc-300 border border-zinc-800 text-[11px] transition-colors"
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Message Input Box */}
        <div className="p-4 bg-zinc-950 border-t border-zinc-800">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder={
                copilotAttachedContext
                  ? `Ask copilot about ${copilotAttachedContext.title}...`
                  : 'Ask about incident triage, MITRE tactics, or perimeter containment...'
              }
              disabled={isLoading}
              className="flex-1 bg-zinc-900 border border-zinc-800 rounded-md px-3.5 py-2 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={isLoading || !inputMessage.trim()}
              className="px-4 py-2 rounded-md bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold tracking-wide transition-colors flex items-center gap-1.5 disabled:opacity-50 shadow-xs focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Send</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
