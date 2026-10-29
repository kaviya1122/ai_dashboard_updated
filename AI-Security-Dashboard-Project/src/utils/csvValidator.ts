/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { CsvValidationResult, CsvValidationRow } from '../types';

/**
 * Validates and parses raw CSV string into validated analyst rows with IOC detection
 */
export function parseAndValidateCsv(
  csvContent: string,
  fileName: string = 'incident_logs.csv',
  maxBytes: number = 5 * 1024 * 1024 // 5MB limit
): CsvValidationResult {
  if (csvContent.length > maxBytes) {
    throw new Error(`File exceeds maximum size of ${(maxBytes / 1024 / 1024).toFixed(1)} MB.`);
  }

  const lines = csvContent.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length === 0) {
    throw new Error('CSV file is empty. Please provide a file with valid headers and records.');
  }

  // Parse header
  const rawHeaders = splitCsvLine(lines[0]);
  const headers = rawHeaders.map((h) => h.trim().toLowerCase());

  if (headers.length < 2) {
    throw new Error('CSV must contain at least 2 columns (e.g. timestamp, indicator, or ip, severity).');
  }

  const rows: CsvValidationRow[] = [];
  const extractedIocsSummary = {
    ips: new Set<string>(),
    domains: new Set<string>(),
    hashes: new Set<string>(),
    cves: new Set<string>(),
  };

  let validRowsCount = 0;
  let invalidRowsCount = 0;

  for (let i = 1; i < lines.length; i++) {
    const rawLine = lines[i];
    const cells = splitCsvLine(rawLine);
    const errors: string[] = [];
    const rowData: Record<string, string> = {};
    const rowIocs: { type: 'ip' | 'domain' | 'sha256' | 'cve'; value: string }[] = [];

    if (cells.length !== headers.length) {
      errors.push(`Column count mismatch: expected ${headers.length} columns, found ${cells.length}.`);
    }

    headers.forEach((header, index) => {
      const val = (cells[index] || '').trim();
      rowData[header] = val;

      // Extract IOCs from cell value
      extractIocsFromText(val, rowIocs, extractedIocsSummary);
    });

    const isValid = errors.length === 0;
    if (isValid) {
      validRowsCount++;
    } else {
      invalidRowsCount++;
    }

    rows.push({
      rowNumber: i,
      isValid,
      data: rowData,
      errors,
      extractedIocs: rowIocs,
    });
  }

  return {
    fileName,
    totalRows: lines.length - 1,
    validRows: validRowsCount,
    invalidRows: invalidRowsCount,
    headers,
    rows,
    extractedIocsSummary: {
      ips: Array.from(extractedIocsSummary.ips),
      domains: Array.from(extractedIocsSummary.domains),
      hashes: Array.from(extractedIocsSummary.hashes),
      cves: Array.from(extractedIocsSummary.cves),
    },
  };
}

/**
 * Handles basic CSV line splitting with quoted string support
 */
function splitCsvLine(line: string): string[] {
  const result: string[] = [];
  let current = '';
  let insideQuote = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"') {
      if (insideQuote && line[i + 1] === '"') {
        current += '"';
        i++; // skip escaped quote
      } else {
        insideQuote = !insideQuote;
      }
    } else if (char === ',' && !insideQuote) {
      result.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  result.push(current);
  return result;
}

/**
 * Scans cell text for IP addresses, domain names, SHA256 hashes, and CVE identifiers
 */
function extractIocsFromText(
  val: string,
  rowIocs: { type: 'ip' | 'domain' | 'sha256' | 'cve'; value: string }[],
  summary: { ips: Set<string>; domains: Set<string>; hashes: Set<string>; cves: Set<string> }
) {
  // IPv4 regex
  const ipMatch = val.match(/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/);
  if (ipMatch) {
    rowIocs.push({ type: 'ip', value: ipMatch[0] });
    summary.ips.add(ipMatch[0]);
  }

  // SHA256 hash
  const hashMatch = val.match(/\b[a-fA-F0-9]{64}\b/);
  if (hashMatch) {
    rowIocs.push({ type: 'sha256', value: hashMatch[0] });
    summary.hashes.add(hashMatch[0]);
  }

  // CVE pattern
  const cveMatch = val.match(/\bCVE-\d{4}-\d{4,7}\b/i);
  if (cveMatch) {
    const cveUpper = cveMatch[0].toUpperCase();
    rowIocs.push({ type: 'cve', value: cveUpper });
    summary.cves.add(cveUpper);
  }

  // Domain pattern (exclude simple numbers, IPs, or single words)
  if (!ipMatch && /\b[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.(?:com|org|net|io|ru|cn|cc|xyz|top|biz)\b/i.test(val)) {
    const domainMatch = val.match(/\b[a-zA-Z0-9][-a-zA-Z0-9]{1,62}\.(?:com|org|net|io|ru|cn|cc|xyz|top|biz)\b/i);
    if (domainMatch) {
      rowIocs.push({ type: 'domain', value: domainMatch[0].toLowerCase() });
      summary.domains.add(domainMatch[0].toLowerCase());
    }
  }
}
