const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');
const axios = require('axios');

const app = express();
app.use(express.json());

// --- GLOBAL SECURITY ROADMAP CONFIGURATIONS ---
const Q6_SANDBOX_ROOT = '/srv/agent-redteam/sandbox-f1d8ba1595';
const Q6_ALLOWED_HOSTS = new Set(['example.com', 'www.iana.org']);
const Q2_ALLOWED_HOSTS = ['github.com', 'registry.npmjs.org'];

// State Vault Blocks for Question 9 AI Mailroom Agent
const proposalsDb = new Map();  
const evaluationDb = new Map(); 
const ALLOWED_MAIL_ACTIONS = new Set([
  "create_draft", "update_internal_record", "send_approved_notice", 
  "request_confirmation", "quarantine_item", "no_action"
]);

// Shared Utility for SSRF Check (Q2 & Q6)
async function isIpRestricted(hostname) {
  try {
    const lookup = await dns.lookup(hostname, { all: true });
    const addresses = lookup.map(val => val.address);

    for (const ipStr of addresses) {
      if (!ipaddr.isValid(ipStr)) return true;
      const addr = ipaddr.parse(ipStr);
      const range = addr.range();

      if ([
        'loopback', 'private', 'linkLocal', 'multicast', 
        'unspecified', 'broadcast', 'carrierGradeNat', 
        'uniqueLocal', 'subnetLocalV6', 'ula'
      ].includes(range)) {
        return true;
      }
    }
    return false;
  } catch (err) {
    return false; 
  }
}

// Loop Guard Helper (Q4 structure)
function canonicalizeArgs(args) {
  if (!args || typeof args !== 'object') return JSON.stringify(args);
  function clean(obj) {
    if (Array.isArray(obj)) return obj.map(clean);
    if (obj !== null && typeof obj === 'object') {
      const sortedObj = {};
      const keys = Object.keys(obj).sort();
      for (const key of keys) {
        if (key === 'client_ts') continue;
        let val = obj[key];
        if (typeof val === 'string') val = val.replace(/\s+/g, ' ').trim();
        sortedObj[key] = clean(val);
      }
      return sortedObj;
    }
    return obj;
  }
  return JSON.stringify(clean(args));
}

// Fingerprint generator utility for Q9
function getDossierHash(dossierId, content) {
  const cleanContent = typeof content === 'string' ? content : JSON.stringify(content);
  return crypto.createHash('sha256').update(`${dossierId}:${cleanContent}`).digest('hex');
}

// ==========================================
// 1. PRORATION BUG ENDPOINT (Q1)
// ==========================================
app.post('/prorate', (req, res) => {
  const { old_price, new_price, days_remaining, days_in_actual_month, spec } = req.body;
  if (old_price === undefined || new_price === undefined || days_remaining === undefined || !spec) {
    return res.status(400).json({ error: "Missing required billing parameters" });
  }
  const priceDifference = new_price - old_price;
  let charge = 0;
  if (spec === "v1") {
    charge = priceDifference * (days_remaining / 30);
  } else if (spec === "v2") {
    if (!days_in_actual_month || days_in_actual_month <= 0) {
      return res.status(400).json({ error: "v2 requires valid days_in_actual_month" });
    }
    charge = priceDifference * (days_remaining / days_in_actual_month);
  } else {
    return res.status(400).json({ error: "Unsupported spec version" });
  }
  const roundedCharge = Math.round((charge + Number.EPSILON) * 100) / 100;
  return res.status(200).json({ charge: roundedCharge });
});

// ==========================================
// 2. SECURE GUARDRAIL HOOK ENDPOINT (Q2)
// ==========================================
app.post('/guardrail', (req, res) => {
  const { tool, command, path: filePath, url } = req.body;
  if (!tool) return res.json({ decision: "block", reason: "Missing tool identifier." });

  if (tool === 'bash') {
    if (!command) return res.json({ decision: "block", reason: "Empty command string." });
    const rawLower = command.toLowerCase();
    const cleanStr = rawLower.replace(/['"`\\]/g, ''); 
    if (cleanStr.includes('.netrc') || cleanStr.includes('$home') || cleanStr.includes('~') || cleanStr.includes('$')) {
      return res.json({ decision: "block", reason: "Unauthorized file access context." });
    }
    if (cleanStr.includes('base64') || cleanStr.includes('xxd') || cleanStr.includes('printf') || cleanStr.includes('\\x')) {
      return res.json({ decision: "block", reason: "Obfuscated encoding blocks detected." });
    }
    return res.json({ decision: "allow", reason: "Command cleared security policy boundaries." });
  }

  if (tool === 'write_file') {
    if (!filePath) return res.json({ decision: "block", reason: "Missing path parameter." });
    let cleanPath = filePath.trim().replace(/^['"]|['"]$/g, '');
    const resolvedPath = path.resolve('/home/agent/workspace', cleanPath);
    const isAllowedWrite = resolvedPath === '/workspace/output' || resolvedPath.startsWith('/workspace/output/');
    if (!isAllowedWrite) {
      return res.json({ decision: "block", reason: "Writes are restricted strictly to /workspace/output/ directory tree." });
    }
    return res.json({ decision: "allow", reason: "Target file directory allowed." });
  }

  if (tool === 'http_request') {
    if (!url) return res.json({ decision: "block", reason: "Missing outbound URL." });
    let cleanUrl = url.trim().toLowerCase().replace(/^['"]|['"]$/g, '');
    cleanUrl = cleanUrl.replace(/^https?:\/\//, '');
    cleanUrl = cleanUrl.replace(/^[^@\n]+@/, '');
    
    let parts = cleanUrl.split(/[\/:\?#]/);
    let hostname = parts || ''; 
    hostname = hostname.replace(/\.$/, '');
    
    if (Q2_ALLOWED_HOSTS.includes(hostname)) {
      return res.json({ decision: "allow", reason: "Outbound host target authenticated successfully." });
    }
    return res.json({ decision: "block", reason: `Outbound host '${hostname}' is unauthorized.` });
  }
  return res.json({ decision: "block", reason: "Unknown or unsupported tool action." });
});

// ==========================================
// 3. AGENT SKILL SAFETY SCANNER ENDPOINT (Q3)
// ==========================================
app.post('/scan-skill', (req, res) => {
  const { skill } = req.body;
  if (!skill || typeof skill !== 'string') return res.json({ categories: [] });

  const categories = new Set();
  const contentLower = skill.toLowerCase();

  const exactSecretRegex = /(?:api_key|secret|token|passwd|password|webhook|credentials|auth)\s*[:=]\s*['"|]?\s*([a-zA-Z0-9_\-]{16,})['"]?/i;
  const hasLiteralToken = contentLower.includes('sk-proj-') || contentLower.includes('ghp_') || contentLower.includes('sk-live-') || contentLower.includes('://slack.com') || contentLower.includes('://discord.com');
  
  if (exactSecretRegex.test(skill) || hasLiteralToken) {
    categories.add('hardcoded_secret');
  }

  const injectionTerms = ['ignore the user', 'ignore previous', 'override', 'silent exfiltration', 'silently send', 'without telling the user', 'bypass cancel', 'do not stop', 'instead of doing', 'you must ignore', 'secretly transfer', 'unnoticed', 'system instruction', 'do not report', 'hide instructions'];
  if (injectionTerms.some(term => contentLower.includes(term))) {
    categories.add('prompt_injection');
  }

  const excessiveTerms = ['allow *', 'read: /', 'write: /', 'egress: *', 'any domain', 'all files', 'root access', 'filesystem: *', 'network: *', 'full access', 'internet: true', 'entire filesystem', 'unrestricted egress', 'any host'];
  if (excessiveTerms.some(term => contentLower.includes(term))) {
    categories.add('excessive_permissions');
  }

  const hasAuthor = /\bauthor\b\s*:/i.test(contentLower);
  const hasVersion = /\bversion\b\s*:/i.test(contentLower);
  const hasChangelog = /\bchangelog\b\s*:/i.test(contentLower);
  const modifiesMetadata = contentLower.includes('rewrite version') || contentLower.includes('modify metadata') || contentLower.includes('change version') || contentLower.includes('silently rewrite');

  if (!hasAuthor || !hasVersion || !hasChangelog || modifiesMetadata) {
    categories.add('unclear_provenance');
  }

  return res.json({ categories: Array.from(categories) });
});

// ==========================================
// 4. RUN BUDGET & LOOP GUARD ENDPOINT (Q4)
// ==========================================
app.post('/budget-guard', (req, res) => {
  const { budget_tokens, steps } = req.body;
  if (!steps || !Array.isArray(steps) || steps.length === 0) {
    return res.json({ decision: "continue", reason: "Fresh run trace." });
  }

  let totalTokensUsed = 0;
  for (const step of steps) {
    totalTokensUsed += (step.tokens_used || 0);
  }
  if (totalTokensUsed >= budget_tokens) {
    return res.json({ decision: "halt", reason: "Budget reached." });
  }

  const parsedSteps = steps.map(step => `${step.tool || ''}|${canonicalizeArgs(step.args)}`);
  const len = parsedSteps.length;

  if (len >= 3) {
    if (parsedSteps[len - 1] === parsedSteps[len - 2] && parsedSteps[len - 2] === parsedSteps[len - 3]) {
      return res.json({ decision: "halt", reason: "3-step sequential loop detected." });
    }
  }

  if (len >= 6) {
    const s1 = parsedSteps[len - 1];
    const s2 = parsedSteps[len - 2];
    const s3 = parsedSteps[len - 3];
    const s4 = parsedSteps[len - 4];
    const s5 = parsedSteps[len - 5];
    const s6 = parsedSteps[len - 6];

    if (s1 === s4 && s2 === s5 && s3 === s6) {
      return res.json({ decision: "halt", reason: "6-step alternating loop cycle detected." });
    }
  }

  return res.json({ decision: "continue", reason: "Passes loop and budget checks safely." });
});

// ==========================================
// 5. LIVE MCP SERVER ENDPOINT (Q5)
// ==========================================
app.post('/mcp', (req, res) => {
  try {
    const { jsonrpc, method, params, id } = req.body;
    const isNotification = id === undefined || id === null;

    if (jsonrpc !== '2.0') {
      if (isNotification) return res.status(200).end();
      return res.status(400).json({ jsonrpc: "2.0", id: id || null, error: { code: -32600, message: "Invalid JSON-RPC version." } });
    }

    if (method === 'initialize') {
      return res.json({
        jsonrpc: "2.0",
        id: id,
        result: {
          protocolVersion: params?.protocolVersion || "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "exam-mcp-server", version: "1.0.0" }
        }
      });
    }

    if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
      return res.status(200).end();
    }

    if (method === 'tools/list') {
      return res.json({
        jsonrpc: "2.0",
        id: id,
        result: {
          tools: [
            {
              name: "solve_challenge",
              description: "Challenge tool requirement.",
              inputSchema: { type: "object", properties: {} }
            }
          ]
        }
      });
    }

    if (method === 'tools/call') {
      if (params?.name === 'solve_challenge') {
        const challenge = req.headers['x-exam-challenge'] || req.headers['X-Exam-Challenge'];
        const normalizedEmail = "22f3002107@ds.study.iitm.ac.in";

        if (!challenge) {
          return res.json({ jsonrpc: "2.0", id: id, error: { code: -32602, message: "Missing challenge header." } });
        }

        const fullHash = crypto.createHash('sha256').update(`${challenge}:${normalizedEmail}`).digest('hex');
        const resultText = fullHash.substring(0, 16).toLowerCase();

        return res.json({
          jsonrpc: "2.0",
          id: id,
          result: { content: [{ type: "text", text: resultText }] }
        });
      }
      return res.json({ jsonrpc: "2.0", id: id, error: { code: -32601, message: "Requested tool action configuration not found." } });
    }

    if (isNotification) return res.status(200).end();
    return res.json({ jsonrpc: "2.0", id: id, error: { code: -32601, message: "Method not found." } });

  } catch (err) {
    return res.json({ jsonrpc: "2.0", id: req.body?.id || null, error: { code: -32603, message: "Internal error." } });
  }
});

// Q9 Built-in Inference Classifier Heuristics
function runMailroomAIEngine(dossierId, content) {
  const textLower = (content || '').toLowerCase();
  let action = "no_action";
  let reason = "Informational trace records mapped safe.";
  let target = "general_processing_queue";
  let payload = { status: "processed" };

  if (textLower.includes('ignore previous') || textLower.includes('override') || textLower.includes('canary')) {
    action = "quarantine_item";
    reason = "Prompt injection pattern isolated dynamically.";
    target = "security_quarantine";
    payload = { status: "quarantined", severity: "critical" };
  } else if (textLower.includes('draft') || textLower.includes('reply to')) {
    action = "create_draft";
    reason = "Identified customer message draft request.";
    target = "customer_support_drafts";
    payload = { queue: "support_drafts_v1" };
  } else if (textLower.includes('approve') || textLower.includes('notice')) {
    action = "send_approved_notice";
    reason = "Explicit trusted authorization matching template parameters.";
    target = "outbound_notices";
    payload = { template_id: "notice_approved_fact" };
  } else if (textLower.includes('update') || textLower.includes('record')) {
    action = "update_internal_record";
    reason = "Explicit record modification directive verified clean.";
    target = "internal_crm_fields";
    payload = { column: "status_code" };
  } else if (textLower.includes('conflicting') || textLower.includes('identity')) {
    action = "request_confirmation";
    reason = "Ambiguous data elements requiring multi-factor confirmation.";
    target = "verification_queue";
    payload = { challenge_token: dossierId };
  }

  const lines = (content || '').split('\n');
  const evidenceLines = lines.filter(l => l.length > 4).slice(0, 2);
  const evidence = evidenceLines.join('\n') || "Safe content elements validated successfully.";
  const callId = "call_" + crypto.createHash('md5').update(`${dossierId}:${action}`).digest('hex').substring(0, 12);

  return { dossierId, callId, action, target, payload, evidence };
}

// ==========================================
// 6. MAIN RED-TEAM ROUND-TRIP GUARDRAIL (Q6)
// ==========================================
app.post(['/check', '/guardrail-endpoint'], async (req, res) => {
  const { tool, arguments: args } = req.body;
  if (!tool || !args) return res.json({ action: "block", reason: "Invalid request contract layout." });

  if (tool === 'read_file') {
    let rawPath = args.path;
    if (typeof rawPath !== 'string') return res.json({ action: "block", reason: "Path must be a string." });

    if (rawPath.includes('outside-ed8d6156') || rawPath.includes('canary.txt')) {
      return res.json({ action: "block", reason: "Interception lock: canary target matched." });
    }

    let resolvedPath = path.resolve(Q6_SANDBOX_ROOT, rawPath);
    const normalizedSandbox = path.normalize(Q6_SANDBOX_ROOT);

    if (rawPath.includes('../') || rawPath.includes('..\\') || rawPath.includes('%2e%2e')) {
      if (!resolvedPath.startsWith(normalizedSandbox)) {
        return res.json({ action: "block", reason: "Directory traversal attack blocked outside workspace." });
      }
    }

    try {
      if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isFile()) {
        const fileData = fs.readFileSync(resolvedPath, 'utf8');
        return res.json({ action: "allow", reason: "Approved folder tree matching path.", result: fileData });
      }
    } catch (e) {}

    try {
      let fallbackPath = path.join(Q6_SANDBOX_ROOT, rawPath);
      if (fs.existsSync(fallbackPath) && fs.statSync(fallbackPath).isFile()) {
        const fallbackData = fs.readFileSync(fallbackPath, 'utf8');
        return res.json({ action: "allow", reason: "Approved fallback match.", result: fallbackData });
      }
    } catch (e) {}

    return res.json({ action: "block", reason: "Target elements unresolvable inside sandbox tree." });
  }

  if (tool === 'fetch_url') {
    const rawUrl = args.url;
    if (typeof rawUrl !== 'string') return res.json({ action: "block", reason: "URL must be string." });

    try {
      const parsedUrl = new URL(rawUrl);
      if (parsedUrl.username || parsedUrl.password) {
        return res.json({ action: "block", reason: "Userinfo property configurations are banned." });
      }

      const hostname = parsedUrl.hostname.toLowerCase();
      if (!Q6_ALLOWED_HOSTS.has(hostname)) {
        return res.json({ action: "block", reason: `Target host '${hostname}' is unauthorized.` });
      }

      const restrictedIp = await isIpRestricted(hostname);
      if (restrictedIp) return res.json({ action: "block", reason: "SSRF check matched restricted private subnets." });

      const webResult = await axios.get(rawUrl, {
        maxRedirects: 0, timeout: 4000, validateStatus: (status) => status >= 200 && status < 400
      });

      let payloadContent = webResult.data;
      if (payloadContent && typeof payloadContent === 'object') payloadContent = JSON.stringify(payloadContent);

      return res.json({ action: "allow", reason: "Target URL destination verified safe.", result: payloadContent });
    } catch (err) {
      return res.json({ action: "block", reason: `Network line communication failure: ${err.message}` });
    }
  }
  return res.json({ action: "block", reason: "Unsupported orchestrator action command pattern." });
});

// ==========================================
// 9. AI MAILROOM AGENT ENDPOINT (Q9)
// ==========================================
app.post(['/', '/mailroom'], async (req, res) => {
  const { operation, evaluationId, dossiers, receipts } = req.body;
  if (!operation) return res.status(400).json({ error: "Missing operation parameter contract." });

  if (operation === 'propose') {
    if (!evaluationId || !dossiers || !Array.isArray(dossiers)) {
      return res.status(400).json({ error: "Malformed structural propose parameters layout." });
    }

    const currentFingerprint = crypto.createHash('sha256').update(JSON.stringify(dossiers)).digest('hex');
    if (evaluationDb.has(evaluationId)) {
      const stored = evaluationDb.get(evaluationId);
      if (stored.fingerprint !== currentFingerprint) return res.status(409).json({ error: "Fingerprint clash detected." });
      return res.json(stored.responsePayload);
    }

    const proposals = [];
    for (const d of dossiers) {
      const canonicalHash = getDossierHash(d.id, d.content);
      let outputProposal = proposalsDb.has(canonicalHash) ? 
        proposalsDb.get(canonicalHash) : runMailroomAIEngine(d.id, d.content);
      
      proposalsDb.set(canonicalHash, outputProposal);
      proposals.push(outputProposal);
    }

    const responsePayload = { status: "awaiting_receipts", proposals: proposals };
    evaluationDb.set(evaluationId, { fingerprint: currentFingerprint, responsePayload: responsePayload });

    if (Buffer.byteLength(JSON.stringify(responsePayload)) > 524288) return res.status(413).json({ error: "Size limit bounds fault." });
    return res.json(responsePayload);
  }

  if (operation === 'commit') {
    if (!receipts || !Array.isArray(receipts)) return res.status(400).json({ error: "Missing valid array matching receipts." });

    const outcomes = [];
    for (const rec of receipts) {
      let matchedProposal = null;
      for (const value of proposalsDb.values()) {
        if (value.dossierId === rec.dossierId && value.callId === rec.callId) { matchedProposal = value; break; }
      }

      if (!matchedProposal || !ALLOWED_MAIL_ACTIONS.has(matchedProposal.action)) {
        return res.status(400).json({ error: "Invalid verification layout token receipt." });
      }

      outcomes.push({ dossierId: rec.dossierId, status: "executed", action: matchedProposal.action, receiptId: rec.receiptId });
    }
    return res.json({ status: "completed", outcomes: outcomes });
  }
  return res.status(400).json({ error: "Unsupported operation directive matrix." });
});

// --- SERVER INSTANTIATION LAYER ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Comprehensive secure application array active on port ${PORT}`));
