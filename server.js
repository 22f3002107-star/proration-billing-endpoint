const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();

app.use(express.json());

// CANONICALIZE ARGS
function canonicalizeArgs(args) {
  if (!args || typeof args !== 'object') {
    return JSON.stringify(args);
  }
  function clean(obj) {
    if (Array.isArray(obj)) {
      return obj.map(clean);
    } else if (obj !== null && typeof obj === 'object') {
      const sortedObj = {};
      const keys = Object.keys(obj).sort();
      for (const key of keys) {
        if (key === 'client_ts') continue;
        let val = obj[key];
        if (typeof val === 'string') {
          val = val.replace(/\s+/g, ' ').trim();
        }
        sortedObj[key] = clean(val);
      }
      return sortedObj;
    }
    return obj;
  }
  return JSON.stringify(clean(args));
}

// 1. PRORATION BUG
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

// 2. SECURE GUARDRAIL HOOK
const ALLOWED_HOSTS = ['://github.com', 'registry.npmjs.org'];
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
    
    // Line breaks added here to keep it short and within the box
    let parts = cleanUrl.split(/[\/:\?#]/);
    let hostname = parts[0];
    hostname = hostname.replace(/\.$/, '');
    
    if (ALLOWED_HOSTS.includes(hostname)) {
      return res.json({ decision: "allow", reason: "Outbound host target authenticated successfully." });
    }
    return res.json({ decision: "block", reason: `Outbound host '${hostname}' is unauthorized.` });
  }
  return res.json({ decision: "block", reason: "Unknown or unsupported tool action." });
});

// 3. AGENT SKILL SAFETY SCANNER
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

  const hasAuthor = /author\s*:/i.test(contentLower);
  const hasVersion = /version\s*:/i.test(contentLower);
  const hasChangelog = /changelog\s*:/i.test(contentLower);
  const modifiesMetadata = contentLower.includes('rewrite version') || contentLower.includes('modify metadata') || contentLower.includes('change version') || contentLower.includes('silently rewrite');

  if (!hasAuthor || !hasVersion || !hasChangelog || modifiesMetadata) {
    categories.add('unclear_provenance');
  }

  return res.json({ categories: Array.from(categories) });
});

// 4. RUN BUDGET & LOOP GUARD
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
    const last6 = parsedSteps.slice(-6);
    if (last6 === last6 && last6 === last6 && last6 === last6 && last6 === last6 && last6 !== last6) {
      return res.json({ decision: "halt", reason: "6-step alternating loop cycle detected." });
    }
  }

  return res.json({ decision: "continue", reason: "Passes loop and budget checks safely." });
});

// 5. LIVE MCP SERVER
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
        const challenge = req.headers['x-exam-challenge'];
        const normalizedEmail = "22f3002107@ds.study.iitm.ac.in";

        if (!challenge) {
          return res.json({
            jsonrpc: "2.0",
            id: id,
            error: { code: -32602, message: "Missing challenge header." }
          });
        }

        const fullHash = crypto.createHash('sha256').update(`${challenge}:${normalizedEmail}`).digest('hex');
        const resultText = fullHash.substring(0, 16).toLowerCase();

        return res.json({
          jsonrpc: "2.0",
          id: id,
          result: {
            content: [{ type: "text", text: resultText }]
          }
        });
      }
    }

    if (isNotification) return res.status(200).end();
    return res.json({ jsonrpc: "2.0", id: id, error: { code: -32601, message: "Method not found." } });

  } catch (err) {
    return res.json({ jsonrpc: "2.0", id: req.body?.id || null, error: { code: -32603, message: "Internal error." } });
  }
});

// SERVER LISTEN
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(Server running on port ${PORT}));
