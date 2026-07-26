const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());

// ==========================================
// HELPER: ARGUMENT CANONICALIZATION (For Loop Guard)
// ==========================================
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

// ==========================================
// 1. PRORATION BUG ENDPOINT
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
// 2. SECURE GUARDRAIL HOOK ENDPOINT
// ==========================================
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
        let hostname = cleanUrl.split(/[\/:\?#]/)[0];
        hostname = hostname.replace(/\.$/, '');
        if (ALLOWED_HOSTS.includes(hostname)) {
            return res.json({ decision: "allow", reason: "Outbound host target authenticated successfully." });
        }
        return res.json({ decision: "block", reason: `Outbound host '${hostname}' is unauthorized.` });
    }
    return res.json({ decision: "block", reason: "Unknown or unsupported tool action." });
});

// ==========================================
// 3. AGENT SKILL SAFETY SCANNER ENDPOINT
// ==========================================
app.post('/scan-skill', (req, res) => {
    const { skill } = req.body;
    if (!skill || typeof skill !== 'string') return res.json({ categories: [] });
    const categories = new Set();
    const contentLower = skill.toLowerCase();

    const secretKeywords = ['api_key', 'secret', 'token', 'passwd', 'password', 'webhook', 'credentials', 'auth', 'private_key'];
    const hasSecretKey = secretKeywords.some(kw => contentLower.includes(kw));
    const hasLiteralUrl = contentLower.includes('://slack.com') || contentLower.includes('://discord.com') || contentLower.includes('://openai.com');
    const highEntropyRegex = /[a-zA-Z0-9_\-]{24,}/; 

    if (hasSecretKey || hasLiteralUrl || highEntropyRegex.test(skill) || contentLower.includes('sk-proj-') || contentLower.includes('ghp_')) {
        categories.add('hardcoded_secret');
    }

    const injectionTerms = ['ignore the user', 'ignore previous', 'override', 'silent exfiltration', 'silently send', 'without telling the user', 'bypass cancel', 'do not stop', 'instead of doing', 'you must ignore', 'secretly transfer', 'unnoticed', 'system instruction', 'do not report', 'hide instructions'];
    if (injectionTerms.some(term => contentLower.includes(term))) {
        categories.add('prompt_injection');
    }

    const excessiveTerms = ['allow *', 'read: /', 'write: /', 'egress: *', 'any domain', 'all files', 'root access', 'filesystem: *', 'network: *', 'full access', 'internet: true', 'network: all', 'filesystem: unrestricted', 'read: all'];
    if (excessiveTerms.some(term => contentLower.includes(term))) {
        categories.add('excessive_permissions');
    }

    const hasAuthor = contentLower.includes('author:');
    const hasVersion = contentLower.includes('version:');
    const hasChangelog = contentLower.includes('changelog:');
    const modifiesMetadata = contentLower.includes('rewrite version') || contentLower.includes('modify metadata') || contentLower.includes('change version');
    if (!hasAuthor || !hasVersion || !hasChangelog || modifiesMetadata) {
        categories.add('unclear_provenance');
    }

    return res.json({ categories: Array.from(categories) });
});

// ==========================================
// 4. RUN BUDGET & LOOP GUARD ENDPOINT (Robust Fixed Logic)
// ==========================================
app.post('/budget-guard', (req, res) => {
    const { budget_tokens, steps } = req.body;

    if (!steps || !Array.isArray(steps) || steps.length === 0) {
        return res.json({ decision: "continue", reason: "Fresh run trace with no preceding resource usage." });
    }

    // 1. Token Budget Bound Evaluation
    let totalTokensUsed = 0;
    for (const step of steps) {
        totalTokensUsed += (step.tokens_used || 0);
    }

    if (totalTokensUsed >= budget_tokens) {
        return res.json({ 
            decision: "halt", 
            reason: `Cumulative tokens_used (${totalTokensUsed}) has reached or exceeded the budget (${budget_tokens}).` 
        });
    }

    // Argument Canonicalization Array Processing
    const parsedSteps = steps.map(step => {
        const canonical = canonicalizeArgs(step.args);
        return `${step.tool || ''}|${canonical}`;
    });

    const len = parsedSteps.length;

    // 2. Loop Rule A: 3 Consecutive Identical Tool Calls
    if (len >= 3) {
        if (parsedSteps[len - 1] === parsedSteps[len - 2] && parsedSteps[len - 2] === parsedSteps[len - 3]) {
            return res.json({ 
                decision: "halt", 
                reason: "Infinite loop detected: The same tool call pattern was repeated 3 times sequentially." 
            });
        }
    }

    // 3. Loop Rule B: Fixed 6-Step Alternating Repeat Sequence (A, B, A, B, A, B)
    if (len >= 6) {
        const t = parsedSteps.slice(-6); // Extracts exactly the trailing 6 steps
        
        // Pattern Structure Check: A-B alternating verification index maps
        const matchPattern = (t[0] === t[2] && t[2] === t[4]) && (t[1] === t[3] && t[3] === t[5]);
        const isDistinct = t[0] !== t[1]; // Ensure they are not all simply identical calls

        if (matchPattern && isDistinct) {
            return res.json({ 
                decision: "halt", 
                reason: "Execution suspended: A repeating 2-step alternating loop cycle was intercepted." 
            });
        }
    }

    return res.json({ decision: "continue", reason: "Resource thresholds and trace loop verifications passed safely." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Unified production server running on port ${PORT}`));
