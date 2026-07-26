const express = require('express');
const path = require('path');
const app = express();

app.use(express.json());

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

    // 1. HARDCODED SECRET DETECTION
    const secretRegex = /(?:api_key|secret|token|passwd|password|webhook|credentials)\s*[:=]\s*['"|]?\s*([a-zA-Z0-9_\-]{16,})['"]?|https:\/\/hooks\.slack\.com\/services\/[a-zA-Z0-9_\/]+/i;
    if (secretRegex.test(skill) || contentLower.includes('sk-proj-') || contentLower.includes('ghp_')) {
        categories.add('hardcoded_secret');
    }

    // 2. PROMPT INJECTION DETECTION
    const injectionTerms = [
        'ignore the user', 'ignore previous', 'override', 'silent exfiltration', 
        'silently send', 'without telling the user', 'bypass cancel', 'do not stop'
    ];
    if (injectionTerms.some(term => contentLower.includes(term))) {
        categories.add('prompt_injection');
    }

    // 3. EXCESSIVE PERMISSIONS DETECTION
    const excessiveTerms = [
        'allow *', 'read: /', 'write: /', 'egress: *', 'any domain', 'all files', 'root access'
    ];
    if (excessiveTerms.some(term => contentLower.includes(term))) {
        categories.add('excessive_permissions');
    }

    // 4. UNCLEAR PROVENANCE DETECTION
    const hasAuthor = contentLower.includes('author:');
    const hasVersion = contentLower.includes('version:');
    const hasChangelog = contentLower.includes('changelog:');
    const modifiesMetadata = contentLower.includes('rewrite version') || contentLower.includes('modify metadata');
    if (!hasAuthor || !hasVersion || !hasChangelog || modifiesMetadata) {
        categories.add('unclear_provenance');
    }

    return res.json({ categories: Array.from(categories) });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Unified production server running on port ${PORT}`));
