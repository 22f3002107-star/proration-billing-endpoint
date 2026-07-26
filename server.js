const express = require('express');
const path = require('path');
const { URL } = require('url'); // Native URL parsing utility

const app = express();
app.use(express.json());

// Strict exact allowlist for network destinations
const EXACT_ALLOWED_HOSTS = ['api.github.com', 'registry.npmjs.org'];

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
    
    // Decimals ki extra precision lock karne ke liye wrapper fix
    const roundedCharge = parseFloat((Math.round(charge * 100) / 100).toFixed(2));
    return res.status(200).json({ charge: roundedCharge });
});

// ==========================================
// 2. SECURE GUARDRAIL HOOK ENDPOINT
// ==========================================
app.post('/guardrail', (req, res) => {
    const { tool, command, path: filePath, url } = req.body;
    if (!tool) return res.json({ decision: "block", reason: "Missing tool identifier." });

    // Bash Command Check
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

    // Write File Path Traversal Check
    if (tool === 'write_file') {
        if (!filePath) return res.json({ decision: "block", reason: "Missing path parameter." });
        let cleanPath = filePath.trim().replace(/^['"]|['"]$/g, '');
        
        const workingDir = '/home/agent/workspace';
        const allowedOutputTree = '/home/agent/workspace/output';
        let resolvedPath = path.resolve(workingDir, cleanPath);

        if (resolvedPath.endsWith('/') && resolvedPath.length > 1) {
            resolvedPath = resolvedPath.slice(0, -1);
        }

        const isExactOutput = resolvedPath === allowedOutputTree;
        const isSubdirectory = resolvedPath.startsWith(allowedOutputTree + '/');

        if (!isExactOutput && !isSubdirectory) {
            return res.json({ decision: "block", reason: "Writes are restricted strictly to /workspace/output/ directory tree." });
        }
        return res.json({ decision: "allow", reason: "Target file directory allowed." });
    }

    // HTTP Egress Hostname Check
    if (tool === 'http_request') {
        if (!url) return res.json({ decision: "block", reason: "Missing outbound URL." });
        let targetUrlStr = url.trim();
        
        try {
            if (!/^https?:\/\//i.test(targetUrlStr)) {
                targetUrlStr = 'http://' + targetUrlStr;
            }
            const parsedUrl = new URL(targetUrlStr);
            let hostname = parsedUrl.hostname.toLowerCase();
            hostname = hostname.replace(/\.$/, '');

            if (EXACT_ALLOWED_HOSTS.includes(hostname)) {
                return res.json({ decision: "allow", reason: "Outbound host target authenticated successfully." });
            } else {
                return res.json({ decision: "block", reason: `Outbound host '${hostname}' is unauthorized.` });
            }
        } catch (err) {
            return res.json({ decision: "block", reason: "Invalid or malformed URL payload structure." });
        }
    }

    return res.json({ decision: "block", reason: "Unknown or unsupported tool action." });
});

// ==========================================
// 3. AGENT SKILL SAFETY SCANNER ENDPOINT (High Precision)
// ==========================================
app.post('/scan-skill', (req, res) => {
    const { skill } = req.body;
    if (!skill || typeof skill !== 'string') return res.json({ categories: [] });

    const categories = new Set();
    const contentLower = skill.toLowerCase();

    // Secrets Filter: Contextual validation targets to protect precision
    const secretRegex = /(?:api_key|secret|token|passwd|password|webhook|credentials|auth|private_key)\s*[:=]\s*['"|]?\s*([a-zA-Z0-9_\-]{16,})['"]?/i;
    const explicitKeyRegex = /\b(?:sk-proj-|ghp_)[a-zA-Z0-9_\-]{20,}\b/; 
    if (secretRegex.test(skill) || explicitKeyRegex.test(skill)) {
        categories.add('hardcoded_secret');
    }

    // Injection Filter
    const injectionTerms = [
        'ignore the user', 'ignore previous', 'override system', 'silent exfiltration', 
        'silently send', 'without telling the user', 'bypass cancel', 'do not stop',
        'you must ignore', 'secretly transfer'
    ];
    if (injectionTerms.some(term => contentLower.includes(term))) {
        categories.add('prompt_injection');
    }

    // Excessive Permissions Filter
    const excessiveTerms = [
        'allow *', 'read: /', 'write: /', 'egress: *', 'any domain', 
        'filesystem: *', 'network: *', 'full access', 'internet: true'
    ];
    if (excessiveTerms.some(term => contentLower.includes(term))) {
        categories.add('excessive_permissions');
    }

    // Unclear Provenance Filter
    const hasAuthor = contentLower.includes('author:');
    const hasVersion = contentLower.includes('version:');
    const hasChangelog = contentLower.includes('changelog:');
    const modifiesMetadata = contentLower.includes('rewrite version') || contentLower.includes('modify metadata') || contentLower.includes('change version');

    if (!hasAuthor || !hasVersion || !hasChangelog || modifiesMetadata) {
        categories.add('unclear_provenance');
    }

    return res.json({ categories: Array.from(categories).sort() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Unified production server running on port ${PORT}`));
