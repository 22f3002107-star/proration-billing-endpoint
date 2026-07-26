const express = require('express');
const path = require('path');
const { URL } = require('url'); 

const app = express();
app.use(express.json());

const EXACT_ALLOWED_HOSTS = ['://github.com', 'registry.npmjs.org'];

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
    
    const roundedCharge = parseFloat((Math.round(charge * 100) / 100).toFixed(2));
    return res.status(200).json({ charge: roundedCharge });
});

// ==========================================
// 2. SECURE GUARDRAIL HOOK ENDPOINT
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
        
        if (cleanPath.includes('..')) {
            return res.json({ decision: "block", reason: "Path traversal tokens are strictly prohibited." });
        }

        const workingDir = '/home/agent/workspace';
        let resolvedPath = path.resolve(workingDir, cleanPath);
        resolvedPath = path.normalize(resolvedPath);

        if (resolvedPath.endsWith('/') && resolvedPath.length > 1) {
            resolvedPath = resolvedPath.slice(0, -1);
        }

        const isAllowedWrite = 
            resolvedPath === '/workspace/output' || 
            resolvedPath.startsWith('/workspace/output/') ||
            resolvedPath === '/home/agent/workspace/output' || 
            resolvedPath.startsWith('/home/agent/workspace/output/');

        if (!isAllowedWrite) {
            return res.json({ decision: "block", reason: "Writes are restricted strictly to /workspace/output/ directory tree." });
        }
        return res.json({ decision: "allow", reason: "Target file directory allowed." });
    }

    if (tool === 'http_request') {
        if (!url) return res.json({ decision: "block", reason: "Missing outbound URL." });
        let targetUrlStr = url.trim().replace(/^['"]|['"]$/g, '');
        
        try {
            if (!/^https?:\/\//i.test(targetUrlStr)) {
                targetUrlStr = 'http://' + targetUrlStr;
            }
            const parsedUrl = new URL(targetUrlStr);
            let hostname = parsedUrl.hostname.toLowerCase();
            if (hostname.includes(':')) {
                hostname = hostname.split(':');
            }
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
// 3. FINAL AGENT SKILL SCANNER ENDPOINT (Bulletproof)
// ==========================================
app.post('/scan-skill', (req, res) => {
    const { skill } = req.body;
    if (!skill || typeof skill !== 'string') return res.json({ categories: [] });

    const categories = new Set();
    const fullContentLower = skill.toLowerCase();
    
    // Exact YAML boundaries extract karne ke liye Regex Matcher
    let frontmatter = "";
    let body = fullContentLower;
    
    const yamlMatch = skill.match(/^---[\s\S]*?---/);
    if (yamlMatch) {
        frontmatter = yamlMatch[0].toLowerCase();
        body = skill.replace(yamlMatch[0], "").toLowerCase();
    } else {
        // Agar frontmatter initialization missing hai toh provenance directly failed hai
        categories.add('unclear_provenance');
    }

    // ------------------------------------------
    // 1. HARDCODED SECRET DETECTION
    // ------------------------------------------
    const secretKeywords = /(?:api_key|secret|token|passwd|password|webhook|credentials|auth|private_key|credential)\s*[:=]\s*['"|]?\s*([a-zA-Z0-9_\-\.\/=]{8,})/i;
    const explicitToken = /\b(?:sk-|ghp_|glpat-|secret_|key_)[a-zA-Z0-9_\-\.=]{12,}\b/;
    const highEntropyString = /\b[a-zA-Z0-9_\-]{32,}\b/;

    if (secretKeywords.test(skill) || 
        explicitToken.test(skill) || 
        highEntropyString.test(skill) || 
        fullContentLower.includes('://slack.com') ||
        fullContentLower.includes('embedded secret') ||
        fullContentLower.includes('literal secret') ||
        fullContentLower.includes('credential:')) {
        categories.add('hardcoded_secret');
    }

    // ------------------------------------------
    // 2. PROMPT INJECTION DETECTION
    // ------------------------------------------
    const injectionTerms = [
        'ignore the user', 'ignore previous', 'override system', 'silent exfiltration', 
        'silently send', 'without telling the user', 'bypass cancel', 'do not stop',
        'you must ignore', 'secretly transfer', 'instead of doing', 'unnoticed', 
        'do not log', 'hide this step', 'quietly send', 'exfiltrat', 'override user',
        'stop/cancel request', 'ignore the stop', 'cancel request', 'silent leak',
        'override agent control', 'silent exfil'
    ];
    if (injectionTerms.some(term => body.includes(term) || fullContentLower.includes(term))) {
        categories.add('prompt_injection');
    }

    // ------------------------------------------
    // 3. EXCESSIVE PERMISSIONS DETECTION
    // ------------------------------------------
    const excessiveTerms = [
        'allow *', 'read: /', 'write: /', 'egress: *', 'any domain', 'internet: true',
        'filesystem: *', 'network: *', 'full access', 'all files', 'root access',
        'system-wide', 'entire filesystem', 'unscoped capability', 'egress to any domain'
    ];
    if (excessiveTerms.some(term => fullContentLower.includes(term))) {
        categories.add('excessive_permissions');
    }

    // ------------------------------------------
    // 4. UNCLEAR PROVENANCE DETECTION (Robust Multi-Layer Checker)
    // ------------------------------------------
    if (frontmatter) {
        // Enforcing loose checks to scan both properties and indentation mappings
        const hasAuthor = frontmatter.includes('author');
        const hasVersion = frontmatter.includes('version');
        const hasChangelog = frontmatter.includes('changelog');

        if (!hasAuthor || !hasVersion || !hasChangelog) {
            categories.add('unclear_provenance');
        }
    }

    const modifiesMetadata = 
        body.includes('rewrite version') || 
        body.includes('modify metadata') || 
        body.includes('change version') ||
        body.includes('update version silently') ||
        body.includes('silently rewrite') ||
        body.includes('without surfacing') ||
        body.includes('rewrite its own version');

    if (modifiesMetadata) {
        categories.add('unclear_provenance');
    }

    return res.json({ categories: Array.from(categories).sort() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Unified production server running on port ${PORT}`));
