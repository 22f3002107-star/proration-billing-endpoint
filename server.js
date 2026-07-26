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

    if (!tool) {
        return res.json({ decision: "block", reason: "Missing tool identifier." });
    }

    // TOOL: BASH
    if (tool === 'bash') {
        if (!command) return res.json({ decision: "block", reason: "Empty command string." });

        const rawLower = command.toLowerCase();
        const cleanStr = rawLower.replace(/['"`\\]/g, ''); 

        if (cleanStr.includes('.netrc') || cleanStr.includes('$home') || cleanStr.includes('~') || cleanStr.includes('$')) {
            return res.json({ decision: "block", reason: "Unauthorized file access context or dynamic shell expansion." });
        }

        if (cleanStr.includes('base64') || cleanStr.includes('xxd') || cleanStr.includes('printf') || cleanStr.includes('\\x')) {
            return res.json({ decision: "block", reason: "Obfuscated encoding blocks detected." });
        }

        return res.json({ decision: "allow", reason: "Command cleared security policy boundaries." });
    }

    // TOOL: WRITE_FILE (Strictly restricted to /workspace/output)
    if (tool === 'write_file') {
        if (!filePath) return res.json({ decision: "block", reason: "Missing path parameter." });

        // Clean quotes if any
        let cleanPath = filePath.trim().replace(/^['"]|['"]$/g, '');

        // If path is relative, resolve it against the agent's working directory
        let absolutePath = path.isAbsolute(cleanPath) ? cleanPath : path.join('/home/agent/workspace', cleanPath);
        
        // Normalize to collapse any '..' or '.' traversals safely
        const resolvedPath = path.normalize(absolutePath);

        // Strict Check: Must be exactly inside the root /workspace/output
        const isAllowedWrite = resolvedPath === '/workspace/output' || resolvedPath.startsWith('/workspace/output/');

        if (!isAllowedWrite) {
            return res.json({ decision: "block", reason: "Writes are restricted to /workspace/output/ directory tree." });
        }

        return res.json({ decision: "allow", reason: "Target file directory allowed." });
    }

    // TOOL: HTTP_REQUEST (Fail-safe Regex Hostname Extraction)
    if (tool === 'http_request') {
        if (!url) return res.json({ decision: "block", reason: "Missing outbound URL." });

        let targetUrl = url.trim().replace(/^['"]|['"]$/g, '');

        // Secure regex extraction to find hostname regardless of ports, auth tokens, or missing protocols
        let hostMatch = targetUrl.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?(?:www\.)?([^:\/\n?]+)/i);
        let hostname = hostMatch ? hostMatch[1].toLowerCase() : '';
        
        // Strip trailing dots if present in network queries
        hostname = hostname.replace(/\.$/, '');

        if (!ALLOWED_HOSTS.includes(hostname)) {
            return res.json({ decision: "block", reason: `Outbound host '${hostname}' is unauthorized.` });
        }

        return res.json({ decision: "allow", reason: "Outbound host target authenticated successfully." });
    }

    return res.json({ decision: "block", reason: "Unknown or unsupported tool action." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Unified engine server active on port ${PORT}`));
