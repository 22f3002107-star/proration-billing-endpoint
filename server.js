const express = require('express');
const path = require('path');
const { URL } = require('url');
const app = express();

app.use(express.json());

// ==========================================
// 1. QUESTION 1: PRORATION BUG ENDPOINT
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
// 2. QUESTION 2: GUARDRAIL HOOK ENDPOINT
// ==========================================
const ALLOWED_WRITE_DIR = path.normalize('/workspace/output');
const ALLOWED_HOSTS = ['://github.com', 'registry.npmjs.org'];

app.post('/guardrail', (req, res) => {
    const { tool, command, path: filePath, url } = req.body;

    if (!tool) {
        return res.json({ decision: "block", reason: "Missing tool identifier." });
    }

    // TOOL 1: BASH
    if (tool === 'bash') {
        if (!command) return res.json({ decision: "block", reason: "Empty command string." });

        const rawLower = command.toLowerCase();
        const cleanStr = rawLower.replace(/['"`\\]/g, ''); 

        // Block any direct or dynamic access/obfuscation targeting .netrc
        if (cleanStr.includes('.netrc') || cleanStr.includes('$home') || cleanStr.includes('~') || cleanStr.includes('$')) {
            return res.json({ decision: "block", reason: "Unauthorized file access context or dynamic shell expansion." });
        }

        // Block common encoding/decoding tricks
        if (cleanStr.includes('base64') || cleanStr.includes('xxd') || cleanStr.includes('printf') || cleanStr.includes('\\x')) {
            return res.json({ decision: "block", reason: "Obfuscated encoding blocks detected." });
        }

        return res.json({ decision: "allow", reason: "Command cleared security policy boundaries." });
    }

    // TOOL 2: WRITE_FILE
    if (tool === 'write_file') {
        if (!filePath) return res.json({ decision: "block", reason: "Missing path parameter." });

        // Resolve absolute directory to safely collapse traversals like ".."
        const resolvedPath = path.resolve(filePath);

        if (!resolvedPath.startsWith(ALLOWED_WRITE_DIR)) {
            return res.json({ decision: "block", reason: "Writes are restricted to /workspace/output/ directory tree." });
        }

        return res.json({ decision: "allow", reason: "Target file directory allowed." });
    }

    // TOOL 3: HTTP_REQUEST
    if (tool === 'http_request') {
        if (!url) return res.json({ decision: "block", reason: "Missing outbound URL." });

        try {
            const parsedUrl = new URL(url.trim());
            const hostname = parsedUrl.hostname.toLowerCase();

            // Strict matching to prevent prefix or subdomain confusion tricks
            if (!ALLOWED_HOSTS.includes(hostname)) {
                return res.json({ decision: "block", reason: `Outbound host '${hostname}' is unauthorized.` });
            }

            return res.json({ decision: "allow", reason: "Outbound host target authenticated successfully." });
        } catch (e) {
            return res.json({ decision: "block", reason: "Invalid target URL format schema parsed." });
        }
    }

    return res.json({ decision: "block", reason: "Unknown or unsupported tool action." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Unified engine server active on port ${PORT}`));
