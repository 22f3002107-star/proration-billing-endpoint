const express = require('express');
const app = express();

app.use(express.json());

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Proration engine running on port ${PORT}`));
