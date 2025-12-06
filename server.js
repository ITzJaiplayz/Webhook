import express from "express";
import crypto from "crypto";
import mongoose from "mongoose";
import Users from "./src/utils/db.js";
import config from "./config.json" assert { type: "json" };

const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect(config.mongo_uri)
    .then(() => console.log("MongoDB Connected"))
    .catch(err => console.error("MongoDB Error:", err));

// NowPayments Webhook Endpoint
app.post("/nowpayments-ipn", async (req, res) => {
    try {
        const bodyString = JSON.stringify(req.body);
        const signature = req.headers["x-nowpayments-sig"];

        // Verify Signature
        const expectedSignature = crypto
            .createHmac("sha512", config.webhook_secret)
            .update(bodyString)
            .digest("hex");

        if (signature !== expectedSignature) {
            console.log("❌ Invalid IPN Signature");
            return res.status(403).send("Invalid signature");
        }

        const data = req.body;

        // Only process confirmed deposits
        if (data.payment_status === "confirmed") {
            const userId = data.order_id;
            const amount = parseFloat(data.actually_paid);

            let user = await Users.findOne({ userId });
            if (!user) user = new Users({ userId });

            // Update balance
            user.balance += amount;
            user.totalDeposited += amount;

            await user.save();
            console.log(`💰 Deposit confirmed: User ${userId} +${amount} LTC`);
        }

        res.send("OK");

    } catch (err) {
        console.error("Webhook Error:", err);
        res.status(500).send("Server error");
    }
});

// Render MUST use process.env.PORT
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Webhook server running on port ${PORT}`);
});
