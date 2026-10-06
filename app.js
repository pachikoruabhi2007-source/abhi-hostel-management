const express = require("express");
const fs = require("fs");
const path = require("path");
const db = require("./db");
const bcrypt = require("bcrypt");
const session = require("express-session");
const sendOTP = require("./email");
const { sendRegistrationOTP, sendWelcomeEmail, sendGoogleLoginOTP } = require("./email");
const crypto = require("crypto");

// Load .env file if present
const envPath = path.join(__dirname, ".env");
if (fs.existsSync(envPath)) {
    const envConfig = fs.readFileSync(envPath, "utf-8");
    envConfig.split("\n").forEach(line => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
            const [key, ...values] = trimmed.split("=");
            if (key && values.length > 0) {
                process.env[key.trim()] = values.join("=").trim().replace(/(^['"]|['"]$)/g, '');
            }
        }
    });
}

const app = express();
app.set("trust proxy", 1);

// ==================== MIDDLEWARE ====================

app.use(express.static("public"));

app.use(express.urlencoded({
    extended: true,
    limit: "10mb"
}));

app.use(express.json({
    limit: "10mb"
}));

// ==================== SECURITY HEADERS & HTTPS ENFORCEMENT ====================
app.use((req, res, next) => {
    // Prevent MIME-type sniffing
    res.setHeader("X-Content-Type-Options", "nosniff");
    // Prevent Clickjacking inside malicious iframes
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    // Cross-Site Scripting (XSS) filter
    res.setHeader("X-XSS-Protection", "1; mode=block");
    // Referrer policy privacy
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    // Enforce HTTPS when deployed in production
    if (process.env.NODE_ENV === "production" && req.headers["x-forwarded-proto"] !== "https") {
        return res.redirect(`https://${req.headers.host}${req.url}`);
    }
    next();
});

// ==================== HARDENED SESSION COOKIE CONFIG ====================
app.use(session({
    secret: process.env.SESSION_SECRET || "hostel_management_secret_key_2026",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true, // Prevents JavaScript document.cookie access (Stops XSS session theft)
        sameSite: "lax", // Protects against Cross-Site Request Forgery (CSRF)
        secure: "auto", // Automatically detects HTTPS behind reverse proxies like Render
        maxAge: 24 * 60 * 60 * 1000 // 24-hour expiration
    }
}));

// XSS Sanitization Helper Function
function escapeHtml(str) {
    if (!str || typeof str !== "string") return str;
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// In-Memory Login Brute-Force Rate Limiter
const loginAttempts = new Map(); // IP -> { count: number, lockedUntil: timestamp }

function checkLoginRateLimit(req, res, next) {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown_ip";
    const now = Date.now();
    const record = loginAttempts.get(ip);

    if (record) {
        if (record.lockedUntil && now < record.lockedUntil) {
            const minutesLeft = Math.ceil((record.lockedUntil - now) / 60000);
            const msg = `Too many failed login attempts. For security, access is temporarily locked for ${minutesLeft} minute(s).`;
            if (req.xhr || req.headers.accept?.includes("json")) {
                return res.status(429).json({ success: false, message: msg });
            }
            return res.status(429).send(msg);
        }
        if (record.lockedUntil && now >= record.lockedUntil) {
            loginAttempts.delete(ip);
        }
    }
    next();
}

function recordFailedLogin(ip) {
    const now = Date.now();
    const record = loginAttempts.get(ip) || { count: 0, firstAttempt: now };
    record.count++;
    if (record.count >= 5) {
        record.lockedUntil = now + 15 * 60 * 1000; // 15-minute lockout after 5 consecutive failures
    }
    loginAttempts.set(ip, record);
}

function clearLoginFailures(ip) {
    loginAttempts.delete(ip);
}

const PORT = process.env.PORT || 3000;


// ==================== LOGIN PROTECTION & NO-CACHE ====================

function setNoCacheHeaders(res) {
    res.set({
        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0",
        "Surrogate-Control": "no-store"
    });
}

function requireLogin(req, res, next) {
    setNoCacheHeaders(res);
    if (!req.session.userId) {
        return res.redirect("/login");
    }
    next();
}


// ==================== STUDENT LOGIN PROTECTION ====================

function requireStudent(req, res, next) {
    setNoCacheHeaders(res);
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    const role = (req.session.role || "").toLowerCase().trim();
    if (role === "admin") {
        return res.redirect("/dashboard");
    }

    next();
}


// ==================== ADMIN LOGIN PROTECTION ====================

function requireAdmin(req, res, next) {
    setNoCacheHeaders(res);
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    const role = (req.session.role || "").toLowerCase().trim();
    if (role !== "admin") {
        return res.redirect("/student-dashboard");
    }

    next();
}


// ==================== SYSTEM & DATABASE HEALTH CHECK ====================

app.get(["/health", "/api/health", "/api/db-status"], (req, res) => {
    db.query("SHOW TABLES", (err, tables) => {
        if (err) {
            return res.status(500).json({
                status: "error",
                message: "Database connection failed",
                error: err.message,
                code: err.code || null,
                sqlMessage: err.sqlMessage || null,
                configuredHost: process.env.DB_HOST || (process.env.DATABASE_URL ? "DATABASE_URL is set" : "localhost (default)")
            });
        }

        db.query("SELECT user_id, email, role, name FROM users", (uErr, uRes) => {
            res.json({
                status: "ok",
                database: "connected",
                tableCount: tables ? tables.length : 0,
                userCount: uRes ? uRes.length : 0,
                users: uRes ? uRes.map(u => ({ id: u.user_id, email: u.email, role: u.role, name: u.name })) : [],
                configuredHost: process.env.DB_HOST || (process.env.DATABASE_URL ? "via DATABASE_URL" : "localhost")
            });
        });
    });
});


// ==================== HOME & PUBLIC COMPLIANCE PAGES ====================

app.get("/", (req, res) => {
    res.sendFile(__dirname + "/views/index.html");
});

app.get(["/contact", "/contact-us"], (req, res) => {
    res.sendFile(__dirname + "/views/contact.html");
});

app.get(["/about", "/about-us"], (req, res) => {
    res.sendFile(__dirname + "/views/about.html");
});

app.get(["/terms", "/terms-and-conditions", "/terms-of-service"], (req, res) => {
    res.sendFile(__dirname + "/views/terms.html");
});

app.get(["/privacy", "/privacy-policy"], (req, res) => {
    res.sendFile(__dirname + "/views/privacy.html");
});

app.get(["/refund-policy", "/refunds", "/cancellation-refund-policy", "/cancellation-policy"], (req, res) => {
    res.sendFile(__dirname + "/views/refund-policy.html");
});


// ==================== ADMIN DASHBOARD PAGE ====================

app.get(
    "/dashboard",
    requireAdmin,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/dashboard.html"
        );

    }
);


// ==================== ADMIN FEES ====================

app.get("/fees", requireAdmin, (req, res) => {
    res.sendFile(__dirname + "/views/fees.html");
});


// ==================== ADMIN SETTINGS PAGE ====================

app.get("/settings", requireAdmin, (req, res) => {
    res.sendFile(__dirname + "/views/settings.html");
});


// ==================== STUDENT SETTINGS PAGE ====================

app.get("/student-settings", requireStudent, (req, res) => {
    res.sendFile(__dirname + "/views/student-settings.html");
});


// ==================== REVIEWS & FEEDBACK PAGES ====================

app.get("/student-reviews", requireStudent, (req, res) => {
    res.sendFile(__dirname + "/views/student-reviews.html");
});

app.get("/admin-reviews", requireAdmin, (req, res) => {
    res.sendFile(__dirname + "/views/admin-reviews.html");
});

app.get("/reviews", (req, res) => {
    if (req.session && req.session.userId) {
        if (req.session.role === "admin") {
            return res.redirect("/admin-reviews");
        } else {
            return res.redirect("/student-reviews");
        }
    }
    res.redirect("/login");
});



// ==================== STUDENT DASHBOARD PAGE ====================

app.get(
    "/student-dashboard",
    requireStudent,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/student-dashboard.html"
        );

    }
);


// ==================== STUDENT PROFILE PAGE ====================

app.get(
    "/student-profile",
    requireStudent,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/student-profile.html"
        );

    }
);


// ==================== STUDENT ROOM PAGE ====================

app.get(
    "/student-room",
    requireStudent,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/student-room.html"
        );

    }
);


// ==================== STUDENT FEES PAGE ====================

app.get(
    "/student-fees",
    requireStudent,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/student-fees.html"
        );

    }
);


// ==================== STUDENT / RESIDENT ROOM API ====================

app.get(
    "/api/student-room",
    requireStudent,
    (req, res) => {

        const userId = req.session.userId;
        const userName = req.session.name || "";

        const sql = `
            SELECT
                r.room_no,
                r.room_type,
                r.total_beds,
                r.occupied_beds,
                (r.total_beds - r.occupied_beds) AS available_beds,
                COALESCE(r.ac_type, 'Non-AC') AS ac_type,
                COALESCE(r.monthly_rent, 6500) AS room_rent,
                s.food_plan,
                s.check_in_date,
                s.expected_checkout_date,
                s.stay_type
            FROM students s
            INNER JOIN rooms r
                ON s.room_no = r.room_no
            WHERE s.user_id = ? OR LOWER(TRIM(s.name)) = LOWER(TRIM(?))
            LIMIT 1
        `;

        db.query(sql, [userId, userName], (err, results) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Database error"
                });
            }

            if (results.length === 0) {
                return res.status(404).json({
                    error: "Room details not found. Please contact administration to assign a room."
                });
            }

            res.json(results[0]);

        });

    }
);


// ==================== STUDENT FEES API ====================

app.get(
    "/api/student-fees",
    requireStudent,
    (req, res) => {
        const userId = req.session.userId;
        const userName = req.session.name || "";

        const sql = `
            SELECT
                fee_id,
                total_fee,
                paid_amount,
                pending_amount,
                status,
                COALESCE(month_name, 'October 2026') AS month_name,
                COALESCE(billing_month, '2026-10') AS billing_month,
                COALESCE(fee_type, 'Monthly Stay Fee') AS fee_type,
                due_date
            FROM fees
            WHERE user_id = ? OR LOWER(TRIM(student_name)) = LOWER(TRIM(?))
            ORDER BY fee_id ASC
        `;

        db.query(sql, [userId, userName], (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: "Database error" });
            }

            if (!results || results.length === 0) {
                return res.status(404).json({ error: "Fee details not found" });
            }

            let cumulativeTotal = 0;
            let cumulativePaid = 0;
            let cumulativePending = 0;
            const unpaidMonths = [];

            results.forEach(row => {
                const total = Number(row.total_fee) || 0;
                const paid = Number(row.paid_amount) || 0;
                const pending = Number(row.pending_amount) !== null && !isNaN(Number(row.pending_amount))
                    ? Number(row.pending_amount)
                    : Math.max(0, total - paid);

                cumulativeTotal += total;
                cumulativePaid += paid;
                cumulativePending += pending;

                if (pending > 0) {
                    unpaidMonths.push(row.month_name || "Current Month");
                }
            });

            // Latest invoice details
            const latest = results[results.length - 1];
            const isAdvance = (latest.fee_type || "").includes("Advance");

            let noticeMessage = "";
            if (cumulativePending > 0) {
                if (unpaidMonths.length > 1) {
                    noticeMessage = `🔔 Monthly Stay Fee Notice: You have a total balance of ₹${cumulativePending.toLocaleString("en-IN")} pending across ${unpaidMonths.length} months (${unpaidMonths.join(", ")}). Please pay your pending stay fees to keep your room active.`;
                } else if (unpaidMonths.length === 1) {
                    noticeMessage = isAdvance
                        ? `🔔 Joining Advance Notice: Your admission & initial stay fee of ₹${cumulativePending.toLocaleString("en-IN")} is pending. Please pay to confirm your stay.`
                        : `🔔 Monthly Stay Fee Notice: Your monthly stay fee of ₹${cumulativePending.toLocaleString("en-IN")} for ${unpaidMonths[0]} is due. Please pay to keep your room active.`;
                }
            } else {
                noticeMessage = `✓ All Clear: All your monthly stay fees up to ${latest.month_name || 'date'} are completely paid.`;
            }

            const hostelUpiMobile = process.env.HOSTEL_UPI_MOBILE || "9876543210";
            const hostelUpiId = process.env.HOSTEL_UPI_ID || (hostelUpiMobile ? `${hostelUpiMobile}@ybl` : "hostel.fees@okhdfcbank");
            const hostelUpiName = process.env.HOSTEL_UPI_NAME || "Hostel Management";

            const feeData = {
                fee_id: latest.fee_id,
                total_fee: cumulativeTotal,
                paid_amount: cumulativePaid,
                pending_amount: cumulativePending,
                status: cumulativePending === 0 ? "Paid" : (cumulativePaid > 0 ? "Partial" : "Pending"),
                month_name: latest.month_name,
                billing_month: latest.billing_month,
                fee_type: latest.fee_type,
                due_date: latest.due_date,
                student_name: latest.student_name || userName,
                monthly_notice_message: noticeMessage,
                unpaid_months_count: unpaidMonths.length,
                unpaid_months: unpaidMonths,
                invoices: results,
                upi_mobile: hostelUpiMobile,
                upi_id: hostelUpiId,
                upi_name: hostelUpiName
            };

            res.json(feeData);
        });
    }
);

// ==================== STUDENT UPI PAYMENT API ====================

app.post(
    "/api/student-fees/upi-pay",
    requireStudent,
    (req, res) => {
        const userId = req.session.userId;
        const userName = req.session.name || "";
        const { amount, utr_number, upi_app, upi_vpa, payment_mode } = req.body;

        const paymentAmount = Number(amount);
        if (!paymentAmount || paymentAmount <= 0) {
            return res.status(400).json({ error: "Please enter a valid payment amount greater than ₹0." });
        }

        const findFeeSql = `
            SELECT fee_id, user_id, student_name, total_fee, paid_amount, pending_amount, status, month_name
            FROM fees
            WHERE user_id = ? OR LOWER(TRIM(student_name)) = LOWER(TRIM(?))
            ORDER BY fee_id ASC
        `;

        db.query(findFeeSql, [userId, userName], async (err, feeResults) => {
            if (err) {
                console.error("UPI Pay Fee Query Error:", err);
                return res.status(500).json({ error: "Database error while fetching fee record." });
            }

            if (!feeResults || feeResults.length === 0) {
                return res.status(404).json({ error: "Fee account not found for this resident." });
            }

            // Calculate total pending across all billing records
            let totalPending = 0;
            feeResults.forEach(f => {
                totalPending += Number(f.pending_amount) || 0;
            });

            if (paymentAmount > totalPending) {
                return res.status(400).json({
                    error: `Payment amount ₹${paymentAmount.toLocaleString('en-IN')} exceeds total outstanding pending balance of ₹${totalPending.toLocaleString('en-IN')}.`
                });
            }

            // Cascade payment to oldest unpaid invoices first (FIFO)
            let remainingToAllocate = paymentAmount;
            const updatePromises = [];

            for (const invoice of feeResults) {
                const invoicePending = Number(invoice.pending_amount) || 0;
                if (invoicePending <= 0 || remainingToAllocate <= 0) continue;

                const paymentForThisInvoice = Math.min(remainingToAllocate, invoicePending);
                const currentPaid = Number(invoice.paid_amount) || 0;
                const newPaid = currentPaid + paymentForThisInvoice;
                const newPending = invoicePending - paymentForThisInvoice;
                const newStatus = newPending === 0 ? "Paid" : "Partial";

                remainingToAllocate -= paymentForThisInvoice;

                const updatePromise = new Promise((resolve, reject) => {
                    db.query(
                        "UPDATE fees SET paid_amount = ?, pending_amount = ?, status = ? WHERE fee_id = ?",
                        [newPaid, newPending, newStatus, invoice.fee_id],
                        (uErr) => {
                            if (uErr) reject(uErr);
                            else resolve();
                        }
                    );
                });

                updatePromises.push(updatePromise);
            }

            try {
                await Promise.all(updatePromises);

                const txnId = "PAY" + Date.now().toString(36).toUpperCase() + Math.floor(1000 + Math.random() * 9000);
                const finalUtr = utr_number && utr_number.trim() ? utr_number.trim() : ("UTR" + Math.floor(100000000000 + Math.random() * 900000000000));
                const appUsed = upi_app || "PhonePe";
                const studentDisplayName = feeResults[0].student_name || userName;
                const vpaUsed = upi_vpa || process.env.HOSTEL_UPI_ID || (process.env.HOSTEL_UPI_MOBILE ? `${process.env.HOSTEL_UPI_MOBILE}@ybl` : "hostel.fees@okhdfcbank");
                const finalMode = payment_mode || `UPI (${appUsed})`;

                const insertPaymentSql = `
                    INSERT INTO payments
                    (user_id, student_name, amount, payment_mode, upi_id, utr_number, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'Success')
                `;

                db.query(
                    insertPaymentSql,
                    [userId, studentDisplayName, paymentAmount, finalMode, vpaUsed, finalUtr],
                    (insertPayErr, payResult) => {
                        if (insertPayErr) {
                            console.warn("Notice: payment transaction log error:", insertPayErr.message);
                        }

                        const remainingBalance = Math.max(0, totalPending - paymentAmount);

                        res.json({
                            success: true,
                            message: `Payment of ₹${paymentAmount.toLocaleString("en-IN")} received successfully via UPI!`,
                            receipt: {
                                paymentId: payResult ? payResult.insertId : null,
                                txnId: txnId,
                                utrNumber: finalUtr,
                                amount: paymentAmount,
                                studentName: studentDisplayName,
                                date: new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }),
                                totalFee: totalPending,
                                newPaidAmount: paymentAmount,
                                newPendingAmount: remainingBalance,
                                status: remainingBalance === 0 ? "Paid" : "Partial",
                                paymentMode: `UPI (${appUsed})`
                            }
                        });
                    }
                );
            } catch (allocErr) {
                console.error("UPI Pay Allocation Error:", allocErr);
                return res.status(500).json({ error: "Error updating fee balance across months." });
            }
        });
    }
);


// ==================== OFFICIAL PHONEPE PAYMENT GATEWAY API ====================

// Endpoint to initiate official PhonePe payment
app.post("/api/phonepe/initiate", requireStudent, async (req, res) => {
    try {
        const userId = req.session.userId;
        const userName = req.session.name || "Resident";
        const { amount } = req.body;

        const paymentAmount = Number(amount);
        if (!paymentAmount || paymentAmount <= 0) {
            return res.status(400).json({ error: "Invalid payment amount." });
        }

        const findFeeSql = `
            SELECT fee_id, user_id, student_name, total_fee, paid_amount, pending_amount, status
            FROM fees
            WHERE user_id = ? OR LOWER(TRIM(student_name)) = LOWER(TRIM(?))
            ORDER BY fee_id DESC
            LIMIT 1
        `;

        db.query(findFeeSql, [userId, userName], async (feeErr, feeResults) => {
            if (feeErr || feeResults.length === 0) {
                return res.status(404).json({ error: "Fee account not found for this resident." });
            }

            const fee = feeResults[0];
            const currentPending = Number(fee.pending_amount);
            if (paymentAmount > currentPending) {
                return res.status(400).json({
                    error: `Payment amount ₹${paymentAmount.toLocaleString('en-IN')} exceeds current pending balance of ₹${currentPending.toLocaleString('en-IN')}.`
                });
            }

            const merchantId = (process.env.PHONEPE_MERCHANT_ID || "PGTESTPAYUAT").trim();
            const saltKey = (process.env.PHONEPE_SALT_KEY || "099eb0cd-02cf-4e2a-8aca-3e6c6aff0399").trim();
            const saltIndex = (process.env.PHONEPE_SALT_INDEX || "1").trim();
            const env = (process.env.PHONEPE_ENV || "UAT").trim().toUpperCase();

            const baseUrl = env === "PROD"
                ? "https://api.phonepe.com/apis/hermes"
                : "https://api-preprod.phonepe.com/apis/pg-sandbox";

            const merchantTransactionId = "TXN" + Date.now() + Math.floor(1000 + Math.random() * 9000);
            const amountInPaise = Math.round(paymentAmount * 100);

            // Construct host for redirect and callback
            const host = req.get("host") || "localhost:3000";
            const protocol = req.protocol || "http";
            const redirectUrl = `${protocol}://${host}/api/phonepe/callback?txnId=${merchantTransactionId}`;
            const callbackUrl = `${protocol}://${host}/api/phonepe/callback?txnId=${merchantTransactionId}`;

            const normalPayload = {
                merchantId: merchantId,
                merchantTransactionId: merchantTransactionId,
                merchantUserId: "MUID_" + userId,
                amount: amountInPaise,
                redirectUrl: redirectUrl,
                redirectMode: "POST",
                callbackUrl: callbackUrl,
                mobileNumber: process.env.HOSTEL_UPI_MOBILE || "9704844011",
                paymentInstrument: {
                    type: "PAY_PAGE"
                }
            };

            const base64Payload = Buffer.from(JSON.stringify(normalPayload)).toString("base64");
            const stringToHash = base64Payload + "/pg/v1/pay" + saltKey;
            const sha256 = crypto.createHash("sha256").update(stringToHash).digest("hex");
            const xVerify = `${sha256}###${saltIndex}`;

            // Save pending transaction state in session
            req.session.phonepePendingTxn = {
                txnId: merchantTransactionId,
                userId: userId,
                studentName: fee.student_name || userName,
                amount: paymentAmount,
                totalFee: Number(fee.total_fee),
                currentPaid: Number(fee.paid_amount),
                feeId: fee.fee_id
            };

            try {
                const response = await fetch(`${baseUrl}/pg/v1/pay`, {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-VERIFY": xVerify,
                        "accept": "application/json"
                    },
                    body: JSON.stringify({
                        request: base64Payload
                    })
                });

                const data = await response.json();

                if (data.success && data.data && data.data.instrumentResponse && data.data.instrumentResponse.redirectInfo) {
                    const payUrl = data.data.instrumentResponse.redirectInfo.url;
                    return res.json({
                        success: true,
                        redirectUrl: payUrl,
                        merchantTransactionId: merchantTransactionId
                    });
                } else {
                    console.warn("PhonePe API response notice:", data);
                    const isKeyNotConfigured = data.code === "KEY_NOT_CONFIGURED";
                    const errorMsg = isKeyNotConfigured
                        ? "PhonePe Business API requires registered Merchant Credentials. Please provide your live PHONEPE_MERCHANT_ID and PHONEPE_SALT_KEY in .env."
                        : (data.message || "PhonePe Gateway returned an error.");
                    return res.json({
                        success: false,
                        code: data.code || "PHONEPE_ERROR",
                        error: errorMsg,
                        details: data
                    });
                }
            } catch (apiErr) {
                console.error("PhonePe Gateway Connection Error:", apiErr.message);
                return res.status(500).json({
                    success: false,
                    error: "Unable to reach PhonePe Payment Gateway server. Please check your network connection or credentials."
                });
            }
        });
    } catch (err) {
        console.error("PhonePe Initiate Exception:", err);
        res.status(500).json({ error: "Internal server error while initializing PhonePe payment." });
    }
});

// PhonePe Callback Handler (Handles POST and GET from PhonePe redirect)
app.all("/api/phonepe/callback", async (req, res) => {
    try {
        const txnId = req.query.txnId || (req.body && req.body.transactionId) || (req.body && req.body.merchantTransactionId);
        const pending = req.session.phonepePendingTxn;

        const merchantId = (process.env.PHONEPE_MERCHANT_ID || "PGTESTPAYUAT").trim();
        const saltKey = (process.env.PHONEPE_SALT_KEY || "099eb0cd-02cf-4e2a-8aca-3e6c6aff0399").trim();
        const saltIndex = (process.env.PHONEPE_SALT_INDEX || "1").trim();
        const env = (process.env.PHONEPE_ENV || "UAT").trim().toUpperCase();

        const baseUrl = env === "PROD"
            ? "https://api.phonepe.com/apis/hermes"
            : "https://api-preprod.phonepe.com/apis/pg-sandbox";

        let paymentSuccess = false;
        let finalUtr = "UTR" + Math.floor(100000000000 + Math.random() * 900000000000);

        if (txnId) {
            try {
                // Verify with PhonePe Status API
                const statusEndpoint = `/pg/v1/status/${merchantId}/${txnId}`;
                const stringToHash = statusEndpoint + saltKey;
                const sha256 = crypto.createHash("sha256").update(stringToHash).digest("hex");
                const xVerify = `${sha256}###${saltIndex}`;

                const statusRes = await fetch(`${baseUrl}${statusEndpoint}`, {
                    method: "GET",
                    headers: {
                        "Content-Type": "application/json",
                        "X-VERIFY": xVerify,
                        "X-MERCHANT-ID": merchantId,
                        "accept": "application/json"
                    }
                });

                const statusData = await statusRes.json();
                if (statusData.code === "PAYMENT_SUCCESS") {
                    paymentSuccess = true;
                    if (statusData.data && statusData.data.transactionId) {
                        finalUtr = statusData.data.transactionId;
                    }
                }
            } catch (verifyErr) {
                console.warn("PhonePe Status Verification Exception:", verifyErr.message);
            }
        }

        // If verified successfully and we have pending transaction
        if (paymentSuccess && pending) {
            const newPaid = pending.currentPaid + pending.amount;
            const newPending = Math.max(0, pending.totalFee - newPaid);
            const newStatus = newPending === 0 ? "Paid" : "Partial";

            const updateFeeSql = `
                UPDATE fees
                SET paid_amount = ?, pending_amount = ?, status = ?
                WHERE fee_id = ?
            `;

            db.query(updateFeeSql, [newPaid, newPending, newStatus, pending.feeId], (updErr) => {
                if (updErr) console.error("Error updating fee in PhonePe callback:", updErr);

                const insertPaySql = `
                    INSERT INTO payments
                    (user_id, student_name, amount, payment_mode, upi_id, utr_number, status)
                    VALUES (?, ?, ?, 'PhonePe Official Gateway', ?, ?, 'Success')
                `;

                const vpa = process.env.HOSTEL_UPI_ID || "9704844011@ybl";
                db.query(insertPaySql, [pending.userId, pending.studentName, pending.amount, vpa, finalUtr], (insErr) => {
                    if (insErr) console.warn("Error inserting payment in PhonePe callback:", insErr);
                    delete req.session.phonepePendingTxn;
                    return res.redirect(`/student-fees?payment_success=true&txn=${txnId}&amount=${pending.amount}`);
                });
            });
        } else if (paymentSuccess) {
            return res.redirect(`/student-fees?payment_success=true&txn=${txnId || 'TXN_SUCCESS'}`);
        } else {
            return res.redirect(`/student-fees?payment_failed=true&msg=Payment%20was%20not%20completed%20or%20cancelled`);
        }
    } catch (e) {
        console.error("PhonePe Callback Fatal Error:", e);
        res.redirect("/student-fees?payment_failed=true&msg=Error%20processing%20payment%20response");
    }
});


// ==================== OFFICIAL RAZORPAY PAYMENT GATEWAY API ====================

// 1. Create Razorpay Order
app.post("/api/razorpay/create-order", requireStudent, async (req, res) => {
    try {
        const userId = req.session.userId;
        const userName = req.session.name || "Resident";
        const { amount } = req.body;

        const paymentAmount = Number(amount);
        if (!paymentAmount || paymentAmount <= 0) {
            return res.status(400).json({ success: false, error: "Please enter a valid payment amount greater than ₹0." });
        }

        const findFeeSql = `
            SELECT fee_id, user_id, student_name, total_fee, paid_amount, pending_amount, status
            FROM fees
            WHERE user_id = ? OR LOWER(TRIM(student_name)) = LOWER(TRIM(?))
            ORDER BY fee_id DESC
            LIMIT 1
        `;

        db.query(findFeeSql, [userId, userName], async (feeErr, feeResults) => {
            if (feeErr || feeResults.length === 0) {
                return res.status(404).json({ success: false, error: "Fee account not found for this resident." });
            }

            const fee = feeResults[0];
            const currentPending = Number(fee.pending_amount);
            if (paymentAmount > currentPending) {
                return res.status(400).json({
                    success: false,
                    error: `Payment amount ₹${paymentAmount.toLocaleString('en-IN')} exceeds current pending balance of ₹${currentPending.toLocaleString('en-IN')}.`
                });
            }

            const keyId = (process.env.RAZORPAY_KEY_ID || "").trim();
            const keySecret = (process.env.RAZORPAY_KEY_SECRET || "").trim();

            if (!keyId || !keySecret) {
                return res.status(400).json({
                    success: false,
                    code: "KEY_NOT_CONFIGURED",
                    error: "Razorpay API keys are not configured yet in .env. Please enter your RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET from https://dashboard.razorpay.com (Settings -> API Keys)."
                });
            }

            const amountInPaise = Math.round(paymentAmount * 100);
            const receiptId = "rcpt_" + Date.now().toString().slice(-8);
            const basicAuth = Buffer.from(`${keyId}:${keySecret}`).toString("base64");

            try {
                const response = await fetch("https://api.razorpay.com/v1/orders", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Basic ${basicAuth}`
                    },
                    body: JSON.stringify({
                        amount: amountInPaise,
                        currency: "INR",
                        receipt: receiptId,
                        notes: {
                            userId: String(userId),
                            studentName: String(fee.student_name || userName),
                            feeId: String(fee.fee_id)
                        }
                    })
                });

                const orderData = await response.json();

                if (!response.ok || orderData.error) {
                    console.error("Razorpay Order Creation Failed:", orderData);
                    return res.status(400).json({
                        success: false,
                        error: (orderData.error && orderData.error.description) ? orderData.error.description : "Failed to create Razorpay Order. Please check your credentials."
                    });
                }

                // Return order details to frontend checkout modal
                return res.json({
                    success: true,
                    orderId: orderData.id,
                    amount: orderData.amount,
                    currency: orderData.currency,
                    keyId: keyId,
                    studentName: fee.student_name || userName,
                    studentEmail: req.session.email || "",
                    studentContact: process.env.HOSTEL_UPI_MOBILE || "9704844011",
                    feeId: fee.fee_id
                });
            } catch (apiErr) {
                console.error("Razorpay API Network Error:", apiErr);
                return res.status(500).json({
                    success: false,
                    error: "Unable to contact Razorpay server. Please check your internet connection."
                });
            }
        });
    } catch (err) {
        console.error("Razorpay Route Exception:", err);
        res.status(500).json({ success: false, error: "Internal server error while initializing Razorpay order." });
    }
});

// 2. Verify Razorpay Payment Signature and Credit Fee
app.post("/api/razorpay/verify", requireStudent, (req, res) => {
    try {
        const userId = req.session.userId;
        const userName = req.session.name || "Resident";
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature, amount, feeId } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ success: false, error: "Missing required Razorpay payment verification parameters." });
        }

        const keySecret = (process.env.RAZORPAY_KEY_SECRET || "").trim();
        if (!keySecret) {
            return res.status(500).json({ success: false, error: "Razorpay Secret Key not configured on server." });
        }

        // Generate HMAC SHA256 Signature
        const generatedSignature = crypto
            .createHmac("sha256", keySecret)
            .update(`${razorpay_order_id}|${razorpay_payment_id}`)
            .digest("hex");

        if (generatedSignature !== razorpay_signature) {
            console.warn("Razorpay Signature Mismatch! Expected:", generatedSignature, "Got:", razorpay_signature);
            return res.status(400).json({ success: false, error: "Payment verification failed: Signature does not match." });
        }

        const paymentAmount = Number(amount);

        const findFeeSql = `
            SELECT fee_id, user_id, student_name, total_fee, paid_amount, pending_amount, status
            FROM fees
            WHERE fee_id = ? OR user_id = ? OR LOWER(TRIM(student_name)) = LOWER(TRIM(?))
            ORDER BY fee_id DESC
            LIMIT 1
        `;

        db.query(findFeeSql, [feeId || 0, userId, userName], (feeErr, feeResults) => {
            if (feeErr || feeResults.length === 0) {
                return res.status(404).json({ success: false, error: "Fee record not found to update." });
            }

            const fee = feeResults[0];
            const currentTotal = Number(fee.total_fee);
            const currentPaid = Number(fee.paid_amount);
            const newPaid = currentPaid + paymentAmount;
            const newPending = Math.max(0, currentTotal - newPaid);
            const newStatus = newPending === 0 ? "Paid" : "Partial";

            const updateFeeSql = `
                UPDATE fees
                SET paid_amount = ?, pending_amount = ?, status = ?
                WHERE fee_id = ?
            `;

            db.query(updateFeeSql, [newPaid, newPending, newStatus, fee.fee_id], (updateErr) => {
                if (updateErr) {
                    console.error("Razorpay Fee Update Error:", updateErr);
                    return res.status(500).json({ success: false, error: "Error updating fee balance in database." });
                }

                const studentDisplayName = fee.student_name || userName;
                const insertPaymentSql = `
                    INSERT INTO payments
                    (user_id, student_name, amount, payment_mode, upi_id, utr_number, status)
                    VALUES (?, ?, ?, 'Razorpay Gateway', 'razorpay@checkout', ?, 'Success')
                `;

                db.query(
                    insertPaymentSql,
                    [userId, studentDisplayName, paymentAmount, razorpay_payment_id],
                    (insErr, payResult) => {
                        if (insErr) {
                            console.warn("Payment log insertion warning:", insErr.message);
                        }

                        res.json({
                            success: true,
                            message: `Payment of ₹${paymentAmount.toLocaleString("en-IN")} completed successfully via Razorpay!`,
                            receipt: {
                                paymentId: payResult ? payResult.insertId : null,
                                txnId: razorpay_order_id,
                                utrNumber: razorpay_payment_id,
                                amount: paymentAmount,
                                studentName: studentDisplayName,
                                date: new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" }),
                                totalFee: currentTotal,
                                newPaidAmount: newPaid,
                                newPendingAmount: newPending,
                                status: newStatus,
                                paymentMode: "Razorpay (Card/UPI/Netbanking)"
                            }
                        });
                    }
                );
            });
        });
    } catch (err) {
        console.error("Razorpay Verify Exception:", err);
        res.status(500).json({ success: false, error: "Internal server error verifying Razorpay transaction." });
    }
});


// ==================== STUDENT PAYMENT HISTORY API ====================

app.get(
    "/api/student-fees/history",
    requireStudent,
    (req, res) => {

        const userId = req.session.userId;
        const userName = req.session.name || "";

        const sql = `
            SELECT
                payment_id,
                amount,
                payment_mode,
                upi_id,
                utr_number,
                status,
                DATE_FORMAT(created_at, '%d %b %Y, %h:%i %p') AS payment_date
            FROM payments
            WHERE user_id = ? OR LOWER(TRIM(student_name)) = LOWER(TRIM(?))
            ORDER BY payment_id DESC
            LIMIT 20
        `;

        db.query(sql, [userId, userName], (err, results) => {

            if (err) {
                console.error("Payment history error:", err);
                return res.status(500).json({ error: "Database error" });
            }

            res.json(results || []);

        });

    }
);


// ==================== STUDENT / RESIDENT PROFILE API ====================

app.get(
    "/api/student-profile",
    requireStudent,
    (req, res) => {

        const userId = req.session.userId;
        const userName = req.session.name || "";

        const sql = `
            SELECT
                u.user_id,
                u.name,
                u.email,
                COALESCE(s.phone, u.phone) AS phone,
                u.role,
                s.student_id,
                s.room_no,
                COALESCE(s.resident_type, 'Jobholder') AS resident_type,
                s.company_or_college,
                s.designation_or_course,
                s.office_address,
                s.id_proof_type,
                s.id_proof_number,
                s.id_proof_file,
                s.id_proof_filename,
                COALESCE(s.id_proof_status, 'Pending Verification') AS id_proof_status,
                s.id_proof_rejection_reason,
                s.native_city,
                s.stay_type,
                s.check_in_date,
                s.expected_checkout_date,
                s.monthly_rent,
                s.security_deposit,
                s.food_plan,
                s.emergency_name,
                s.emergency_phone,
                COALESCE(u.profile_photo, s.profile_photo) AS profile_photo
            FROM users u
            LEFT JOIN students s
                ON s.user_id = u.user_id 
                OR LOWER(TRIM(s.email)) = LOWER(TRIM(u.email))
                OR LOWER(TRIM(s.name)) = LOWER(TRIM(u.name))
            WHERE u.user_id = ?
            LIMIT 1
        `;

        db.query(sql, [userId], (err, results) => {

            if (err) {
                console.error(err);
                return res.status(500).json({
                    error: "Database error"
                });
            }

            if (results.length === 0) {
                return res.status(404).json({
                    error: "Resident profile not found"
                });
            }

            const profile = results[0];
            // Security: Aadhaar / Government ID number is stored securely in database,
            // but NEVER exposed in plain text to anyone in the user profile (masked format only).
            const rawNum = profile.id_proof_number ? String(profile.id_proof_number).trim() : "";
            profile.id_proof_number_masked = rawNum 
                ? ("•••• •••• " + (rawNum.length >= 4 ? rawNum.slice(-4) : "••••"))
                : "Stored & Confidential";
            profile.id_proof_number = profile.id_proof_number_masked;
            profile.id_proof_status = profile.id_proof_status || "Pending Verification";
            profile.is_verified = (profile.id_proof_status === "Verified");

            res.json(profile);

        });

    }
);


// ==================== REPORTS PAGE ====================

app.get(
    "/reports",
    requireAdmin,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/reports.html"
        );

    }
);


// ==================== DASHBOARD / REPORTS API ====================

app.get(
    "/api/dashboard",
    requireAdmin,
    (req, res) => {

        const queries = {
            students:
                "SELECT COUNT(*) AS total_students FROM students",

            jobholders:
                "SELECT COUNT(*) AS total FROM students WHERE LOWER(COALESCE(resident_type, 'jobholder')) = 'jobholder'",

            transfers:
                "SELECT COUNT(*) AS total FROM students WHERE LOWER(resident_type) = 'transfer'",

            studentResidents:
                "SELECT COUNT(*) AS total FROM students WHERE LOWER(resident_type) = 'student'",

            rooms:
                "SELECT COUNT(*) AS total_rooms FROM rooms",

            occupied:
                "SELECT COALESCE(SUM(occupied_beds), 0) AS occupied_beds FROM rooms",

            available:
                "SELECT COALESCE(SUM(total_beds - occupied_beds), 0) AS available_beds FROM rooms",

            pendingComplaints:
                "SELECT COUNT(*) AS pending_complaints FROM complaints WHERE status = 'Pending'",

            resolvedComplaints:
                "SELECT COUNT(*) AS resolved_complaints FROM complaints WHERE status = 'Resolved'",

            pendingNotices:
                "SELECT COUNT(*) AS pending_notices FROM vacating_notices WHERE status = 'Pending Review'",

            financials:
                "SELECT COALESCE(SUM(monthly_rent), 0) AS expected_rent, COALESCE(SUM(security_deposit), 0) AS total_deposits FROM students"
        };

        db.query(queries.students, (err, studentResult) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: "Database error" });
            }

            db.query(queries.jobholders, (err, jobResult) => {
                db.query(queries.transfers, (err, transResult) => {
                    db.query(queries.studentResidents, (err, stuResResult) => {
                        db.query(queries.rooms, (err, roomResult) => {
                            if (err) return res.status(500).json({ error: "Database error" });

                            db.query(queries.occupied, (err, occupiedResult) => {
                                db.query(queries.available, (err, availableResult) => {
                                    db.query(queries.pendingComplaints, (err, pendingResult) => {
                                        db.query(queries.resolvedComplaints, (err, resolvedResult) => {
                                            db.query(queries.pendingNotices, (err, noticeResult) => {
                                                db.query(queries.financials, (err, finResult) => {
                                                    const total = studentResult[0] ? studentResult[0].total_students : 0;
                                                    const jobs = (jobResult && jobResult[0]) ? jobResult[0].total : 0;
                                                    const trans = (transResult && transResult[0]) ? transResult[0].total : 0;
                                                    const stus = (stuResResult && stuResResult[0]) ? stuResResult[0].total : 0;
                                                    const notices = (noticeResult && noticeResult[0]) ? noticeResult[0].pending_notices : 0;
                                                    const expRent = (finResult && finResult[0]) ? finResult[0].expected_rent : 0;
                                                    const depTotal = (finResult && finResult[0]) ? finResult[0].total_deposits : 0;

                                                    res.json({
                                                        total_students: total,
                                                        total_residents: total,
                                                        jobholder_count: jobs,
                                                        transfer_count: trans,
                                                        student_count: stus,
                                                        total_rooms: (roomResult && roomResult[0]) ? roomResult[0].total_rooms : 0,
                                                        occupied_beds: (occupiedResult && occupiedResult[0]) ? occupiedResult[0].occupied_beds : 0,
                                                        available_beds: (availableResult && availableResult[0]) ? availableResult[0].available_beds : 0,
                                                        pending_complaints: (pendingResult && pendingResult[0]) ? pendingResult[0].pending_complaints : 0,
                                                        resolved_complaints: (resolvedResult && resolvedResult[0]) ? resolvedResult[0].resolved_complaints : 0,
                                                        pending_notices: notices,
                                                        expected_monthly_rent: expRent,
                                                        total_deposits: depTotal
                                                    });
                                                });
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                });
            });
        });
    }
);


// ==================== STUDENTS ====================


// ==================== GET STUDENTS ====================

app.get(
    "/api/students",
    requireAdmin,
    (req, res) => {

        db.query(
            "SELECT * FROM students",
            (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error: "Database error"
                    });

                }

                res.json(results);

            }
        );

    }
);


// ==================== GOVERNMENT ID VALIDATION (AADHAAR / PAN) ====================

function validateGovernmentId(idType, idNumber) {
    if (!idNumber || typeof idNumber !== "string" || !idNumber.trim()) {
        return {
            valid: false,
            error: "Government ID Proof (Aadhaar or PAN Card) is mandatory. Please provide a valid ID number."
        };
    }

    const cleanNum = idNumber.trim().toUpperCase().replace(/[\s-]/g, "");
    const cleanType = (idType || "Aadhaar Card").trim();

    if (cleanType.toLowerCase().includes("aadhaar")) {
        // Aadhaar: exactly 12 numeric digits, must not start with 0 or 1
        if (!/^[2-9]\d{11}$/.test(cleanNum)) {
            return {
                valid: false,
                error: "Invalid Aadhaar number. Must be exactly 12 numeric digits and cannot start with 0 or 1."
            };
        }
        return { valid: true, cleanType: "Aadhaar Card", cleanNum: cleanNum };
    } else if (cleanType.toLowerCase().includes("pan")) {
        // PAN Card: 5 letters, 4 digits, 1 letter (e.g. ABCDE1234F)
        if (!/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(cleanNum)) {
            return {
                valid: false,
                error: "Invalid PAN Card number. Must be 10 characters in standard format (e.g. ABCDE1234F)."
            };
        }
        return { valid: true, cleanType: "PAN Card", cleanNum: cleanNum };
    } else if (cleanType.toLowerCase().includes("passport")) {
        if (!/^[A-Z][0-9]{7}$/.test(cleanNum)) {
            return {
                valid: false,
                error: "Invalid Passport number. Format must be 1 letter followed by 7 digits."
            };
        }
        return { valid: true, cleanType: "Passport", cleanNum: cleanNum };
    } else if (cleanType.toLowerCase().includes("voter")) {
        if (!/^[A-Z]{3}[0-9]{7}$/.test(cleanNum)) {
            return {
                valid: false,
                error: "Invalid Voter ID number. Format must be 3 letters followed by 7 digits."
            };
        }
        return { valid: true, cleanType: "Voter ID", cleanNum: cleanNum };
    } else {
        if (cleanNum.length < 6 || cleanNum.length > 25) {
            return {
                valid: false,
                error: "Invalid government ID number. Must be between 6 and 25 characters."
            };
        }
        return { valid: true, cleanType: cleanType, cleanNum: cleanNum };
    }
}


// ==================== SECURE ID PROOF STORAGE & CONFIDENTIALITY ====================

const SECURE_ID_DIR = path.join(__dirname, "secure_uploads", "id_proofs");
if (!fs.existsSync(SECURE_ID_DIR)) {
    fs.mkdirSync(SECURE_ID_DIR, { recursive: true });
}

function saveSecureIdDocument(dataUrl, originalName, prefix = "id_doc") {
    if (!dataUrl || typeof dataUrl !== "string") return null;
    if (!dataUrl.startsWith("data:")) return null;

    const matches = dataUrl.match(/^data:([a-zA-Z0-9\/\+.-]+);base64,(.+)$/);
    if (!matches || matches.length !== 3) {
        throw new Error("Invalid document upload format. Please select an image (JPG, PNG, WebP) or PDF.");
    }

    const mime = matches[1].toLowerCase();
    const base64Data = matches[2];
    const buffer = Buffer.from(base64Data, "base64");

    if (buffer.length > 10 * 1024 * 1024) {
        throw new Error("ID Proof document size exceeds the 10MB limit.");
    }

    let ext = "png";
    if (mime.includes("pdf")) ext = "pdf";
    else if (mime.includes("jpeg") || mime.includes("jpg")) ext = "jpg";
    else if (mime.includes("webp")) ext = "webp";
    else if (mime.includes("png")) ext = "png";

    const safeTimestamp = Date.now();
    const safeRandom = Math.floor(Math.random() * 1000000);
    const safeFilename = `${prefix}_${safeTimestamp}_${safeRandom}.${ext}`;
    const filePath = path.join(SECURE_ID_DIR, safeFilename);

    fs.writeFileSync(filePath, buffer);
    return safeFilename;
}

function checkDuplicateIdProof(idNumber, excludeStudentId = null) {
    return new Promise((resolve, reject) => {
        if (!idNumber) return resolve(null);
        const clean = idNumber.toString().toUpperCase().replace(/[\s-]/g, "");

        let sql = `
            SELECT student_id, name, email, id_proof_type, id_proof_number
            FROM students
            WHERE REPLACE(REPLACE(UPPER(TRIM(id_proof_number)), ' ', ''), '-', '') = ?
        `;
        const params = [clean];
        if (excludeStudentId) {
            sql += " AND student_id != ?";
            params.push(excludeStudentId);
        }

        db.query(sql, params, (err, rows) => {
            if (err) return reject(err);
            if (rows && rows.length > 0) {
                return resolve(rows[0]);
            }
            resolve(null);
        });
    });
}

// Confidential View Route: Accessible ONLY by Admin or the Resident Owner
app.get("/api/id-proof/view/:studentId", requireLogin, (req, res) => {
    const studentId = parseInt(req.params.studentId, 10);
    if (!studentId) return res.status(400).send("Invalid resident ID");

    db.query("SELECT * FROM students WHERE student_id = ?", [studentId], (err, rows) => {
        if (err || !rows || rows.length === 0) {
            return res.status(404).send("Resident record not found.");
        }
        const resident = rows[0];

        const isAdmin = req.session.role === "admin";
        const isOwner = (resident.user_id && resident.user_id === req.session.userId) ||
                        (req.session.email && resident.email && resident.email.toLowerCase() === req.session.email.toLowerCase()) ||
                        (req.session.name && resident.name && resident.name.toLowerCase() === req.session.name.toLowerCase());

        if (!isAdmin && !isOwner) {
            return res.status(403).send("Access Denied: Government ID proof documents are confidential and accessible ONLY by the verified resident and authorized hostel administrators.");
        }

        if (!resident.id_proof_file) {
            return res.status(404).send("No ID proof document has been uploaded for this resident yet.");
        }

        const filePath = path.join(SECURE_ID_DIR, resident.id_proof_file);
        if (!fs.existsSync(filePath)) {
            return res.status(404).send("Uploaded ID document file was not found on the server.");
        }

        const ext = path.extname(resident.id_proof_file).toLowerCase();
        let contentType = "application/octet-stream";
        if (ext === ".pdf") contentType = "application/pdf";
        else if (ext === ".jpg" || ext === ".jpeg") contentType = "image/jpeg";
        else if (ext === ".png") contentType = "image/png";
        else if (ext === ".webp") contentType = "image/webp";

        res.setHeader("Content-Type", contentType);
        res.setHeader("Content-Disposition", `inline; filename="${resident.id_proof_filename || 'id_proof_document' + ext}"`);
        res.sendFile(filePath);
    });
});


// Admin ID Verification Action: Approve or Reject Resident Government ID
app.post("/api/students/:id/verify-id", requireAdmin, (req, res) => {
    const studentId = parseInt(req.params.id, 10);
    const { status, reason } = req.body; // 'Verified' | 'Rejected' | 'Pending Verification'

    if (!studentId) return res.status(400).json({ error: "Invalid resident ID." });
    if (!["Verified", "Rejected", "Pending Verification"].includes(status)) {
        return res.status(400).json({ error: "Invalid status. Must be Verified, Rejected, or Pending Verification." });
    }

    const rejectionReason = status === "Rejected" ? (reason && reason.trim() ? reason.trim() : "Document copy is blurry, invalid, or details mismatch with registration record.") : null;

    const updateSql = `
        UPDATE students
        SET id_proof_status = ?,
            id_proof_rejection_reason = ?
        WHERE student_id = ?
    `;

    db.query(updateSql, [status, rejectionReason, studentId], (err, result) => {
        if (err) {
            console.error("Error updating ID verification status:", err);
            return res.status(500).json({ error: "Database error while updating ID status." });
        }

        res.json({
            success: true,
            status: status,
            reason: rejectionReason,
            message: status === "Verified" 
                ? "Resident ID proof approved successfully! All hostel permissions and verified badge granted."
                : `Resident ID marked as Rejected. Resident has been notified to re-upload their valid ID.`
        });
    });
});


// Resident Re-upload ID Route (Called when ID was rejected or needs update)
app.post("/api/student/reupload-id", requireStudent, async (req, res) => {
    try {
        const userId = req.session.userId;
        const userName = req.session.name || "";
        const { id_proof_type, id_proof_number, id_proof_file, id_proof_filename } = req.body;

        if (!id_proof_file || typeof id_proof_file !== "string" || !id_proof_file.includes("base64,")) {
            return res.status(400).json({ error: "Please select a valid clear photo (JPG, PNG) or PDF of your ID document." });
        }

        let cleanType = id_proof_type || "Aadhaar Card";
        let cleanNum = null;

        if (id_proof_number && String(id_proof_number).trim()) {
            const idCheck = validateGovernmentId(id_proof_type, id_proof_number);
            if (!idCheck.valid) {
                return res.status(400).json({ error: idCheck.error });
            }
            cleanType = idCheck.cleanType;
            cleanNum = idCheck.cleanNum;

            // Check if duplicate with another resident
            const duplicate = await checkDuplicateIdProof(cleanNum);
            if (duplicate && duplicate.user_id !== userId) {
                return res.status(400).json({
                    error: `Security Alert: This ${cleanType} (${cleanNum}) is already registered with another resident (${duplicate.name}). Each resident must have their own unique government ID.`
                });
            }
        }

        let savedDocFilename = null;
        try {
            savedDocFilename = saveSecureIdDocument(id_proof_file, id_proof_filename, `reupload_${userId}_${Date.now()}`);
        } catch (docErr) {
            return res.status(400).json({ error: docErr.message });
        }

        const updateSql = cleanNum
            ? `UPDATE students
               SET id_proof_type = ?,
                   id_proof_number = ?,
                   id_proof_file = ?,
                   id_proof_filename = ?,
                   id_proof_status = 'Pending Verification',
                   id_proof_rejection_reason = NULL
               WHERE user_id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?))`
            : `UPDATE students
               SET id_proof_file = ?,
                   id_proof_filename = ?,
                   id_proof_status = 'Pending Verification',
                   id_proof_rejection_reason = NULL
               WHERE user_id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?))`;

        const updateParams = cleanNum
            ? [cleanType, cleanNum, savedDocFilename, id_proof_filename || null, userId, userName]
            : [savedDocFilename, id_proof_filename || null, userId, userName];

        db.query(updateSql, updateParams, (err, result) => {
            if (err) {
                console.error("Re-upload ID DB error:", err);
                return res.status(500).json({ error: "Failed to update ID proof record in database." });
            }

            res.json({
                success: true,
                message: "New ID proof document re-uploaded successfully! It has been submitted to Admin for verification.",
                status: "Pending Verification"
            });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});


// ==================== ADD RESIDENT (JOBHOLDER / TRANSFER / STUDENT) ====================

app.post(
    "/api/students",
    requireAdmin,
    async (req, res) => {

        const {
            name,
            room_no,
            department,
            phone,
            resident_type,
            company_or_college,
            designation_or_course,
            office_address,
            id_proof_type,
            id_proof_number,
            id_proof_file,
            id_proof_filename,
            native_city,
            stay_type,
            check_in_date,
            expected_checkout_date,
            monthly_rent,
            security_deposit,
            food_plan,
            emergency_name,
            emergency_phone
        } = req.body;

        // Mandatory Government ID Proof Check (Aadhaar or PAN)
        const idCheck = validateGovernmentId(id_proof_type, id_proof_number);
        if (!idCheck.valid) {
            return res.status(400).json({ error: idCheck.error });
        }

        // Anti-Fraud / Anti-Duplicate ID Check
        try {
            const dup = await checkDuplicateIdProof(idCheck.cleanNum);
            if (dup) {
                return res.status(400).json({
                    error: `This Government ID proof (${idCheck.cleanType} ending in ${idCheck.cleanNum.slice(-4)}) is already registered in the system under resident "${dup.name}". For security, duplicate ID proofs are strictly prohibited.`
                });
            }
        } catch (dupErr) {
            console.error("Duplicate ID check error:", dupErr);
        }

        let savedDocFilename = null;
        if (id_proof_file) {
            try {
                savedDocFilename = saveSecureIdDocument(id_proof_file, id_proof_filename, `admin_add_${Date.now()}`);
            } catch (dErr) {
                return res.status(400).json({ error: dErr.message });
            }
        }

        const resType = resident_type || "Jobholder";
        const compCollege = company_or_college || department || "General";
        const desigCourse = designation_or_course || (resType === "Student" ? "Student" : "Professional");
        const idType = idCheck.cleanType;
        const idNum = idCheck.cleanNum;
        const city = native_city || "";
        const sType = stay_type || "Monthly Stay";
        const checkIn = check_in_date || new Date().toISOString().split("T")[0];
        const checkOut = expected_checkout_date || null;
        const rent = Number(monthly_rent) || 0;
        const deposit = Number(security_deposit) || 0;
        const food = food_plan || "With Food";
        const emergName = emergency_name || "";
        const emergPhone = emergency_phone || "";
        const offAddr = office_address || "";

        const checkRoomSql = `
            SELECT
                total_beds,
                occupied_beds
            FROM rooms
            WHERE room_no = ?
        `;

        db.query(
            checkRoomSql,
            [room_no],
            (err, roomResult) => {

                if (err) {
                    console.log(err);
                    return res.status(500).json({ error: "Database error" });
                }

                if (roomResult.length === 0) {
                    return res.status(400).json({ error: "Room not found" });
                }

                const room = roomResult[0];

                if (
                    room.occupied_beds >=
                    room.total_beds
                ) {
                    return res.status(400).json({ error: "Room is full" });
                }

                const studentSql = `
                    INSERT INTO students
                    (name, room_no, department, phone, resident_type, company_or_college, designation_or_course, office_address, id_proof_type, id_proof_number, id_proof_file, id_proof_filename, native_city, stay_type, check_in_date, expected_checkout_date, monthly_rent, security_deposit, food_plan, emergency_name, emergency_phone)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `;

                db.query(
                    studentSql,
                    [
                        name,
                        room_no,
                        compCollege,
                        phone,
                        resType,
                        compCollege,
                        desigCourse,
                        offAddr,
                        idType,
                        idNum,
                        savedDocFilename,
                        id_proof_filename || null,
                        city,
                        sType,
                        checkIn,
                        checkOut,
                        rent,
                        deposit,
                        food,
                        emergName,
                        emergPhone
                    ],
                    (err, result) => {

                        if (err) {
                            console.log(err);
                            return res.status(500).json({ error: "Error adding resident" });
                        }

                        const updateRoomSql = `
                            UPDATE rooms
                            SET occupied_beds =
                                occupied_beds + 1
                            WHERE room_no = ?
                        `;

                        db.query(
                            updateRoomSql,
                            [room_no],
                            (err, resultUpdate) => {

                                if (err) {
                                    console.log(err);
                                }

                                // Create fee record for monthly rent + security deposit if provided
                                if (rent > 0 || deposit > 0) {
                                    const totalFee = rent + deposit;
                                    const feeSql = `
                                        INSERT INTO fees (student_name, total_fee, paid_amount, pending_amount, status)
                                        VALUES (?, ?, 0, ?, 'Pending')
                                    `;
                                    db.query(feeSql, [name, totalFee, totalFee], () => {});
                                }

                                if (req.headers.accept && req.headers.accept.includes("application/json")) {
                                    return res.json({ success: true, message: "Resident added successfully", id: result.insertId });
                                }

                                res.redirect("/students");

                            }
                        );

                    }
                );

            }
        );

    }
);


// ==================== DELETE STUDENT ====================

app.delete(
    "/api/students/:id",
    requireAdmin,
    (req, res) => {

        const studentId =
            req.params.id;


        const findStudentSql = `
            SELECT room_no
            FROM students
            WHERE student_id = ?
        `;


        db.query(
            findStudentSql,
            [studentId],
            (err, studentResult) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error: "Database error"
                    });

                }


                if (studentResult.length === 0) {

                    return res.status(404).json({
                        error: "Student not found"
                    });

                }


                const roomNo =
                    studentResult[0].room_no;


                const deleteStudentSql = `
                    DELETE FROM students
                    WHERE student_id = ?
                `;


                db.query(
                    deleteStudentSql,
                    [studentId],
                    (err, result) => {

                        if (err) {

                            console.log(err);

                            return res.status(500).json({
                                error:
                                    "Error deleting student"
                            });

                        }


                        const updateRoomSql = `
                            UPDATE rooms
                            SET occupied_beds =
                                occupied_beds - 1
                            WHERE room_no = ?
                              AND occupied_beds > 0
                        `;


                        db.query(
                            updateRoomSql,
                            [roomNo],
                            (err, result) => {

                                if (err) {

                                    console.log(err);

                                    return res.status(500).json({
                                        error:
                                            "Student deleted, but room count could not be updated"
                                    });

                                }


                                res.json({
                                    message:
                                        "Student deleted and room bed released successfully"
                                });

                            }
                        );

                    }
                );

            }
        );

    }
);


// ==================== UPDATE RESIDENT ====================

app.put(
    "/api/students/:id",
    requireAdmin,
    async (req, res) => {

        const studentId =
            req.params.id;

        const {
            name,
            room_no,
            department,
            phone,
            resident_type,
            company_or_college,
            designation_or_course,
            office_address,
            id_proof_type,
            id_proof_number,
            id_proof_file,
            id_proof_filename,
            native_city,
            stay_type,
            check_in_date,
            expected_checkout_date,
            monthly_rent,
            security_deposit,
            food_plan,
            emergency_name,
            emergency_phone
        } = req.body;

        const resType = resident_type || "Jobholder";
        const compCollege = company_or_college || department || "General";
        const desigCourse = designation_or_course || "";
        let idType = id_proof_type || "Aadhaar Card";
        let idNum = id_proof_number || "";
        if (id_proof_number && String(id_proof_number).trim()) {
            const idCheck = validateGovernmentId(id_proof_type, id_proof_number);
            if (!idCheck.valid) {
                return res.status(400).json({ error: idCheck.error });
            }
            idType = idCheck.cleanType;
            idNum = idCheck.cleanNum;

            // Security check: ensure no other resident already has this ID proof number
            const duplicate = await checkDuplicateIdProof(idNum, studentId);
            if (duplicate) {
                return res.status(400).json({
                    error: `Security Alert: This ${idType} (${idNum}) is already registered to resident "${duplicate.name}" (Room: ${duplicate.room_no || 'N/A'}). Two residents cannot share the same government ID.`
                });
            }
        }

        let savedDocFilename = null;
        if (id_proof_file && typeof id_proof_file === 'string' && id_proof_file.includes('base64,')) {
            try {
                savedDocFilename = saveSecureIdDocument(id_proof_file, id_proof_filename, `admin_edit_${studentId}_${Date.now()}`);
            } catch (docErr) {
                return res.status(400).json({ error: docErr.message });
            }
        }

        const city = native_city || "";
        const sType = stay_type || "Monthly Stay";
        const checkIn = check_in_date || null;
        const checkOut = expected_checkout_date || null;
        const rent = Number(monthly_rent) || 0;
        const deposit = Number(security_deposit) || 0;
        const food = food_plan || "With Food";
        const emergName = emergency_name || "";
        const emergPhone = emergency_phone || "";
        const offAddr = office_address || "";

        const findStudentSql = `
            SELECT room_no
            FROM students
            WHERE student_id = ?
        `;

        db.query(
            findStudentSql,
            [studentId],
            (err, studentResult) => {

                if (err) {
                    console.log(err);
                    return res.status(500).json({ error: "Database error" });
                }

                if (studentResult.length === 0) {
                    return res.status(404).json({ error: "Resident not found" });
                }

                const oldRoomNo =
                    studentResult[0].room_no;

                const baseUpdateParams = [
                    name,
                    compCollege,
                    phone,
                    resType,
                    compCollege,
                    desigCourse,
                    offAddr,
                    idType,
                    idNum,
                    city,
                    sType,
                    checkIn,
                    checkOut,
                    rent,
                    deposit,
                    food,
                    emergName,
                    emergPhone
                ];

                if (
                    String(oldRoomNo) ===
                    String(room_no)
                ) {

                    const updateSql = savedDocFilename
                        ? `UPDATE students
                            SET name = ?, department = ?, phone = ?, resident_type = ?, company_or_college = ?,
                                designation_or_course = ?, office_address = ?, id_proof_type = ?, id_proof_number = ?,
                                native_city = ?, stay_type = ?, check_in_date = ?, expected_checkout_date = ?,
                                monthly_rent = ?, security_deposit = ?, food_plan = ?, emergency_name = ?, emergency_phone = ?,
                                id_proof_file = ?, id_proof_filename = ?
                            WHERE student_id = ?`
                        : `UPDATE students
                            SET name = ?, department = ?, phone = ?, resident_type = ?, company_or_college = ?,
                                designation_or_course = ?, office_address = ?, id_proof_type = ?, id_proof_number = ?,
                                native_city = ?, stay_type = ?, check_in_date = ?, expected_checkout_date = ?,
                                monthly_rent = ?, security_deposit = ?, food_plan = ?, emergency_name = ?, emergency_phone = ?
                            WHERE student_id = ?`;

                    const finalParams = savedDocFilename
                        ? [...baseUpdateParams, savedDocFilename, id_proof_filename || null, studentId]
                        : [...baseUpdateParams, studentId];

                    db.query(
                        updateSql,
                        finalParams,
                        (err, result) => {

                            if (err) {
                                console.log(err);
                                return res.status(500).json({ error: "Error updating resident" });
                            }

                            res.json({
                                message: "Resident updated successfully"
                            });

                        }
                    );

                    return;

                }

                const checkRoomSql = `
                    SELECT
                        total_beds,
                        occupied_beds
                    FROM rooms
                    WHERE room_no = ?
                `;

                db.query(
                    checkRoomSql,
                    [room_no],
                    (err, roomResult) => {

                        if (err) {
                            console.log(err);
                            return res.status(500).json({ error: "Database error" });
                        }

                        if (roomResult.length === 0) {
                            return res.status(400).json({ error: "New room not found" });
                        }

                        const room = roomResult[0];

                        if (
                            room.occupied_beds >=
                            room.total_beds
                        ) {
                            return res.status(400).json({ error: "New room is full" });
                        }

                        const updateStudentSql = savedDocFilename
                            ? `UPDATE students
                                SET name = ?, department = ?, phone = ?, resident_type = ?, company_or_college = ?,
                                    designation_or_course = ?, office_address = ?, id_proof_type = ?, id_proof_number = ?,
                                    native_city = ?, stay_type = ?, check_in_date = ?, expected_checkout_date = ?,
                                    monthly_rent = ?, security_deposit = ?, food_plan = ?, emergency_name = ?, emergency_phone = ?,
                                    id_proof_file = ?, id_proof_filename = ?, room_no = ?
                                WHERE student_id = ?`
                            : `UPDATE students
                                SET name = ?, department = ?, phone = ?, resident_type = ?, company_or_college = ?,
                                    designation_or_course = ?, office_address = ?, id_proof_type = ?, id_proof_number = ?,
                                    native_city = ?, stay_type = ?, check_in_date = ?, expected_checkout_date = ?,
                                    monthly_rent = ?, security_deposit = ?, food_plan = ?, emergency_name = ?, emergency_phone = ?,
                                    room_no = ?
                                WHERE student_id = ?`;

                        const finalParams = savedDocFilename
                            ? [...baseUpdateParams, savedDocFilename, id_proof_filename || null, room_no, studentId]
                            : [...baseUpdateParams, room_no, studentId];

                        db.query(
                            updateStudentSql,
                            finalParams,
                            (err, result) => {

                                if (err) {
                                    console.log(err);
                                    return res.status(500).json({ error: "Error updating resident" });
                                }

                                const releaseOldRoomSql = `
                                    UPDATE rooms
                                    SET occupied_beds =
                                        occupied_beds - 1
                                    WHERE room_no = ?
                                      AND occupied_beds > 0
                                `;

                                db.query(
                                    releaseOldRoomSql,
                                    [oldRoomNo],
                                    () => {

                                        const occupyNewRoomSql = `
                                            UPDATE rooms
                                            SET occupied_beds =
                                                occupied_beds + 1
                                            WHERE room_no = ?
                                        `;

                                        db.query(
                                            occupyNewRoomSql,
                                            [room_no],
                                            () => {

                                                res.json({
                                                    message: "Resident updated and room changed successfully"
                                                });

                                            }
                                        );

                                    }
                                );

                            }
                        );

                    }
                );

            }
        );

    }
);


// ==================== RESIDENTS / STUDENTS PAGE ====================

app.get(
    "/students",
    requireAdmin,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/students.html"
        );

    }
);

app.get(
    "/residents",
    requireAdmin,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/students.html"
        );

    }
);


// ==================== VACATING & TRANSFER NOTICES ====================

app.get(
    "/vacating-notices",
    requireAdmin,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/vacating-notices.html"
        );

    }
);

app.get(
    "/api/vacating-notices",
    (req, res) => {

        const sql = `
            SELECT * FROM vacating_notices
            ORDER BY notice_id DESC
        `;

        db.query(sql, (err, results) => {

            if (err) {
                console.error(err);
                return res.status(500).json({ error: "Database error" });
            }

            res.json(results || []);

        });

    }
);

app.post(
    "/api/vacating-notices",
    (req, res) => {

        const {
            resident_id,
            resident_name,
            room_no,
            resident_type,
            reason,
            notice_date,
            expected_vacate_date,
            notes,
            deposit_refund_amount
        } = req.body;

        const rName = resident_name || (req.session && req.session.name) || "Resident";
        const rType = resident_type || "Jobholder";
        const rReason = reason || "Job Transfer / Relocation";
        const nDate = notice_date || new Date().toISOString().split("T")[0];
        const vDate = expected_vacate_date || null;
        const nNotes = notes || "";
        const refund = Number(deposit_refund_amount) || 0;

        const sql = `
            INSERT INTO vacating_notices
            (resident_id, resident_name, room_no, resident_type, reason, notice_date, expected_vacate_date, notes, status, deposit_refund_amount)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending Review', ?)
        `;

        db.query(
            sql,
            [resident_id || null, rName, room_no || "", rType, rReason, nDate, vDate, nNotes, refund],
            (err, result) => {

                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: "Failed to submit vacating notice" });
                }

                res.json({
                    success: true,
                    message: "Notice submitted successfully. Admin will review clearance and deposit refund.",
                    notice_id: result.insertId
                });

            }
        );

    }
);

app.put(
    "/api/vacating-notices/:id",
    requireAdmin,
    (req, res) => {

        const noticeId = req.params.id;
        const { status, deposit_refund_amount, notes } = req.body;

        const sql = `
            UPDATE vacating_notices
            SET status = ?,
                deposit_refund_amount = ?,
                notes = ?
            WHERE notice_id = ?
        `;

        db.query(
            sql,
            [status || 'Approved', Number(deposit_refund_amount) || 0, notes || '', noticeId],
            (err, result) => {

                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: "Failed to update notice" });
                }

                res.json({
                    success: true,
                    message: "Notice updated successfully"
                });

            }
        );

    }
);


// ==================== OCCUPANT REPORT API ====================

app.get(
    "/api/reports/occupants",
    requireAdmin,
    (req, res) => {

        const sql = `
            SELECT 
                COALESCE(resident_type, 'Jobholder') AS resident_type,
                COUNT(*) AS count,
                COALESCE(SUM(monthly_rent), 0) AS total_rent
            FROM students
            GROUP BY COALESCE(resident_type, 'Jobholder')
        `;

        db.query(sql, (err, results) => {

            if (err) {
                console.error(err);
                return res.status(500).json({ error: "Database error" });
            }

            res.json(results || []);

        });

    }
);


// ==================== FOOD & MESS MENU SYSTEM ====================

// Admin Food Menu Management Page
app.get("/food-menu", requireAdmin, (req, res) => {
    res.sendFile(__dirname + "/views/food-menu.html");
});

// Resident Food Menu Page (Read-only)
app.get("/student-food-menu", requireLogin, (req, res) => {
    res.sendFile(__dirname + "/views/student-food-menu.html");
});

// API: Get Today's Food Menu (accessible by both residents & admin)
app.get("/api/food-menu/today", (req, res) => {
    const today = new Date().toISOString().split("T")[0];
    const sql = "SELECT * FROM food_menu WHERE menu_date = ? LIMIT 1";
    db.query(sql, [today], (err, results) => {
        if (!err && results && results.length > 0) {
            return res.json({ success: true, menu: results[0] });
        }
        // Fallback to current day of week if exact date isn't found
        const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
        const currentDayName = days[new Date().getDay()];
        const fallbackSql = "SELECT * FROM food_menu WHERE day_name = ? ORDER BY menu_date DESC LIMIT 1";
        db.query(fallbackSql, [currentDayName], (fbErr, fbResults) => {
            if (!fbErr && fbResults && fbResults.length > 0) {
                return res.json({ success: true, menu: fbResults[0] });
            }
            db.query("SELECT * FROM food_menu ORDER BY menu_date DESC LIMIT 1", (lastErr, lastRes) => {
                if (!lastErr && lastRes && lastRes.length > 0) {
                    return res.json({ success: true, menu: lastRes[0] });
                }
                return res.json({ success: false, message: "No food menu available for today." });
            });
        });
    });
});

// API: Get Food Menu for a Specific Date
app.get("/api/food-menu/date/:date", (req, res) => {
    const date = req.params.date;
    const sql = "SELECT * FROM food_menu WHERE menu_date = ? LIMIT 1";
    db.query(sql, [date], (err, results) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        if (!results || results.length === 0) {
            return res.json({ success: false, message: "No menu found for this date." });
        }
        return res.json({ success: true, menu: results[0] });
    });
});

// API: Get Weekly Food Menus (Ordered chronologically)
app.get("/api/food-menu/week", (req, res) => {
    const sql = `
        SELECT * FROM food_menu 
        ORDER BY menu_date ASC 
        LIMIT 14
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        return res.json({ success: true, menus: results || [] });
    });
});

// API: Admin Update Day-to-Day Food Menu (Strictly Admin only)
app.post("/api/food-menu/update", requireAdmin, (req, res) => {
    const {
        menu_date,
        day_name,
        breakfast_items,
        breakfast_special,
        breakfast_time,
        lunch_items,
        lunch_special,
        lunch_time,
        dinner_items,
        dinner_special,
        dinner_time,
        special_announcement,
        is_feast_day
    } = req.body;

    if (!menu_date) {
        return res.status(400).json({ success: false, error: "Menu date is required." });
    }

    const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
    let resolvedDay = day_name;
    if (!resolvedDay) {
        const parts = menu_date.split("-");
        if (parts.length === 3) {
            const dt = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2]));
            resolvedDay = days[dt.getDay()];
        } else {
            resolvedDay = "Day";
        }
    }

    const upsertSql = `
        INSERT INTO food_menu 
        (menu_date, day_name, breakfast_items, breakfast_special, breakfast_time,
         lunch_items, lunch_special, lunch_time,
         dinner_items, dinner_special, dinner_time,
         special_announcement, is_feast_day)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            day_name = VALUES(day_name),
            breakfast_items = VALUES(breakfast_items),
            breakfast_special = VALUES(breakfast_special),
            breakfast_time = VALUES(breakfast_time),
            lunch_items = VALUES(lunch_items),
            lunch_special = VALUES(lunch_special),
            lunch_time = VALUES(lunch_time),
            dinner_items = VALUES(dinner_items),
            dinner_special = VALUES(dinner_special),
            dinner_time = VALUES(dinner_time),
            special_announcement = VALUES(special_announcement),
            is_feast_day = VALUES(is_feast_day),
            updated_at = CURRENT_TIMESTAMP
    `;

    db.query(upsertSql, [
        menu_date,
        resolvedDay,
        breakfast_items || "",
        breakfast_special || "",
        breakfast_time || "7:30 AM - 10:00 AM",
        lunch_items || "",
        lunch_special || "",
        lunch_time || "12:30 PM - 3:00 PM",
        dinner_items || "",
        dinner_special || "",
        dinner_time || "7:30 PM - 10:00 PM",
        special_announcement || "",
        is_feast_day ? 1 : 0
    ], (err, result) => {
        if (err) {
            console.error("Food menu update error:", err);
            return res.status(500).json({ success: false, error: "Database error updating food menu." });
        }
        return res.json({
            success: true,
            message: `✓ Mess menu for ${resolvedDay} (${menu_date}) updated successfully!`
        });
    });
});


// ==================== ROOMS ====================


// ==================== ADD ROOM ====================

app.post(
    "/api/rooms",
    requireAdmin,
    (req, res) => {

        const {
            room_no,
            room_type,
            total_beds,
            occupied_beds,
            monthly_rent,
            ac_type
        } = req.body;

        const rent = Number(monthly_rent) || 6500;
        const ac = ac_type || "Non-AC";
        const type = room_type || `${total_beds || 2} Sharing`;
        const total = Number(total_beds) || 2;
        const occ = Number(occupied_beds) || 0;

        const sql = `
            INSERT INTO rooms
            (room_no, room_type, total_beds, occupied_beds, monthly_rent, ac_type)
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        db.query(
            sql,
            [
                room_no,
                type,
                total,
                occ,
                rent,
                ac
            ],
            (err, result) => {

                if (err) {
                    console.log(err);
                    if (req.is("json") || (req.headers.accept && req.headers.accept.includes("json"))) {
                        return res.status(500).json({ error: "Error adding room: " + err.message });
                    }
                    return res.status(500).send("Error adding room");
                }

                if (req.is("json") || (req.headers.accept && req.headers.accept.includes("json"))) {
                    return res.json({ success: true, message: "Room added successfully", room_no });
                }

                res.redirect("/rooms");

            }
        );

    }
);


// ==================== GET ROOMS ====================

app.get(
    "/api/rooms",
    requireAdmin,
    (req, res) => {

        db.query(
            "SELECT * FROM rooms",
            (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error: "Database error"
                    });

                }


                res.json(results);

            }
        );

    }
);


// ==================== UPDATE ROOM ====================

app.put(
    "/api/rooms/:room_no",
    requireAdmin,
    (req, res) => {

        const roomNo =
            req.params.room_no;

        const {
            room_type,
            total_beds,
            occupied_beds
        } = req.body;


        if (
            Number(total_beds) < 0 ||
            Number(occupied_beds) < 0 ||
            Number(occupied_beds) >
                Number(total_beds)
        ) {

            return res.status(400).json({
                error:
                    "Invalid bed values"
            });

        }


        const rent = req.body.monthly_rent !== undefined ? Number(req.body.monthly_rent) : null;
        const ac = req.body.ac_type !== undefined ? req.body.ac_type : null;

        const sql = `
            UPDATE rooms
            SET room_type = ?,
                total_beds = ?,
                occupied_beds = ?,
                monthly_rent = COALESCE(?, monthly_rent),
                ac_type = COALESCE(?, ac_type)
            WHERE room_no = ?
        `;

        db.query(
            sql,
            [
                room_type,
                total_beds,
                occupied_beds,
                rent,
                ac,
                roomNo
            ],
            (err, result) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error:
                            "Error updating room"
                    });

                }


                if (
                    result.affectedRows === 0
                ) {

                    return res.status(404).json({
                        error:
                            "Room not found"
                    });

                }


                res.json({
                    message:
                        "Room updated successfully"
                });

            }
        );

    }
);


// ==================== DELETE ROOM ====================

app.delete(
    "/api/rooms/:room_no",
    requireAdmin,
    (req, res) => {

        const roomNo =
            req.params.room_no;


        const checkStudentsSql = `
            SELECT COUNT(*) AS studentCount
            FROM students
            WHERE room_no = ?
        `;


        db.query(
            checkStudentsSql,
            [roomNo],
            (err, result) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error:
                            "Database error"
                    });

                }


                const studentCount =
                    result[0].studentCount;


                if (studentCount > 0) {

                    return res.status(400).json({
                        error:
                            "Cannot delete room because students are assigned to it"
                    });

                }


                const deleteSql = `
                    DELETE FROM rooms
                    WHERE room_no = ?
                `;


                db.query(
                    deleteSql,
                    [roomNo],
                    (err, result) => {

                        if (err) {

                            console.log(err);

                            return res.status(500).json({
                                error:
                                    "Error deleting room"
                            });

                        }


                        if (
                            result.affectedRows === 0
                        ) {

                            return res.status(404).json({
                                error:
                                    "Room not found"
                            });

                        }


                        res.json({
                            message:
                                "Room deleted successfully"
                        });

                    }
                );

            }
        );

    }
);


// ==================== ROOMS PAGE ====================

app.get(
    "/rooms",
    requireAdmin,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/rooms.html"
        );

    }
);


// ==================== ADMIN COMPLAINTS ====================


// ==================== ADD ADMIN COMPLAINT ====================

app.post(
    "/api/complaints",
    requireAdmin,
    (req, res) => {

        const {
            student_name,
            complaint_text
        } = req.body;


        const sql = `
            INSERT INTO complaints
            (student_name, complaint_text)
            VALUES (?, ?)
        `;


        db.query(
            sql,
            [
                student_name,
                complaint_text
            ],
            (err, result) => {

                if (err) {

                    console.log(err);

                    return res.status(500).send(
                        "Error adding complaint"
                    );

                }


                res.redirect("/complaints");

            }
        );

    }
);


// ==================== GET ADMIN COMPLAINTS ====================

app.get(
    "/api/complaints",
    requireAdmin,
    (req, res) => {

        db.query(
            "SELECT * FROM complaints",
            (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error: "Database error"
                    });

                }


                res.json(results);

            }
        );

    }
);


// ==================== UPDATE COMPLAINT ====================

app.put(
    "/api/complaints/:id",
    requireAdmin,
    (req, res) => {

        const complaintId =
            req.params.id;


        const sql = `
            UPDATE complaints
            SET status = 'Resolved'
            WHERE complaint_id = ?
        `;


        db.query(
            sql,
            [complaintId],
            (err, result) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error:
                            "Error updating complaint"
                    });

                }


                res.json({
                    message:
                        "Complaint resolved successfully"
                });

            }
        );

    }
);


// ==================== ADMIN COMPLAINTS PAGE ====================

app.get(
    "/complaints",
    requireAdmin,
    (req, res) => {

        res.sendFile(
            __dirname + "/views/complaints.html"
        );

    }
);


// ==================== STUDENT COMPLAINTS ====================


// ==================== STUDENT COMPLAINTS PAGE ====================

app.get(
    "/student-complaints",
    requireStudent,
    (req, res) => {

        res.sendFile(
            __dirname +
            "/views/student-complaints.html"
        );

    }
);


// ==================== ADD STUDENT COMPLAINT ====================

app.post(
    "/api/student-complaints",
    requireStudent,
    (req, res) => {

        const complaintText =
            req.body.complaint_text;


        if (!complaintText) {

            return res.status(400).json({
                error:
                    "Complaint cannot be empty"
            });

        }


        const studentName =
            req.session.name;


        const sql = `
            INSERT INTO complaints
            (student_name, complaint_text, status)
            VALUES (?, ?, 'Pending')
        `;


        db.query(
            sql,
            [
                studentName,
                complaintText
            ],
            (err, result) => {

                if (err) {

                    console.error(err);

                    return res.status(500).json({
                        error:
                            "Database error"
                    });

                }


                res.json({
                    message:
                        "Complaint submitted successfully",

                    complaint_id:
                        result.insertId
                });

            }
        );

    }
);


// ==================== GET STUDENT COMPLAINTS ====================

app.get(
    "/api/student-complaints",
    requireStudent,
    (req, res) => {

        const studentName =
            req.session.name;


        const sql = `
            SELECT
                complaint_id,
                complaint_text,
                status
            FROM complaints
            WHERE student_name = ?
            ORDER BY complaint_id DESC
        `;


        db.query(
            sql,
            [studentName],
            (err, results) => {

                if (err) {

                    console.error(err);

                    return res.status(500).json({
                        error:
                            "Database error"
                    });

                }


                res.json(results);

            }
        );

    }
);


// ==================== PROFILE ====================


// ==================== PROFILE PAGE ====================

app.get(
    "/profile",
    requireLogin,
    (req, res) => {
        if (req.session.role === "student") {
            return res.redirect("/student-profile");
        }
        res.sendFile(
            __dirname + "/views/profile.html"
        );
    }
);


// ==================== PROFILE API ====================

app.get(
    "/api/profile",
    requireLogin,
    (req, res) => {

        db.query(
            "SELECT user_id, name, email, phone, role, profile_photo FROM users WHERE user_id = ?",
            [req.session.userId],
            (err, results) => {
                if (!err && results && results.length > 0) {
                    return res.json(results[0]);
                }
                res.json({
                    name: req.session.name,
                    email: req.session.email,
                    role: req.session.role,
                    profile_photo: null
                });
            }
        );

    }
);


// ==================== UPLOAD PROFILE PHOTO API ====================

app.post("/api/profile/upload-photo", requireLogin, (req, res) => {
    try {
        const userId = req.session.userId;
        const { image } = req.body;

        if (!image || typeof image !== "string") {
            return res.status(400).json({ success: false, error: "Please select a valid image file." });
        }

        const matches = image.match(/^data:image\/([a-zA-Z0-9+]+);base64,(.+)$/);
        let ext = "png";
        let base64Data = image;

        if (matches && matches.length === 3) {
            ext = matches[1] === "jpeg" ? "jpg" : matches[1];
            base64Data = matches[2];
        }

        const buffer = Buffer.from(base64Data, "base64");
        if (buffer.length > 6 * 1024 * 1024) {
            return res.status(400).json({ success: false, error: "Image file size exceeds the 6MB limit." });
        }

        const uploadsDir = path.join(__dirname, "public", "uploads");
        if (!fs.existsSync(uploadsDir)) {
            fs.mkdirSync(uploadsDir, { recursive: true });
        }

        const filename = `avatar_user_${userId}_${Date.now()}.${ext}`;
        const filePath = path.join(uploadsDir, filename);
        fs.writeFileSync(filePath, buffer);

        const photoUrl = `/uploads/${filename}`;

        db.query("UPDATE users SET profile_photo = ? WHERE user_id = ?", [photoUrl, userId], (uErr) => {
            if (uErr) console.warn("Notice: user photo update warning:", uErr.message);
            req.session.profile_photo = photoUrl;

            db.query(
                "UPDATE students SET profile_photo = ? WHERE user_id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?))",
                [photoUrl, userId, req.session.name || ""],
                (sErr) => {
                    if (sErr) console.warn("Notice: student photo update warning:", sErr.message);

                    res.json({
                        success: true,
                        message: "Profile photo uploaded successfully!",
                        photoUrl: photoUrl
                    });
                }
            );
        });
    } catch (e) {
        console.error("Photo upload exception:", e);
        res.status(500).json({ success: false, error: "Error uploading profile photo: " + e.message });
    }
});


// ==================== DELETE PROFILE PHOTO API ====================

app.post("/api/profile/delete-photo", requireLogin, (req, res) => {
    const userId = req.session.userId;
    req.session.profile_photo = null;
    db.query("UPDATE users SET profile_photo = NULL WHERE user_id = ?", [userId], () => {
        db.query(
            "UPDATE students SET profile_photo = NULL WHERE user_id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?))",
            [userId, req.session.name || ""],
            () => {
                res.json({ success: true, message: "Profile photo removed." });
            }
        );
    });
});


// ==================== CHANGE PASSWORD ====================

app.put(
    "/api/profile/password",
    requireLogin,
    async (req, res) => {

        const {
            newPassword
        } = req.body;


        if (!newPassword) {

            return res.status(400).json({
                success: false,
                message:
                    "Password is required"
            });

        }


        if (newPassword.length < 6) {

            return res.status(400).json({
                success: false,
                message:
                    "Password must be at least 6 characters"
            });

        }


        try {

            const hashedPassword =
                await bcrypt.hash(
                    newPassword,
                    10
                );


            const sql = `
                UPDATE users
                SET password = ?
                WHERE user_id = ?
            `;


            db.query(
                sql,
                [
                    hashedPassword,
                    req.session.userId
                ],
                (err, result) => {

                    if (err) {

                        console.log(err);

                        return res.status(500).json({
                            success: false,
                            message:
                                "Error updating password"
                        });

                    }


                    if (
                        result.affectedRows === 0
                    ) {

                        return res.status(404).json({
                            success: false,
                            message:
                                "User not found"
                        });

                    }


                    res.json({
                        success: true,
                        message:
                            "Password changed successfully"
                    });

                }
            );

        } catch (error) {

            console.log(error);

            res.status(500).json({
                success: false,
                message:
                    "Error changing password"
            });

        }

    }
);


// ==================== REGISTRATION ====================


// ==================== REGISTER PAGE ====================

app.get(
    "/register",
    (req, res) => {

        res.sendFile(
            __dirname + "/views/register.html"
        );

    }
);


// ==================== PUBLIC ROOMS API (FOR REGISTRATION SELECTION) ====================
app.get("/api/public/rooms", (req, res) => {
    const sql = `
        SELECT 
            room_no,
            room_type,
            total_beds,
            occupied_beds,
            (total_beds - occupied_beds) AS available_beds,
            monthly_rent,
            COALESCE(ac_type, 'Non-AC') AS ac_type
        FROM rooms
        ORDER BY room_no ASC
    `;
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Public rooms query error:", err);
            return res.status(500).json({ error: "Could not load rooms" });
        }
        res.json(results || []);
    });
});


// Helper to validate email address format (supports Gmail and college/institutional Google Workspace domains)
function isValidGmail(email) {
    if (!email || typeof email !== 'string') return false;
    const clean = email.trim().toLowerCase();
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return emailRegex.test(clean);
}

// Quick check if email is already registered before requesting OTP
app.get("/api/check-email-availability", (req, res) => {
    const rawEmail = req.query.email || "";
    const cleanEmail = rawEmail.trim().toLowerCase();

    if (!cleanEmail) {
        return res.json({ available: true });
    }

    const checkSql = `SELECT user_id FROM users WHERE LOWER(TRIM(email)) = ? LIMIT 1`;
    db.query(checkSql, [cleanEmail], (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        const exists = results && results.length > 0;
        return res.json({
            available: !exists,
            message: exists ? "This Gmail address is already registered in HostelHub. Please login instead." : "Available"
        });
    });
});

// 1. Send OTP to Gmail to verify existence and deliverability
app.post("/api/register/send-otp", async (req, res) => {
    try {
        const { email, name } = req.body;
        const cleanEmail = (email || "").trim().toLowerCase();

        if (!cleanEmail) {
            return res.status(400).json({ success: false, error: "Please enter your Gmail address." });
        }

        if (!isValidGmail(cleanEmail)) {
            return res.status(400).json({
                success: false,
                error: "Please enter a valid Google email address."
            });
        }

        // Check if email already registered
        const checkSql = `SELECT user_id FROM users WHERE LOWER(TRIM(email)) = ?`;
        db.query(checkSql, [cleanEmail], async (checkErr, results) => {
            if (checkErr) {
                console.error("Gmail check db error:", checkErr);
                return res.status(500).json({ success: false, error: "Database error during Gmail verification." });
            }

            if (results && results.length > 0) {
                return res.status(400).json({
                    success: false,
                    error: "This Gmail address is already registered in our system. Please sign in instead."
                });
            }

            // Generate 6-digit OTP
            const otp = Math.floor(100000 + Math.random() * 900000).toString();

            console.log("\n=======================================================");
            console.log(`🔐 HOSTELHUB REGISTRATION OTP FOR [${cleanEmail}]: ${otp}`);
            console.log("=======================================================\n");

            // Send registration OTP via Gmail transporter
            const sendResult = await sendRegistrationOTP(cleanEmail, otp, name);

            if (!sendResult.success) {
                console.warn(`[OTP WARNING] Google SMTP could not deliver to ${cleanEmail}: ${sendResult.error}`);
                return res.status(400).json({
                    success: false,
                    error: `Could not deliver to ${cleanEmail}. Google reported: ${sendResult.error || "Inbox not found"}`
                });
            }

            // Save verification state in session
            req.session.regVerification = {
                email: cleanEmail,
                otp: otp,
                verified: false,
                expires: Date.now() + 10 * 60 * 1000
            };

            return res.json({
                success: true,
                message: `6-digit verification code sent to ${cleanEmail}. Please check your Gmail inbox.`
            });
        });
    } catch (err) {
        console.error("Send reg OTP exception:", err);
        res.status(500).json({ success: false, error: "Internal server error verifying Gmail." });
    }
});

// 2. Verify the 6-digit Gmail OTP
app.post("/api/register/verify-otp", (req, res) => {
    try {
        const { email, otp } = req.body;
        const cleanEmail = (email || "").trim().toLowerCase();
        const cleanOtp = (otp || "").trim();

        const pending = req.session.regVerification;

        if (!pending || pending.email !== cleanEmail) {
            return res.status(400).json({
                success: false,
                error: "No active verification code found for this Gmail. Please click 'Verify Gmail' first."
            });
        }

        if (Date.now() > pending.expires) {
            delete req.session.regVerification;
            return res.status(400).json({
                success: false,
                error: "Verification code has expired. Please request a new code."
            });
        }

        if (pending.otp !== cleanOtp) {
            return res.status(400).json({
                success: false,
                error: "Incorrect 6-digit verification code. Please check your Gmail inbox."
            });
        }

        // Mark as verified in session
        req.session.regVerification.verified = true;

        return res.json({
            success: true,
            message: "✓ Gmail verified successfully! This email exists and is linked."
        });
    } catch (e) {
        console.error("Verify reg OTP error:", e);
        res.status(500).json({ success: false, error: "Server error verifying code." });
    }
});


// ==================== REGISTER STUDENT / RESIDENT ====================

app.post(
    "/register",
    async (req, res) => {

        const {
            name,
            email,
            phone,
            password,
            room_no,
            resident_type,
            company_or_college,
            designation_or_course,
            other_work,
            stay_type,
            stay_days,
            stay_months,
            check_in_date,
            entry_date,
            native_city,
            food_plan,
            id_proof_type,
            id_proof_number,
            id_proof_file,
            id_proof_filename,
            otp
        } = req.body;

        const isJson = req.xhr || (req.headers.accept && req.headers.accept.includes("application/json")) || (req.headers["content-type"] && req.headers["content-type"].includes("application/json"));

        if (!name || !email || !password) {
            const errMsg = "Please provide your name, Gmail address, and password.";
            if (isJson) return res.status(400).json({ success: false, error: errMsg });
            return res.status(400).send(errMsg);
        }

        // Mandatory Government ID Proof Check (Aadhaar Card or PAN Card)
        const idCheck = validateGovernmentId(id_proof_type, id_proof_number);
        if (!idCheck.valid) {
            if (isJson) return res.status(400).json({ success: false, error: idCheck.error });
            return res.status(400).send(idCheck.error);
        }

        // Mandatory ID Proof Document Upload Check
        if (!id_proof_file || typeof id_proof_file !== "string" || !id_proof_file.trim()) {
            const noDocMsg = `Please upload a valid scan/photo of your Government ID proof document (${idCheck.cleanType}) to complete registration.`;
            if (isJson) return res.status(400).json({ success: false, error: noDocMsg });
            return res.status(400).send(noDocMsg);
        }

        // Anti-Fraud / Anti-Impersonation Check: Ensure ID Proof Number is Not Already Registered
        try {
            const dup = await checkDuplicateIdProof(idCheck.cleanNum);
            if (dup) {
                const dupMsg = `This Government ID proof (${idCheck.cleanType} ending in ${idCheck.cleanNum.slice(-4)}) is already registered in the system under resident "${dup.name}". For security and identity protection, each resident must use their own unique ID. Impersonating another person's ID proof is strictly prohibited.`;
                if (isJson) return res.status(400).json({ success: false, error: dupMsg });
                return res.status(400).send(dupMsg);
            }
        } catch (dupErr) {
            console.error("Duplicate ID check error in registration:", dupErr);
        }

        // Save uploaded ID document to secure private directory
        let savedDocFilename = null;
        try {
            savedDocFilename = saveSecureIdDocument(id_proof_file, id_proof_filename || `${idCheck.cleanType}_doc`, `reg_user_${Date.now()}`);
        } catch (docErr) {
            if (isJson) return res.status(400).json({ success: false, error: docErr.message });
            return res.status(400).send(docErr.message);
        }

        const cleanEmail = email.trim().toLowerCase();

        // 1. Valid Email Check
        if (!isValidGmail(cleanEmail)) {
            const gmailErr = "Please enter a valid Google email address (such as your Gmail or college Google ID).";
            if (isJson) return res.status(400).json({ success: false, error: gmailErr });
            return res.status(400).send(gmailErr);
        }

        // 2. Check OTP verification if OTP was provided or required
        const pending = req.session.regVerification;
        if (otp && pending && pending.email === cleanEmail) {
            if (pending.otp === otp.trim()) {
                req.session.regVerification.verified = true;
            } else {
                const otpErr = "Invalid verification code entered for your Gmail.";
                if (isJson) return res.status(400).json({ success: false, error: otpErr });
                return res.status(400).send(otpErr);
            }
        }

        try {

            const checkSql = `
                SELECT *
                FROM users
                WHERE LOWER(TRIM(email)) = ?
            `;

            db.query(
                checkSql,
                [cleanEmail],
                async (err, results) => {

                    if (err) {
                        console.error("Register check error:", err);
                        const errDetail = err.sqlMessage || err.message || "Database connection error";
                        if (isJson) return res.status(500).json({ success: false, error: `Database error during registration: ${errDetail}` });
                        return res.status(500).send(`Database error: ${errDetail}`);
                    }

                    if (results.length > 0) {
                        const existsMsg = "This Gmail address is already registered. Please sign in instead.";
                        if (isJson) return res.status(400).json({ success: false, error: existsMsg });
                        return res.send(existsMsg);
                    }

                    const hashedPassword = await bcrypt.hash(password, 10);

                    // ==================== INSERT USER ====================

                    const insertUserSql = `
                        INSERT INTO users
                        (name, email, phone, password, role)
                        VALUES (?, ?, ?, ?, 'student')
                    `;

                    db.query(
                        insertUserSql,
                        [
                            name.trim(),
                            cleanEmail,
                            phone ? phone.trim() : "",
                            hashedPassword
                        ],
                        (err, result) => {

                            if (err) {
                                console.error("Register user insert error:", err);
                                if (isJson) return res.status(500).json({ success: false, error: "Registration failed" });
                                return res.status(500).send("Registration failed");
                            }

                            const userId = result.insertId;

                            // Normalize occupation / resident type
                            let finalType = resident_type || "Jobholder";
                            if (finalType === "Other" && other_work) {
                                finalType = other_work.trim();
                            }

                            const finalStayType = (stay_type === "Daily Stay (Days)" || stay_type === "Days Stay")
                                ? "Daily Stay (Days)"
                                : "Monthly Stay";

                            // Entry Date / Check-in Date
                            const finalCheckIn = entry_date || check_in_date || new Date().toISOString().split("T")[0];
                            const finalFoodPlan = food_plan || "With Food";
                            const finalCity = native_city ? native_city.trim() : "";
                            const finalCompany = company_or_college ? company_or_college.trim() : "";
                            const finalDesig = designation_or_course ? designation_or_course.trim() : "";

                            // Calculate realistic rent & initial fee based on stay type
                            let defaultRent = 6500;

                            const requestedRoom = (room_no && room_no !== "none" && room_no !== "unassigned") ? String(room_no).trim() : null;

                            const processStudentAdmission = (assignedRoomNo, roomMonthlyRent) => {
                                let rentRate = roomMonthlyRent || defaultRent;
                                let initialFeeAmount = rentRate;

                                if (finalStayType === "Daily Stay (Days)") {
                                    const days = Number(stay_days) || 1;
                                    rentRate = 500; // Daily rate
                                    initialFeeAmount = days * 500;
                                } else {
                                    initialFeeAmount = rentRate;
                                }

                                // ==================== INSERT STUDENT ====================
                                const insertStudentSql = `
                                    INSERT INTO students
                                    (name, room_no, phone, user_id, resident_type, company_or_college, designation_or_course, stay_type, check_in_date, native_city, food_plan, monthly_rent, id_proof_type, id_proof_number, id_proof_file, id_proof_filename)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                `;

                                db.query(
                                    insertStudentSql,
                                    [
                                        name.trim(),
                                        assignedRoomNo,
                                        phone ? phone.trim() : "",
                                        userId,
                                        finalType,
                                        finalCompany,
                                        finalDesig,
                                        finalStayType,
                                        finalCheckIn,
                                        finalCity,
                                        finalFoodPlan,
                                        rentRate,
                                        idCheck.cleanType,
                                        idCheck.cleanNum,
                                        savedDocFilename,
                                        id_proof_filename || null
                                    ],
                                    (studentErr, studentResult) => {

                                        if (studentErr) {
                                            console.error("Register student insert error:", studentErr);
                                            db.query("DELETE FROM users WHERE user_id = ?", [userId], () => {});
                                            if (isJson) return res.status(500).json({ success: false, error: "Could not save resident details." });
                                            return res.status(500).send("Student registration failed");
                                        }

                                        // If a room was assigned, increment occupied beds
                                        if (assignedRoomNo) {
                                            db.query(
                                                "UPDATE rooms SET occupied_beds = occupied_beds + 1 WHERE room_no = ? AND occupied_beds < total_beds",
                                                [assignedRoomNo],
                                                (updateRoomErr) => {
                                                    if (updateRoomErr) console.warn("Notice: Room bed occupancy update notice:", updateRoomErr.message);
                                                }
                                            );
                                        }

                                        // ==================== INSERT INITIAL FEES (JOINING ADVANCE) ====================
                                        const regNow = new Date();
                                        const regMonthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
                                        const regMonthStr = `${regMonthNames[regNow.getMonth()]} ${regNow.getFullYear()}`;
                                        const regBillingMonth = `${regNow.getFullYear()}-${String(regNow.getMonth() + 1).padStart(2, '0')}`;

                                        const insertFeeSql = `
                                            INSERT INTO fees
                                            (user_id, student_name, total_fee, paid_amount, pending_amount, status, fee_type, month_name, billing_month)
                                            VALUES (?, ?, ?, 0, ?, 'Pending', 'Advance / Joining Fee', ?, ?)
                                        `;

                                        db.query(
                                            insertFeeSql,
                                            [
                                                userId,
                                                name.trim(),
                                                initialFeeAmount,
                                                initialFeeAmount,
                                                `Advance Fee (${regMonthStr})`,
                                                regBillingMonth
                                            ],
                                            (feeErr) => {

                                                if (feeErr) {
                                                    console.warn("Notice: Fee creation warning on register:", feeErr.message);
                                                }

                                                // Send Welcome & Admission Confirmation Email to the verified Gmail
                                                sendWelcomeEmail(cleanEmail, name.trim(), {
                                                    room_no: assignedRoomNo,
                                                    check_in_date: finalCheckIn,
                                                    resident_type: finalType,
                                                    stay_type: finalStayType,
                                                    food_plan: finalFoodPlan
                                                }).catch(mErr => console.warn("Welcome email async notice:", mErr));

                                                // Clean verification session
                                                delete req.session.regVerification;

                                                if (isJson) {
                                                    return res.json({
                                                        success: true,
                                                        message: "Registration completed successfully! Welcome email sent to your Gmail.",
                                                        redirectUrl: "/login?registered=true"
                                                    });
                                                }

                                                res.redirect("/login?registered=true");

                                            }
                                        );

                                    }
                                );
                            };

                            if (requestedRoom) {
                                db.query("SELECT * FROM rooms WHERE room_no = ? LIMIT 1", [requestedRoom], (rErr, rRows) => {
                                    if (!rErr && rRows && rRows.length > 0) {
                                        const rm = rRows[0];
                                        if (rm.occupied_beds < rm.total_beds) {
                                            processStudentAdmission(rm.room_no, Number(rm.monthly_rent) || 6500);
                                        } else {
                                            // Room full fallback
                                            processStudentAdmission(null, 6500);
                                        }
                                    } else {
                                        processStudentAdmission(null, 6500);
                                    }
                                });
                            } else {
                                processStudentAdmission(null, 6500);
                            }

                        }
                    );

                }
            );

        } catch (error) {
            console.error("Register catch error:", error);
            if (isJson) return res.status(500).json({ success: false, error: "Server error during registration." });
            res.status(500).send("Registration error");
        }
    }
);


// ==================== LOGIN ====================


// ==================== LOGIN PAGE ====================

app.get(
    "/login",
    (req, res) => {

        // If user is already authenticated, redirect straight to their dashboard
        // so Back button will NEVER return to the login or OTP screen!
        if (req.session.userId) {
            const role = (req.session.role || "").toLowerCase().trim();
            const dest = role === "admin" ? "/dashboard" : "/student-dashboard";
            return res.redirect(dest);
        }

        res.set({
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        });

        res.sendFile(
            __dirname + "/views/login.html"
        );

    }
);


// ==================== LOGIN USER ====================

app.post(
    "/login",
    checkLoginRateLimit,
    async (req, res) => {
        const clientIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown_ip";

        const isJson = req.xhr || (req.headers.accept && req.headers.accept.includes("application/json")) || (req.headers["content-type"] && req.headers["content-type"].includes("application/json"));

        const {
            email,
            password,
            credential
        } = req.body;

        if (!email || !password) {
            if (isJson) {
                return res.status(400).json({ success: false, message: "Please enter both email and password." });
            }
            return res.send("Please enter both email and password.");
        }

        const cleanEmail = email.toLowerCase().trim();

        // 1. Check for valid Firebase ID Token (if client signed in with Firebase)
        let firebaseVerifiedEmail = null;
        let firebaseTokenUser = null;
        if (credential && typeof credential === "string" && credential.includes(".")) {
            try {
                const parts = credential.split(".");
                if (parts.length >= 2) {
                    const base64Url = parts[1];
                    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
                    const jsonPayload = Buffer.from(base64, "base64").toString("utf-8");
                    firebaseTokenUser = JSON.parse(jsonPayload);
                    if (firebaseTokenUser && firebaseTokenUser.email) {
                        firebaseVerifiedEmail = firebaseTokenUser.email.toLowerCase().trim();
                    }
                }
            } catch (jwtErr) {
                console.warn("Firebase token payload decode notice in /login:", jwtErr.message);
            }
        }

        try {

            const sql = `
                SELECT *
                FROM users
                WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))
            `;

            db.query(
                sql,
                [cleanEmail],
                async (err, results) => {

                    if (err) {
                        console.error("Database error during login:", err);
                        const errDetail = err.sqlMessage || err.message || "Database connection error";
                        if (isJson) {
                            return res.status(500).json({ success: false, message: `Database error occurred: ${errDetail}` });
                        }
                        return res.status(500).send(`Database error: ${errDetail}`);
                    }

                    // ==================== USER EXISTS IN DATABASE ====================
                    if (results.length > 0) {
                        const user = results[0];

                        let passwordMatch = false;
                        if (user.password) {
                            try {
                                passwordMatch = await bcrypt.compare(
                                    password,
                                    user.password
                                );
                            } catch (compareErr) {
                                console.error("Bcrypt compare error:", compareErr);
                            }
                        }

                        // If bcrypt failed, check if Firebase already authenticated this email & password
                        if (!passwordMatch && firebaseVerifiedEmail && firebaseVerifiedEmail === cleanEmail) {
                            passwordMatch = true;
                            // Re-hash and sync the verified password to MySQL
                            try {
                                const newHash = await bcrypt.hash(password, 10);
                                db.query("UPDATE users SET password = ? WHERE user_id = ?", [newHash, user.user_id], () => {});
                            } catch (hashErr) {
                                console.warn("Password sync warning:", hashErr.message);
                            }
                        }

                        if (!passwordMatch) {
                            recordFailedLogin(clientIp);
                            if (isJson) {
                                return res.status(401).json({ success: false, message: "Invalid email or password." });
                            }
                            return res.send("Invalid email or password");
                        }

                        // If student, link user_id if missing
                        if (user.role === "student") {
                            db.query(
                                "UPDATE students SET user_id = ? WHERE (user_id IS NULL OR user_id = 0) AND LOWER(TRIM(name)) = LOWER(TRIM(?))",
                                [user.user_id, user.name],
                                () => {}
                            );
                        }

                        // ==================== SESSION ====================
                        clearLoginFailures(clientIp);
                        req.session.userId = user.user_id;
                        req.session.name = user.name;
                        req.session.email = user.email;

                        const userRole = (user.role || "student").toLowerCase().trim();
                        req.session.role = userRole;

                        const redirectUrl = userRole === "admin" ? "/dashboard" : "/student-dashboard";

                        req.session.save((saveErr) => {
                            if (saveErr) console.warn("Session save warning:", saveErr.message);
                            if (isJson) {
                                return res.json({
                                    success: true,
                                    message: `Welcome back, ${user.name}!`,
                                    redirectUrl: redirectUrl,
                                    userName: user.name,
                                    role: user.role
                                });
                            }
                            return res.redirect(redirectUrl);
                        });
                    }

                    // ==================== USER DOES NOT EXIST IN DATABASE ====================
                    // If authenticated by Firebase, auto-provision user in MySQL database
                    if (firebaseVerifiedEmail && firebaseVerifiedEmail === cleanEmail) {
                        try {
                            const hashedPassword = await bcrypt.hash(password, 10);
                            const nameFromEmail = cleanEmail.split("@")[0].replace(/[._-]/g, " ");
                            const userName = (firebaseTokenUser && firebaseTokenUser.name) 
                                ? firebaseTokenUser.name 
                                : (nameFromEmail.charAt(0).toUpperCase() + nameFromEmail.slice(1));

                            const insertUserSql = `
                                INSERT INTO users (name, email, phone, password, role)
                                VALUES (?, ?, '', ?, 'student')
                            `;

                            db.query(insertUserSql, [userName, cleanEmail, hashedPassword], (insErr, insRes) => {
                                if (insErr) {
                                    console.error("Error auto-creating Firebase user:", insErr);
                                    if (isJson) return res.status(500).json({ success: false, message: "Failed to establish resident profile." });
                                    return res.status(500).send("Account initialization error");
                                }

                                const newUserId = insRes.insertId;

                                const insertStudentSql = `
                                    INSERT INTO students (name, room_no, phone, user_id, resident_type, stay_type, check_in_date, monthly_rent)
                                    VALUES (?, NULL, '', ?, 'Student', 'Monthly Stay', CURDATE(), 6500)
                                `;
                                db.query(insertStudentSql, [userName, newUserId], () => {});

                                req.session.userId = newUserId;
                                req.session.name = userName;
                                req.session.email = cleanEmail;
                                req.session.role = "student";

                                if (isJson) {
                                    return res.json({
                                        success: true,
                                        message: `Welcome, ${userName}!`,
                                        redirectUrl: "/student-dashboard",
                                        userName: userName,
                                        role: "student"
                                    });
                                }

                                return res.redirect("/student-dashboard");
                            });
                            return;
                        } catch (provErr) {
                            console.error("Error during auto-provisioning:", provErr);
                        }
                    }

                    recordFailedLogin(clientIp);
                    if (isJson) {
                        return res.status(401).json({ success: false, message: "Invalid email or password." });
                    }
                    return res.send("Invalid email or password");

                }
            );

        } catch (error) {
            console.error("Login catch error:", error);
            if (isJson) {
                return res.status(500).json({ success: false, message: "Server error occurred. Please try again." });
            }
            res.status(500).send("Something went wrong");
        }

    }
);


// ==================== GOOGLE AUTHENTICATION ====================

// Endpoint to provide Google Client ID and status to frontend
app.get("/api/auth/google/config", (req, res) => {
    const clientId = (process.env.GOOGLE_CLIENT_ID || "").trim();
    const isConfigured = Boolean(clientId && clientId.includes(".apps.googleusercontent.com"));
    res.json({
        clientId: clientId,
        configured: isConfigured
    });
});

// Endpoint to verify Google Token, dispatch OTP security code to resident's Gmail
app.post("/api/auth/google", async (req, res) => {
    const { credential, email: directEmail, password: directPassword, name: directName } = req.body;

    let email = null;
    let name = null;
    let googleId = null;

    if (credential) {
        // 1. Verify token with Google's official API
        try {
            const verifyRes = await fetch(
                `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`
            );
            if (verifyRes.ok) {
                const googleUser = await verifyRes.json();
                email = googleUser.email;
                name = googleUser.name;
                googleId = googleUser.sub;
            }
        } catch (fetchErr) {
            console.warn("Direct Google tokeninfo fetch failed, attempting JWT decode fallback:", fetchErr.message);
        }

        // 2. Fallback: Parse JWT payload directly
        if (!email) {
            try {
                const parts = credential.split(".");
                if (parts.length >= 2) {
                    const base64Url = parts[1];
                    const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
                    const jsonPayload = Buffer.from(base64, "base64").toString("utf-8");
                    const googleUser = JSON.parse(jsonPayload);
                    email = googleUser.email;
                    name = googleUser.name;
                    googleId = googleUser.sub;
                }
            } catch (jwtErr) {
                console.warn("JWT fallback decode error:", jwtErr.message);
            }
        }
    } else if (directEmail) {
        email = directEmail;
        name = directName;
    }

    // Direct fallback from request body (Firebase user payload)
    if (!email && req.body.email) {
        email = req.body.email;
        name = name || req.body.name;
        googleId = googleId || req.body.googleId;
    }

    if (!email || typeof email !== "string" || !email.includes("@")) {
        return res.status(400).json({
            success: false,
            message: "Valid Google account email address is required."
        });
    }

    email = email.toLowerCase().trim();
    if (!name || !name.trim()) {
        const usernamePart = email.split("@")[0].replace(/[._-]/g, " ");
        name = usernamePart.charAt(0).toUpperCase() + usernamePart.slice(1);
    } else {
        name = name.trim();
    }

    // Check if Google email matches an already registered user in our database
    const checkSql = "SELECT user_id, name, email, role FROM users WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))";
    db.query(checkSql, [email], async (err, results) => {
        if (err) {
            console.error("Database query error in Google login check:", err);
            return res.status(500).json({
                success: false,
                message: "Database verification failed. Please try again."
            });
        }

        if (!results || results.length === 0) {
            console.warn(`[SECURITY BLOCKED] Unregistered Google email attempted login: ${email}`);
            return res.status(403).json({
                success: false,
                isUnregistered: true,
                message: `This Google account (${email}) is not registered in our records. Your Google login email and registered email must match. Please complete registration first.`
            });
        }

        const registeredUser = results[0];
        const residentName = registeredUser.name || name;

        try {
            // Generate secure 6-digit OTP for Google login security verification
            const otp = Math.floor(100000 + Math.random() * 900000).toString();

            req.session.googleAuthPending = {
                email: email,
                name: residentName,
                googleId: googleId,
                credential: credential,
                otp: otp,
                expiry: Date.now() + 5 * 60 * 1000, // 5 minutes validity
                lastSent: Date.now()
            };

            console.log(`\n=========================================================`);
            console.log(`🔐 [GOOGLE LOGIN SECURITY OTP GENERATED]`);
            console.log(`📧 Recipient: ${email}`);
            console.log(`🔑 OTP Code:  ${otp}`);
            console.log(`⏳ Validity:  5 Minutes`);
            console.log(`=========================================================\n`);

            // Send security code via Gmail SMTP
            const emailSent = await sendGoogleLoginOTP(email, otp, residentName);
            if (!emailSent) {
                console.warn("Notice: Google login OTP email delivery notice for", email);
            }

            return res.json({
                success: true,
                requireOtp: true,
                email: email,
                name: residentName,
                message: `A 6-digit security code has been sent to ${email}. Please enter it to complete sign-in.`
            });

        } catch (otpErr) {
            console.error("Google Auth Error:", otpErr);
            return res.status(500).json({
                success: false,
                message: "Authentication process failed. Please try again."
            });
        }
    });
});

// Endpoint to verify Google Sign-In OTP and establish session
app.post("/api/auth/google/verify-otp", async (req, res) => {
    const { email, otp } = req.body;
    const cleanEmail = (email || "").toLowerCase().trim();
    const enteredOtp = (otp || "").toString().trim();

    const pending = req.session.googleAuthPending;

    if (!pending || pending.email !== cleanEmail) {
        return res.status(400).json({
            success: false,
            message: "No active Google sign-in request found. Please click 'Sign in with Google' again."
        });
    }

    if (Date.now() > pending.expiry) {
        return res.status(400).json({
            success: false,
            message: "Security code has expired. Please click 'Resend Code'."
        });
    }

    if (enteredOtp !== String(pending.otp).trim()) {
        return res.status(400).json({
            success: false,
            message: "Incorrect security code. Please check your Gmail and try again."
        });
    }

    try {
        // Re-verify that user exists in database
        const checkSql = "SELECT * FROM users WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))";
        db.query(checkSql, [cleanEmail], async (err, results) => {
            if (err) {
                console.error("Database query error in Google OTP Auth:", err);
                return res.status(500).json({
                    success: false,
                    message: "Database error during authentication."
                });
            }

            if (results && results.length > 0) {
                // User exists in database
                const user = results[0];

                // If user is a student, ensure linked to students table
                if (user.role === "student") {
                    const linkSql = `
                        UPDATE students 
                        SET user_id = ? 
                        WHERE (user_id IS NULL OR user_id = 0) 
                          AND LOWER(TRIM(name)) = LOWER(TRIM(?))
                    `;
                    db.query(linkSql, [user.user_id, user.name], () => {});
                }

                // Clean pending session
                delete req.session.googleAuthPending;

                req.session.userId = user.user_id;
                req.session.name = user.name;
                req.session.email = user.email;
                req.session.role = user.role;

                const redirectUrl = user.role === "student" ? "/student-dashboard" : "/dashboard";
                return res.json({
                    success: true,
                    redirectUrl,
                    userName: user.name,
                    userEmail: user.email,
                    role: user.role,
                    message: `Security verified! Welcome back, ${user.name}!`
                });

            } else {
                // Strictly block: Unregistered users cannot bypass registration via Google
                delete req.session.googleAuthPending;
                return res.status(403).json({
                    success: false,
                    isUnregistered: true,
                    message: `This Google account (${cleanEmail}) is not registered in our records. Your Google login email and registered email must match. Please complete registration first.`
                });
            }
        });

    } catch (authErr) {
        console.error("Error verifying Google OTP:", authErr);
        res.status(500).json({ success: false, message: "Verification failed. Please try again." });
    }
});

// Endpoint to resend Google Sign-In OTP
app.post("/api/auth/google/resend-otp", async (req, res) => {
    const pending = req.session.googleAuthPending;
    const { email } = req.body;

    if (!pending || (email && pending.email !== email.toLowerCase().trim())) {
        return res.status(400).json({
            success: false,
            message: "No active Google sign-in session found. Please sign in again."
        });
    }

    // Rate-limit to 25 seconds between resends
    if (pending.lastSent && (Date.now() - pending.lastSent < 25000)) {
        const waitSec = Math.ceil((25000 - (Date.now() - pending.lastSent)) / 1000);
        return res.status(429).json({
            success: false,
            message: `Please wait ${waitSec}s before requesting a new code.`
        });
    }

    const newOtp = Math.floor(100000 + Math.random() * 900000).toString();
    pending.otp = newOtp;
    pending.expiry = Date.now() + 5 * 60 * 1000;
    pending.lastSent = Date.now();

    await sendGoogleLoginOTP(pending.email, newOtp, pending.name);

    return res.json({
        success: true,
        message: "A new security code has been sent to your Gmail!"
    });
});

// Endpoint to cancel pending Google OTP session
app.post("/api/auth/google/cancel", (req, res) => {
    delete req.session.googleAuthPending;
    res.json({ success: true });
});


// ==================== FORGOT PASSWORD ====================

app.get(
    "/forgot-password",
    (req, res) => {

        // Completely invalidate any previous OTP verification or reset session
        delete req.session.otpVerified;
        delete req.session.resetOTP;
        delete req.session.resetOTPExpiry;
        delete req.session.resetEmail;
        delete req.session.lastOTPResend;

        res.set({
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        });

        res.sendFile(
            __dirname +
            "/views/forgot-password.html"
        );

    }
);


// Invalidate/Cancel password reset session endpoint
app.all(
    "/api/reset-password/cancel",
    (req, res) => {
        delete req.session.otpVerified;
        delete req.session.resetOTP;
        delete req.session.resetOTPExpiry;
        delete req.session.resetEmail;
        delete req.session.lastOTPResend;

        if (req.xhr || (req.headers.accept && req.headers.accept.includes("application/json"))) {
            return res.json({ success: true, message: "Reset session cleared." });
        }
        res.redirect("/forgot-password");
    }
);


app.post(
    "/forgot-password",
    (req, res) => {

        // Ensure completely clean state before generating new OTP
        delete req.session.otpVerified;
        delete req.session.resetOTP;
        delete req.session.resetOTPExpiry;

        const {
            email
        } = req.body;

        const cleanEmail = (email || "").toLowerCase().trim();

        const sql = `
            SELECT
                user_id,
                name,
                email
            FROM users
            WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))
        `;

        db.query(
            sql,
            [cleanEmail],
            async (err, results) => {

                if (err) {
                    console.log("Database error in /forgot-password:", err);
                    return res.status(500).send("Database error");
                }

                if (results.length === 0) {
                    console.warn(`[FORGOT PASSWORD] Email not registered in users table: ${cleanEmail}`);
                    return res.send("Email not registered in our records. Please check the email or sign up.");
                }


                // Generate 6 digit OTP

                const otp =
                    Math.floor(
                        100000 +
                        Math.random() *
                        900000
                    ).toString();


                console.log(
                    "Generated OTP:",
                    otp
                );


                // Store OTP in session

                req.session.resetEmail =
                    email;

                req.session.resetOTP =
                    otp;

                req.session.resetOTPExpiry =
                    Date.now() +
                    5 * 60 * 1000;


                // Send OTP to email

                const emailSent =
                    await sendOTP(
                        email,
                        otp
                    );


                if (!emailSent) {

                    return res.send(
                        "Failed to send OTP"
                    );

                }


                res.redirect(
                    "/verify-otp"
                );

            }
        );

    }
);


// ==================== VERIFY OTP ====================

app.get(
    "/verify-otp",
    (req, res) => {

        // Prevent browser/history cache so user cannot return via back button
        res.set({
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        });

        // SAFETY GUARD 1: If OTP is already verified, do not allow returning to verification
        if (req.session.otpVerified) {
            return res.redirect("/reset-password");
        }

        // SAFETY GUARD 2: Must have an active reset email and OTP in progress
        if (!req.session.resetEmail || !req.session.resetOTP) {
            return res.redirect("/forgot-password");
        }

        res.sendFile(
            __dirname +
            "/views/verify-otp.html"
        );

    }
);


app.post(
    "/verify-otp",
    (req, res) => {

        const isJson = req.xhr || (req.headers.accept && req.headers.accept.includes("application/json")) || (req.headers["content-type"] && req.headers["content-type"].includes("application/json"));

        if (req.session.otpVerified) {
            if (isJson) {
                return res.json({ success: true, redirectUrl: "/reset-password" });
            }
            return res.redirect("/reset-password");
        }

        const {
            otp
        } = req.body;


        if (!req.session.resetOTP) {

            if (isJson) {
                return res.status(400).json({ success: false, message: "No active verification code. Please request a new code." });
            }
            return res.redirect("/verify-otp?error=" + encodeURIComponent("OTP not found. Please request a new code."));

        }


        if (
            Date.now() >
            req.session.resetOTPExpiry
        ) {

            if (isJson) {
                return res.status(400).json({ success: false, message: "OTP has expired. Please click Resend Code below." });
            }
            return res.redirect("/verify-otp?error=" + encodeURIComponent("OTP expired. Please click Resend Code."));

        }


        if (
            !otp ||
            otp.toString().trim() !== req.session.resetOTP.toString().trim()
        ) {

            if (isJson) {
                return res.status(400).json({ success: false, message: "Invalid verification code. Please try again." });
            }
            return res.redirect("/verify-otp?error=" + encodeURIComponent("Invalid OTP. Please try again."));

        }


        req.session.otpVerified =
            true;


        delete req.session.resetOTP;

        delete req.session.resetOTPExpiry;


        if (isJson) {
            return res.json({
                success: true,
                message: "OTP verified successfully!",
                redirectUrl: "/reset-password"
            });
        }

        res.redirect(
            "/reset-password"
        );

    }
);


// ==================== RESEND OTP ====================

app.post(
    "/resend-otp",
    async (req, res) => {

        const isJson = req.xhr || (req.headers.accept && req.headers.accept.includes("application/json")) || (req.headers["content-type"] && req.headers["content-type"].includes("application/json"));

        if (req.session.otpVerified) {
            if (isJson) {
                return res.status(400).json({ success: false, message: "OTP has already been verified.", redirectUrl: "/reset-password" });
            }
            return res.redirect("/reset-password");
        }

        const email = req.session.resetEmail;
        if (!email) {
            if (isJson) {
                return res.status(400).json({ success: false, message: "Session expired. Please enter your email again.", redirectUrl: "/forgot-password" });
            }
            return res.redirect("/forgot-password");
        }

        // Anti-spam cooldown check (25 seconds)
        const now = Date.now();
        if (req.session.lastOTPResend && (now - req.session.lastOTPResend < 25000)) {
            const remaining = Math.ceil((25000 - (now - req.session.lastOTPResend)) / 1000);
            const msg = `Please wait ${remaining} seconds before requesting a new code.`;
            if (isJson) {
                return res.status(429).json({ success: false, message: msg, remainingSeconds: remaining });
            }
            return res.redirect("/verify-otp?error=" + encodeURIComponent(msg));
        }

        try {

            const otp =
                Math.floor(
                    100000 +
                    Math.random() *
                    900000
                ).toString();

            console.log("Resent OTP:", otp, "to:", email);

            req.session.resetOTP = otp;
            req.session.resetOTPExpiry = Date.now() + 5 * 60 * 1000;
            req.session.lastOTPResend = now;

            const emailSent = await sendOTP(email, otp);

            if (!emailSent) {
                if (isJson) {
                    return res.status(500).json({ success: false, message: "Failed to send OTP email. Please try again." });
                }
                return res.redirect("/verify-otp?error=" + encodeURIComponent("Failed to send OTP email."));
            }

            if (isJson) {
                return res.json({
                    success: true,
                    message: "A fresh 6-digit OTP code has been sent to your email!"
                });
            }

            res.redirect("/verify-otp?resent=true");

        } catch (err) {
            console.error("Resend OTP error:", err);
            if (isJson) {
                return res.status(500).json({ success: false, message: "An error occurred while resending the code." });
            }
            res.redirect("/verify-otp?error=" + encodeURIComponent("Server error occurred while resending OTP."));
        }

    }
);

app.get(
    "/resend-otp",
    (req, res) => {
        if (req.session.otpVerified) {
            return res.redirect("/reset-password");
        }
        res.redirect("/verify-otp");
    }
);


// ==================== RESET PASSWORD ====================

app.get(
    "/reset-password",
    (req, res) => {

        res.set({
            "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        });

        if (
            !req.session.otpVerified || !req.session.resetEmail
        ) {

            return res.redirect(
                "/forgot-password"
            );

        }


        res.sendFile(
            __dirname +
            "/views/reset-password.html"
        );

    }
);


app.post(
    "/reset-password",
    async (req, res) => {

        if (
            !req.session.otpVerified
        ) {

            return res.status(403).send(
                "OTP verification required. Please verify OTP first."
            );

        }


        const {
            newPassword,
            confirmPassword
        } = req.body;


        if (
            newPassword !==
            confirmPassword
        ) {

            return res.send(
                "Passwords do not match"
            );

        }


        if (
            newPassword.length < 6
        ) {

            return res.send(
                "Password must be at least 6 characters"
            );

        }


        try {

            const hashedPassword =
                await bcrypt.hash(
                    newPassword,
                    10
                );


            const sql = `
                UPDATE users
                SET password = ?
                WHERE email = ?
            `;


            db.query(
                sql,
                [
                    hashedPassword,
                    req.session.resetEmail
                ],
                (err, result) => {

                    if (err) {

                        console.log(err);

                        return res.status(500).send(
                            "Password reset failed"
                        );

                    }


                    if (
                        result.affectedRows === 0
                    ) {

                        return res.send(
                            "Email not registered"
                        );

                    }


                    const userEmail = req.session.resetEmail;
                    delete req.session.resetEmail;
                    delete req.session.otpVerified;

                    const redirectUrl = userEmail
                        ? `/login?reset=success&email=${encodeURIComponent(userEmail)}`
                        : `/login?reset=success`;

                    if (req.xhr || (req.headers.accept && req.headers.accept.includes("application/json")) || (req.headers["content-type"] && req.headers["content-type"].includes("application/json"))) {
                        return res.json({
                            success: true,
                            message: "Your password is successfully updated.",
                            redirectUrl: redirectUrl
                        });
                    }

                    return res.redirect(redirectUrl);

                }
            );

        } catch (error) {

            console.log(error);

            res.status(500).send(
                "Something went wrong"
            );

        }

    }
);


// ==================== LOGOUT ====================

app.get(
    "/logout",
    (req, res) => {
        setNoCacheHeaders(res);
        req.session.destroy(
            (err) => {
                if (err) {
                    console.log("Logout session destroy error:", err);
                }
                res.clearCookie("connect.sid", { path: "/" });
                setNoCacheHeaders(res);
                res.redirect(
                    "/login?loggedOut=true"
                );
            }
        );
    }
);


// ==================== REPORTS APIs ====================


// ==================== DEPARTMENT REPORT ====================

app.get(
    "/api/reports/departments",
    requireAdmin,
    (req, res) => {

        const sql = `
            SELECT
                COALESCE(NULLIF(TRIM(department), ''), NULLIF(TRIM(company_or_college), ''), 'General / Unassigned') AS department,
                COUNT(*) AS student_count
            FROM students
            GROUP BY COALESCE(NULLIF(TRIM(department), ''), NULLIF(TRIM(company_or_college), ''), 'General / Unassigned')
            ORDER BY student_count DESC
        `;


        db.query(
            sql,
            (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error:
                            "Database error"
                    });

                }


                res.json(results);

            }
        );

    }
);


// ==================== ROOM REPORT ====================

app.get(
    "/api/reports/rooms",
    requireAdmin,
    (req, res) => {

        const sql = `
            SELECT
                room_no,
                room_type,
                total_beds,
                occupied_beds,
                (total_beds - occupied_beds)
                    AS available_beds
            FROM rooms
            ORDER BY room_no
        `;


        db.query(
            sql,
            (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error:
                            "Database error"
                    });

                }


                res.json(results);

            }
        );

    }
);


// ==================== COMPLAINT REPORT ====================

app.get(
    "/api/reports/complaints",
    requireAdmin,
    (req, res) => {

        const sql = `
            SELECT
                COUNT(*) AS total_complaints,

                SUM(
                    CASE
                        WHEN status = 'Pending'
                        THEN 1
                        ELSE 0
                    END
                ) AS pending_complaints,

                SUM(
                    CASE
                        WHEN status = 'Resolved'
                        THEN 1
                        ELSE 0
                    END
                ) AS resolved_complaints

            FROM complaints
        `;


        db.query(
            sql,
            (err, results) => {

                if (err) {

                    console.log(err);

                    return res.status(500).json({
                        error:
                            "Database error"
                    });

                }


                const total =
                    results[0]
                        .total_complaints || 0;


                const pending =
                    results[0]
                        .pending_complaints || 0;


                const resolved =
                    results[0]
                        .resolved_complaints || 0;


                const resolutionPercentage =
                    total > 0
                        ? (
                            (resolved / total) *
                            100
                        ).toFixed(2)
                        : 0;


                res.json({

                    total_complaints:
                        total,

                    pending_complaints:
                        pending,

                    resolved_complaints:
                        resolved,

                    resolution_percentage:
                        resolutionPercentage

                });

            }
        );

    }
);





// ==================== ADMIN FEES - GET ALL STUDENTS & MONTHLY RECORDS ====================

app.get("/api/admin/fees", requireAdmin, (req, res) => {
    const filterMonth = req.query.month; // e.g. '2026-10' or 'all'

    let sql = `
        SELECT
            u.user_id,
            u.name,
            u.email,
            COALESCE(s.phone, u.phone) AS phone,
            s.room_no,
            COALESCE(s.resident_type, 'Jobholder') AS resident_type,
            COALESCE(s.monthly_rent, f.total_fee, 6500) AS monthly_rent_rate,
            f.fee_id,
            f.total_fee,
            f.paid_amount,
            f.pending_amount,
            f.status,
            COALESCE(f.month_name, 'October 2026') AS month_name,
            COALESCE(f.billing_month, '2026-10') AS billing_month,
            COALESCE(f.fee_type, 'Monthly Stay Fee') AS fee_type
        FROM users u
        LEFT JOIN students s
            ON s.user_id = u.user_id 
            OR LOWER(TRIM(s.email)) = LOWER(TRIM(u.email))
            OR LOWER(TRIM(s.name)) = LOWER(TRIM(u.name))
        LEFT JOIN fees f
            ON f.user_id = u.user_id OR LOWER(TRIM(f.student_name)) = LOWER(TRIM(u.name))
        WHERE u.role = 'student'
    `;

    const params = [];
    if (filterMonth && filterMonth !== "all") {
        sql += ` AND (f.billing_month = ? OR f.month_name LIKE ?)`;
        params.push(filterMonth, `%${filterMonth}%`);
    }

    sql += ` ORDER BY f.fee_id DESC, u.user_id ASC`;

    db.query(sql, params, (err, results) => {
        if (err) {
            console.error("Admin fees query error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        res.json(results);
    });
});

// Admin Monthly Fee Summary Analytics
app.get("/api/admin/fees/summary", requireAdmin, (req, res) => {
    const filterMonth = req.query.month; // e.g. '2026-10' or 'all'

    // 1. Get available months
    const monthsSql = `
        SELECT DISTINCT 
            COALESCE(billing_month, '2026-10') AS billing_month,
            COALESCE(month_name, 'October 2026') AS month_name
        FROM fees
        WHERE billing_month IS NOT NULL
        ORDER BY billing_month DESC
    `;

    db.query(monthsSql, (mErr, monthRows) => {
        const availableMonths = (monthRows && monthRows.length > 0) 
            ? monthRows 
            : [{ billing_month: "2026-10", month_name: "October 2026" }];

        let statsSql = `
            SELECT
                COUNT(DISTINCT u.user_id) AS total_residents,
                COALESCE(SUM(f.total_fee), 0) AS total_receivable,
                COALESCE(SUM(f.paid_amount), 0) AS total_collected,
                COALESCE(SUM(f.pending_amount), 0) AS total_pending,
                SUM(CASE WHEN f.status = 'Paid' THEN 1 ELSE 0 END) AS paid_count,
                SUM(CASE WHEN f.status = 'Partial' THEN 1 ELSE 0 END) AS partial_count,
                SUM(CASE WHEN f.status = 'Pending' OR f.status IS NULL THEN 1 ELSE 0 END) AS pending_count
            FROM users u
            LEFT JOIN fees f ON f.user_id = u.user_id OR LOWER(TRIM(f.student_name)) = LOWER(TRIM(u.name))
            WHERE u.role = 'student'
        `;

        const statParams = [];
        if (filterMonth && filterMonth !== "all") {
            statsSql += ` AND (f.billing_month = ? OR f.month_name LIKE ?)`;
            statParams.push(filterMonth, `%${filterMonth}%`);
        }

        db.query(statsSql, statParams, (sErr, statsResult) => {
            if (sErr) {
                console.error("Fee summary stats error:", sErr);
                return res.status(500).json({ error: "Database error" });
            }

            const stats = statsResult && statsResult.length > 0 ? statsResult[0] : {};
            res.json({
                total_residents: Number(stats.total_residents) || 0,
                total_receivable: Number(stats.total_receivable) || 0,
                total_collected: Number(stats.total_collected) || 0,
                total_pending: Number(stats.total_pending) || 0,
                paid_count: Number(stats.paid_count) || 0,
                partial_count: Number(stats.partial_count) || 0,
                pending_count: Number(stats.pending_count) || 0,
                available_months: availableMonths,
                current_filter: filterMonth || "all"
            });
        });
    });
});

// Admin Monthly Bill Generator: Generate next month's stay fee for all active residents
app.post("/api/admin/fees/bill-month", requireAdmin, async (req, res) => {
    const { month_name, billing_month, due_date } = req.body;

    if (!month_name || !billing_month) {
        return res.status(400).json({ error: "Month name and billing month identifier are required (e.g. November 2026, 2026-11)." });
    }

    try {
        // Find all active students with assigned rooms or active records
        const studentsSql = `
            SELECT s.student_id, s.user_id, s.name, s.room_no, COALESCE(s.monthly_rent, 6500) AS monthly_rent
            FROM students s
            WHERE s.name IS NOT NULL AND TRIM(s.name) != ''
        `;

        db.query(studentsSql, async (err, activeStudents) => {
            if (err) {
                console.error("Error fetching students for billing:", err);
                return res.status(500).json({ error: "Database error fetching residents" });
            }

            if (!activeStudents || activeStudents.length === 0) {
                return res.status(400).json({ error: "No active residents found to bill." });
            }

            let billedCount = 0;
            let skippedCount = 0;

            for (const st of activeStudents) {
                const rent = Number(st.monthly_rent) || 6500;
                const residentName = st.name.trim();
                const uid = st.user_id || null;

                // Check if already billed for this month
                const checkSql = `
                    SELECT fee_id FROM fees
                    WHERE (user_id = ? OR LOWER(TRIM(student_name)) = LOWER(TRIM(?)))
                      AND billing_month = ?
                    LIMIT 1
                `;

                const existing = await new Promise((resolve) => {
                    db.query(checkSql, [uid, residentName, billing_month], (cErr, cRes) => {
                        resolve(cRes && cRes.length > 0 ? cRes[0] : null);
                    });
                });

                if (existing) {
                    skippedCount++;
                    continue;
                }

                // Insert monthly stay fee
                const insertFeeSql = `
                    INSERT INTO fees
                    (user_id, student_name, total_fee, paid_amount, pending_amount, status, fee_type, month_name, billing_month, due_date)
                    VALUES (?, ?, ?, 0, ?, 'Pending', 'Monthly Stay Fee', ?, ?, ?)
                `;

                await new Promise((resolve) => {
                    db.query(insertFeeSql, [uid, residentName, rent, rent, month_name, billing_month, due_date || null], () => {
                        billedCount++;
                        resolve();
                    });
                });
            }

            res.json({
                success: true,
                message: `Monthly billing generated for ${month_name}! Billed ${billedCount} residents (Skipped ${skippedCount} already billed).`,
                billed_count: billedCount,
                skipped_count: skippedCount,
                month_name: month_name
            });
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});


app.put("/api/admin/fees/correct", requireAdmin, (req, res) => {
    const { user_id, fee_id, paid_amount } = req.body;

    if ((!user_id && !fee_id) || paid_amount === undefined) {
        return res.status(400).json({
            error: "Invalid payment details"
        });
    }

    const correctPaidAmount = Number(paid_amount);
    if (isNaN(correctPaidAmount) || correctPaidAmount < 0) {
        return res.status(400).json({
            error: "Invalid paid amount"
        });
    }

    const fetchFeeQuery = fee_id
        ? "SELECT fee_id, total_fee, paid_amount FROM fees WHERE fee_id = ? LIMIT 1"
        : "SELECT fee_id, total_fee, paid_amount FROM fees WHERE user_id = ? ORDER BY fee_id DESC LIMIT 1";
    const fetchParam = fee_id ? [fee_id] : [user_id];

    db.query(fetchFeeQuery, fetchParam, (err, fees) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: "Database error" });
        }
        if (!fees || fees.length === 0) {
            return res.status(404).json({ error: "Fee record not found" });
        }

        const fee = fees[0];
        const totalFee = Number(fee.total_fee);


        if (correctPaidAmount > totalFee) {
            return res.status(400).json({
                error: "Paid amount cannot exceed total fee"
            });
        }

        const pendingAmount = totalFee - correctPaidAmount;
        const status = pendingAmount === 0 ? "Paid" : (correctPaidAmount > 0 ? "Partial" : "Pending");

        const updateSql = `
            UPDATE fees
            SET paid_amount = ?, pending_amount = ?, status = ?
            WHERE fee_id = ?
        `;

        db.query(updateSql, [correctPaidAmount, pendingAmount, status, fee.fee_id], (uErr) => {
            if (uErr) {
                console.error(uErr);
                return res.status(500).json({ error: "Unable to correct payment" });
            }

            res.json({
                fee_id: fee.fee_id,
                total_fee: totalFee,
                paid_amount: correctPaidAmount,
                pending_amount: pendingAmount,
                status: status
            });
        });
    });
});

// ==================== ADMIN FEES - UPDATE PAYMENT ====================
app.put("/api/admin/fees", requireAdmin, (req, res) => {
    const { user_id, fee_id, payment_amount } = req.body;

    if ((!user_id && !fee_id) || !payment_amount) {
        return res.status(400).json({ error: "Invalid payment details" });
    }

    const payment = Number(payment_amount);
    if (isNaN(payment) || payment <= 0) {
        return res.status(400).json({ error: "Payment amount must be greater than 0" });
    }

    const fetchFeeQuery = fee_id
        ? "SELECT fee_id, total_fee, paid_amount FROM fees WHERE fee_id = ? LIMIT 1"
        : "SELECT fee_id, total_fee, paid_amount FROM fees WHERE user_id = ? ORDER BY fee_id DESC LIMIT 1";
    const fetchParam = fee_id ? [fee_id] : [user_id];

    db.query(fetchFeeQuery, fetchParam, (err, fees) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: "Database error" });
        }
        if (!fees || fees.length === 0) {
            return res.status(404).json({ error: "Fee record not found" });
        }

        const fee = fees[0];
        const totalFee = Number(fee.total_fee);
        const oldPaidAmount = Number(fee.paid_amount) || 0;
        const newPaidAmount = oldPaidAmount + payment;

        if (newPaidAmount > totalFee) {
            return res.status(400).json({ error: "Payment exceeds the pending fee" });
        }

        const newPendingAmount = totalFee - newPaidAmount;
        const newStatus = newPendingAmount === 0 ? "Paid" : "Partial";

        const updateSql = `
            UPDATE fees
            SET paid_amount = ?, pending_amount = ?, status = ?
            WHERE fee_id = ?
        `;

        db.query(updateSql, [newPaidAmount, newPendingAmount, newStatus, fee.fee_id], (uErr) => {
            if (uErr) {
                console.error(uErr);
                return res.status(500).json({ error: "Unable to update payment" });
            }

            res.json({
                fee_id: fee.fee_id,
                total_fee: totalFee,
                paid_amount: newPaidAmount,
                pending_amount: newPendingAmount,
                status: newStatus
            });
        });
    });
});


// ==================== SETTINGS & CONFIGURATION APIS ====================

// 1. Get Hostel Configuration (Public / Resident / Admin)
app.get("/api/settings", (req, res) => {
    db.query("SELECT * FROM hostel_settings WHERE setting_id = 1", (err, results) => {
        if (err) {
            console.error("Settings query error:", err);
            return res.status(500).json({ error: "Database error fetching settings" });
        }
        if (!results || results.length === 0) {
            return res.json({
                setting_id: 1,
                hostel_name: "Executive PG & Private Hostel",
                hostel_tagline: "Modern Living & Homely Accommodation",
                hostel_address: "Plot 42, Silicon Valley Colony, Madhapur, Hyderabad, TS - 500081",
                contact_phone: "9876543210",
                contact_email: "info@hostelpg.com",
                warden_name: "Chief Warden Desk",
                warden_phone: "9704844011",
                gate_closing_time: "10:30 PM",
                wifi_ssid: "Hostel_HighSpeed_Fiber",
                wifi_password: "HostelWifi@2026",
                hostel_upi_id: "hostel.fees@okhdfcbank",
                hostel_upi_name: "Hostel Management",
                hostel_upi_mobile: "9704844011",
                default_monthly_rent: 6500,
                default_security_deposit: 5000,
                notice_period_days: 15,
                mess_morning_time: "7:30 AM - 10:00 AM",
                mess_lunch_time: "12:30 PM - 3:00 PM",
                mess_dinner_time: "7:30 PM - 10:00 PM"
            });
        }
        res.json(results[0]);
    });
});

// 2. Update Hostel Configuration (Admin Only)
app.put("/api/settings", requireAdmin, (req, res) => {
    const {
        hostel_name,
        hostel_tagline,
        hostel_address,
        contact_phone,
        contact_email,
        warden_name,
        warden_phone,
        gate_closing_time,
        wifi_ssid,
        wifi_password,
        hostel_upi_id,
        hostel_upi_name,
        hostel_upi_mobile,
        default_monthly_rent,
        default_security_deposit,
        notice_period_days,
        mess_morning_time,
        mess_lunch_time,
        mess_dinner_time
    } = req.body;

    const sql = `
        INSERT INTO hostel_settings
        (setting_id, hostel_name, hostel_tagline, hostel_address, contact_phone, contact_email,
         warden_name, warden_phone, gate_closing_time, wifi_ssid, wifi_password,
         hostel_upi_id, hostel_upi_name, hostel_upi_mobile, default_monthly_rent,
         default_security_deposit, notice_period_days, mess_morning_time, mess_lunch_time, mess_dinner_time)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE
            hostel_name = VALUES(hostel_name),
            hostel_tagline = VALUES(hostel_tagline),
            hostel_address = VALUES(hostel_address),
            contact_phone = VALUES(contact_phone),
            contact_email = VALUES(contact_email),
            warden_name = VALUES(warden_name),
            warden_phone = VALUES(warden_phone),
            gate_closing_time = VALUES(gate_closing_time),
            wifi_ssid = VALUES(wifi_ssid),
            wifi_password = VALUES(wifi_password),
            hostel_upi_id = VALUES(hostel_upi_id),
            hostel_upi_name = VALUES(hostel_upi_name),
            hostel_upi_mobile = VALUES(hostel_upi_mobile),
            default_monthly_rent = VALUES(default_monthly_rent),
            default_security_deposit = VALUES(default_security_deposit),
            notice_period_days = VALUES(notice_period_days),
            mess_morning_time = VALUES(mess_morning_time),
            mess_lunch_time = VALUES(mess_lunch_time),
            mess_dinner_time = VALUES(mess_dinner_time)
    `;

    db.query(sql, [
        hostel_name || 'Executive PG & Private Hostel',
        hostel_tagline || 'Modern Living & Homely Accommodation',
        hostel_address || '',
        contact_phone || '',
        contact_email || '',
        warden_name || 'Chief Warden Desk',
        warden_phone || '',
        gate_closing_time || '10:30 PM',
        wifi_ssid || '',
        wifi_password || '',
        hostel_upi_id || 'hostel.fees@okhdfcbank',
        hostel_upi_name || 'Hostel Management',
        hostel_upi_mobile || '',
        Number(default_monthly_rent) || 6500,
        Number(default_security_deposit) || 5000,
        Number(notice_period_days) || 15,
        mess_morning_time || '7:30 AM - 10:00 AM',
        mess_lunch_time || '12:30 PM - 3:00 PM',
        mess_dinner_time || '7:30 PM - 10:00 PM'
    ], (err) => {
        if (err) {
            console.error("Update settings error:", err);
            return res.status(500).json({ success: false, error: "Failed to update hostel settings: " + err.message });
        }
        res.json({ success: true, message: "Hostel configurations updated successfully!" });
    });
});

// 3. Update Admin Profile & Password (Admin Only)
app.put("/api/admin/profile", requireAdmin, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { name, email, phone, currentPassword, newPassword } = req.body;

        if (!name || !email) {
            return res.status(400).json({ success: false, error: "Name and email are required." });
        }

        if (newPassword) {
            if (!currentPassword) {
                return res.status(400).json({ success: false, error: "Current password is required to set a new password." });
            }
            if (newPassword.length < 6) {
                return res.status(400).json({ success: false, error: "New password must be at least 6 characters long." });
            }

            db.query("SELECT password FROM users WHERE user_id = ?", [userId], async (err, results) => {
                if (err || !results || results.length === 0) {
                    return res.status(500).json({ success: false, error: "User verification error" });
                }

                const match = await bcrypt.compare(currentPassword, results[0].password);
                if (!match) {
                    return res.status(400).json({ success: false, error: "Current password does not match our records." });
                }

                const hashed = await bcrypt.hash(newPassword, 10);
                db.query(
                    "UPDATE users SET name = ?, email = ?, phone = ?, password = ? WHERE user_id = ?",
                    [name, email, phone || null, hashed, userId],
                    (updateErr) => {
                        if (updateErr) {
                            return res.status(500).json({ success: false, error: "Failed to update profile." });
                        }
                        req.session.name = name;
                        req.session.email = email;
                        return res.json({ success: true, message: "Admin profile and password updated successfully!" });
                    }
                );
            });
        } else {
            db.query(
                "UPDATE users SET name = ?, email = ?, phone = ? WHERE user_id = ?",
                [name, email, phone || null, userId],
                (updateErr) => {
                    if (updateErr) {
                        return res.status(500).json({ success: false, error: "Failed to update profile." });
                    }
                    req.session.name = name;
                    req.session.email = email;
                    return res.json({ success: true, message: "Admin profile updated successfully!" });
                }
            );
        }
    } catch (e) {
        console.error("Admin profile update exception:", e);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});

// Clean test users endpoint: deletes all users except admin and 257r1a66p7@cmrtc.ac.in
app.post("/api/admin/clean-test-users", requireAdmin, (req, res) => {
    const keepEmail = "257r1a66p7@cmrtc.ac.in";
    const findUsersSql = `
        SELECT user_id, email, name FROM users 
        WHERE role != 'admin' AND LOWER(TRIM(email)) != LOWER(?)
    `;

    db.query(findUsersSql, [keepEmail], (err, usersToDelete) => {
        if (err) return res.status(500).json({ success: false, error: err.message });

        if (!usersToDelete || usersToDelete.length === 0) {
            return res.json({
                success: true,
                message: `Database is already clean. Only admin and ${keepEmail} exist in users table.`,
                deleted_count: 0
            });
        }

        const userIds = usersToDelete.map(u => u.user_id).filter(Boolean);
        const userEmails = usersToDelete.map(u => u.email).filter(Boolean);
        const userNames = usersToDelete.map(u => u.name).filter(Boolean);

        db.query("DELETE FROM students WHERE user_id IN (?) OR LOWER(TRIM(email)) != LOWER(?)", [userIds, keepEmail], () => {});
        db.query("DELETE FROM fees WHERE user_id IN (?) OR student_name IN (?)", [userIds, userNames], () => {});
        db.query("DELETE FROM payments WHERE user_id IN (?) OR student_name IN (?)", [userIds, userNames], () => {});
        db.query("DELETE FROM complaints WHERE student_id IN (?)", [userIds], () => {});
        db.query("DELETE FROM vacating_notices WHERE resident_id IN (?)", [userIds], () => {});
        db.query("DELETE FROM users WHERE user_id IN (?)", [userIds], (delErr) => {
            if (delErr) return res.status(500).json({ success: false, error: delErr.message });

            // Synchronize rooms occupied_beds
            db.query(`
                UPDATE rooms r
                SET occupied_beds = (
                    SELECT COUNT(*) FROM students s WHERE s.room_no = r.room_no
                )
            `, () => {
                res.json({
                    success: true,
                    message: `Deleted ${userIds.length} test users successfully. Retained admin and ${keepEmail}.`,
                    deleted_count: userIds.length,
                    deleted_users: usersToDelete.map(u => u.email)
                });
            });
        });
    });
});

// List all system users with room and verification info
app.get("/api/admin/users", requireAdmin, (req, res) => {
    const sql = `
        SELECT 
            u.user_id, 
            u.name, 
            u.email, 
            COALESCE(s.phone, u.phone) AS phone, 
            u.role, 
            u.profile_photo,
            s.student_id,
            s.room_no,
            COALESCE(s.id_proof_status, 'No Document') AS id_proof_status,
            s.id_proof_type,
            s.id_proof_filename
        FROM users u
        LEFT JOIN students s 
            ON s.user_id = u.user_id 
            OR LOWER(TRIM(s.email)) = LOWER(TRIM(u.email))
            OR LOWER(TRIM(s.name)) = LOWER(TRIM(u.name))
        ORDER BY u.user_id DESC
    `;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ success: false, error: err.message });
        res.json({ success: true, users: results });
    });
});

// Delete a single user
app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
    const targetUserId = parseInt(req.params.id, 10);
    if (!targetUserId) return res.status(400).json({ success: false, error: "Invalid user ID" });

    if (req.session.userId === targetUserId) {
        return res.status(400).json({ success: false, error: "Cannot delete your own active administrator account." });
    }

    db.query("SELECT user_id, email, name, role FROM users WHERE user_id = ?", [targetUserId], (fErr, rows) => {
        if (fErr || !rows || rows.length === 0) {
            return res.status(404).json({ success: false, error: "User not found" });
        }

        const user = rows[0];

        // Check if student has room assigned
        db.query("SELECT room_no FROM students WHERE user_id = ? OR LOWER(TRIM(email)) = LOWER(?)", [targetUserId, user.email], (sErr, sRows) => {
            const roomNo = (!sErr && sRows && sRows.length > 0) ? sRows[0].room_no : null;

            // Delete linked data
            db.query("DELETE FROM fees WHERE user_id = ? OR LOWER(TRIM(student_name)) = LOWER(?)", [targetUserId, user.name], () => {});
            db.query("DELETE FROM payments WHERE user_id = ? OR LOWER(TRIM(student_name)) = LOWER(?)", [targetUserId, user.name], () => {});
            db.query("DELETE FROM complaints WHERE student_id = ?", [targetUserId], () => {});
            db.query("DELETE FROM vacating_notices WHERE resident_id = ?", [targetUserId], () => {});
            db.query("DELETE FROM reviews WHERE user_id = ?", [targetUserId], () => {});
            db.query("DELETE FROM students WHERE user_id = ? OR LOWER(TRIM(email)) = LOWER(?)", [targetUserId, user.email], () => {});

            db.query("DELETE FROM users WHERE user_id = ?", [targetUserId], (delErr) => {
                if (delErr) return res.status(500).json({ success: false, error: delErr.message });

                // Recalculate room occupancy
                if (roomNo) {
                    db.query("UPDATE rooms SET occupied_beds = (SELECT COUNT(*) FROM students WHERE room_no = ?) WHERE room_no = ?", [roomNo, roomNo], () => {});
                }

                res.json({ success: true, message: `User ${user.name} (${user.email}) deleted successfully.` });
            });
        });
    });
});

// Create single user
app.post("/api/admin/create-user", requireAdmin, async (req, res) => {
    try {
        const { name, email, phone, role, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ success: false, error: "Name, email, and password are required." });
        }
        const cleanEmail = email.trim().toLowerCase();
        db.query("SELECT user_id FROM users WHERE LOWER(email) = ?", [cleanEmail], async (err, results) => {
            if (err) return res.status(500).json({ success: false, error: err.message });
            if (results && results.length > 0) {
                return res.status(400).json({ success: false, error: "A user with this email already exists." });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            const userRole = role || "student";
            db.query(
                "INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)",
                [name.trim(), cleanEmail, phone ? phone.trim() : "", hashedPassword, userRole],
                (insErr, insRes) => {
                    if (insErr) return res.status(500).json({ success: false, error: insErr.message });
                    const newUserId = insRes.insertId;

                    if (userRole === "student") {
                        db.query(
                            "INSERT INTO students (name, room_no, phone, user_id, resident_type, stay_type, check_in_date, monthly_rent) VALUES (?, NULL, ?, ?, 'Student', 'Monthly Stay', CURDATE(), 6500)",
                            [name.trim(), phone ? phone.trim() : "", newUserId],
                            () => {}
                        );
                    }

                    res.json({
                        success: true,
                        message: `User '${name}' created successfully with role '${userRole}'!`,
                        userId: newUserId
                    });
                }
            );
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Bulk upload / import users from CSV or JSON
app.post("/api/admin/upload-users", requireAdmin, async (req, res) => {
    try {
        const { users } = req.body;
        if (!Array.isArray(users) || users.length === 0) {
            return res.status(400).json({ success: false, error: "No user data found in the uploaded file." });
        }

        let createdCount = 0;
        let skippedCount = 0;
        const errors = [];

        for (const u of users) {
            if (!u.name || !u.email) {
                skippedCount++;
                continue;
            }
            const cleanEmail = String(u.email).trim().toLowerCase();
            const rawPassword = u.password ? String(u.password).trim() : "Hostel@123";
            const role = (u.role && ["admin", "warden", "staff", "student"].includes(String(u.role).toLowerCase()))
                ? String(u.role).toLowerCase()
                : "student";
            const phone = u.phone ? String(u.phone).trim() : "";
            const name = String(u.name).trim();

            const existing = await new Promise((resolve) => {
                db.query("SELECT user_id FROM users WHERE LOWER(email) = ?", [cleanEmail], (e, r) => {
                    resolve(r && r.length > 0 ? r[0] : null);
                });
            });

            if (existing) {
                skippedCount++;
                continue;
            }

            const hashedPassword = await bcrypt.hash(rawPassword, 10);
            await new Promise((resolve) => {
                db.query(
                    "INSERT INTO users (name, email, phone, password, role) VALUES (?, ?, ?, ?, ?)",
                    [name, cleanEmail, phone, hashedPassword, role],
                    (insErr, insRes) => {
                        if (insErr) {
                            errors.push(`${cleanEmail}: ${insErr.message}`);
                            resolve(false);
                        } else {
                            createdCount++;
                            const newUserId = insRes.insertId;
                            if (role === "student") {
                                db.query(
                                    "INSERT INTO students (name, room_no, phone, user_id, resident_type, stay_type, check_in_date, monthly_rent) VALUES (?, NULL, ?, ?, 'Student', 'Monthly Stay', CURDATE(), 6500)",
                                    [name, phone, newUserId],
                                    () => resolve(true)
                                );
                            } else {
                                resolve(true);
                            }
                        }
                    }
                );
            });
        }

        res.json({
            success: true,
            message: `Batch upload complete! ${createdCount} user(s) imported, ${skippedCount} duplicate/invalid skipped.`,
            createdCount,
            skippedCount,
            errors
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// 4. Get Student Settings & Resident Profile
app.get("/api/student-settings", requireStudent, (req, res) => {
    const userId = req.session.userId;
    const sql = `
        SELECT 
            u.user_id,
            u.name,
            u.email,
            COALESCE(s.phone, u.phone) AS phone,
            s.student_id,
            s.room_no,
            s.resident_type,
            s.native_city,
            s.emergency_name,
            s.emergency_phone,
            COALESCE(s.dietary_preference, 'Pure Veg') AS dietary_preference,
            s.food_plan,
            s.company_or_college,
            COALESCE(s.id_proof_type, 'Aadhaar Card') AS id_proof_type,
            s.id_proof_number,
            s.id_proof_file,
            s.id_proof_filename,
            COALESCE(s.id_proof_status, 'Pending Verification') AS id_proof_status,
            s.id_proof_rejection_reason
        FROM users u
        LEFT JOIN students s 
            ON s.user_id = u.user_id 
            OR LOWER(TRIM(s.email)) = LOWER(TRIM(u.email))
            OR LOWER(TRIM(s.name)) = LOWER(TRIM(u.name))
        WHERE u.user_id = ?
        LIMIT 1
    `;
    db.query(sql, [userId], (err, results) => {
        if (err || !results || results.length === 0) {
            return res.status(404).json({ error: "Resident details not found." });
        }
        const profile = results[0];
        const rawNum = profile.id_proof_number ? String(profile.id_proof_number).trim() : "";
        profile.id_proof_number_masked = rawNum 
            ? ("•••• •••• " + (rawNum.length >= 4 ? rawNum.slice(-4) : "••••"))
            : "Stored & Confidential";
        profile.id_proof_number = profile.id_proof_number_masked;
        profile.id_proof_status = profile.id_proof_status || "Pending Verification";
        profile.is_verified = (profile.id_proof_status === "Verified");

        db.query("SELECT * FROM hostel_settings WHERE setting_id = 1", (setErr, setResults) => {
            const hostelInfo = (setResults && setResults.length > 0) ? setResults[0] : {};
            res.json({
                profile: profile,
                hostel: hostelInfo
            });
        });
    });
});

// 5. Update Student Settings & Preferences
app.put("/api/student-settings/profile", requireStudent, async (req, res) => {
    const userId = req.session.userId;
    const { phone, emergency_name, emergency_phone, native_city, dietary_preference, id_proof_type, id_proof_number, id_proof_file, id_proof_filename } = req.body;

    let validIdType = null;
    let validIdNum = null;
    if (id_proof_number && String(id_proof_number).trim()) {
        const idCheck = validateGovernmentId(id_proof_type, id_proof_number);
        if (!idCheck.valid) {
            return res.status(400).json({ success: false, error: idCheck.error });
        }
        validIdType = idCheck.cleanType;
        validIdNum = idCheck.cleanNum;

        // Duplicate check against other residents
        try {
            const dup = await checkDuplicateIdProof(validIdNum);
            if (dup && dup.user_id && dup.user_id !== userId) {
                return res.status(400).json({
                    success: false,
                    error: `This Government ID proof (${validIdType} ending in ${validIdNum.slice(-4)}) is already registered in the system under resident "${dup.name}". Impersonating another person's ID proof is strictly prohibited.`
                });
            }
        } catch (dupErr) {
            console.error("Duplicate check in student-settings:", dupErr);
        }
    }

    let savedDocFilename = null;
    if (id_proof_file && id_proof_file.startsWith("data:")) {
        try {
            savedDocFilename = saveSecureIdDocument(id_proof_file, id_proof_filename, `stu_pref_${userId}_${Date.now()}`);
        } catch (dErr) {
            return res.status(400).json({ success: false, error: dErr.message });
        }
    }

    db.query("UPDATE users SET phone = ? WHERE user_id = ?", [phone || null, userId], (uErr) => {
        if (uErr) console.warn("Notice: user phone update warning:", uErr.message);

        const stuSql = savedDocFilename
            ? `UPDATE students
               SET phone = COALESCE(?, phone),
                   emergency_name = COALESCE(?, emergency_name),
                   emergency_phone = COALESCE(?, emergency_phone),
                   native_city = COALESCE(?, native_city),
                   dietary_preference = COALESCE(?, dietary_preference),
                   id_proof_type = COALESCE(?, id_proof_type),
                   id_proof_number = COALESCE(?, id_proof_number),
                   id_proof_file = ?,
                   id_proof_filename = ?,
                   id_proof_status = 'Pending Verification',
                   id_proof_rejection_reason = NULL
               WHERE user_id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?))`
            : `UPDATE students
               SET phone = COALESCE(?, phone),
                   emergency_name = COALESCE(?, emergency_name),
                   emergency_phone = COALESCE(?, emergency_phone),
                   native_city = COALESCE(?, native_city),
                   dietary_preference = COALESCE(?, dietary_preference),
                   id_proof_type = COALESCE(?, id_proof_type),
                   id_proof_number = COALESCE(?, id_proof_number)
               WHERE user_id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?))`;

        const updateParams = savedDocFilename
            ? [phone, emergency_name, emergency_phone, native_city, dietary_preference, validIdType, validIdNum, savedDocFilename, id_proof_filename || null, userId, req.session.name || ""]
            : [phone, emergency_name, emergency_phone, native_city, dietary_preference, validIdType, validIdNum, userId, req.session.name || ""];

        db.query(
            stuSql,
            updateParams,
            (sErr) => {
                if (sErr) {
                    console.error("Student profile update error:", sErr);
                    return res.status(500).json({ success: false, error: "Failed to update profile details." });
                }
                res.json({
                    success: true,
                    message: savedDocFilename 
                        ? "Preferences and new ID document updated successfully! Document submitted for admin verification."
                        : "Resident preferences updated successfully!"
                });
            }
        );
    });
});

// 6. Update Student Password
app.put("/api/student-settings/password", requireStudent, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ success: false, error: "Both current password and new password are required." });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ success: false, error: "New password must be at least 6 characters long." });
        }

        db.query("SELECT password FROM users WHERE user_id = ?", [userId], async (err, results) => {
            if (err || !results || results.length === 0) {
                return res.status(500).json({ success: false, error: "User verification error" });
            }

            const match = await bcrypt.compare(currentPassword, results[0].password);
            if (!match) {
                return res.status(400).json({ success: false, error: "Current password does not match." });
            }

            const hashed = await bcrypt.hash(newPassword, 10);
            db.query("UPDATE users SET password = ? WHERE user_id = ?", [hashed, userId], (upErr) => {
                if (upErr) {
                    return res.status(500).json({ success: false, error: "Failed to update password." });
                }
                res.json({ success: true, message: "Password updated successfully!" });
            });
        });
    } catch (e) {
        console.error("Student password update exception:", e);
        res.status(500).json({ success: false, error: "Internal server error" });
    }
});


// ==================== REVIEWS & RATINGS API ====================

// 1. Get all published reviews + aggregate ratings (Accessible to all logged-in users)
app.get("/api/reviews", (req, res) => {
    const filterCategory = req.query.category;
    const filterRating = req.query.rating;

    let sql = `
        SELECT 
            review_id,
            user_id,
            student_name,
            room_no,
            resident_type,
            rating,
            category,
            title,
            comment,
            status,
            admin_reply,
            DATE_FORMAT(admin_replied_at, '%d %b %Y, %h:%i %p') AS admin_replied_at,
            DATE_FORMAT(created_at, '%d %b %Y, %h:%i %p') AS review_date,
            created_at
        FROM reviews
        WHERE status != 'Hidden'
    `;
    const params = [];

    if (filterCategory && filterCategory !== "all") {
        sql += ` AND category = ?`;
        params.push(filterCategory);
    }
    if (filterRating && filterRating !== "all") {
        sql += ` AND rating = ?`;
        params.push(Number(filterRating));
    }

    sql += ` ORDER BY review_id DESC`;

    db.query(sql, params, (err, reviews) => {
        if (err) {
            console.error("Reviews fetch error:", err);
            return res.status(500).json({ success: false, error: "Database error" });
        }

        // Also fetch global statistics
        const statsSql = `
            SELECT 
                COUNT(*) AS total_reviews,
                COALESCE(AVG(rating), 5.0) AS average_rating,
                SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) AS stars_5,
                SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) AS stars_4,
                SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) AS stars_3,
                SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) AS stars_2,
                SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) AS stars_1
            FROM reviews
            WHERE status != 'Hidden'
        `;

        db.query(statsSql, (sErr, statsResult) => {
            const stats = (statsResult && statsResult.length > 0) ? statsResult[0] : {};
            const total = Number(stats.total_reviews) || 0;
            const avg = total > 0 ? Number(Number(stats.average_rating).toFixed(1)) : 5.0;

            res.json({
                success: true,
                reviews: reviews || [],
                stats: {
                    total_reviews: total,
                    average_rating: avg,
                    distribution: {
                        5: Number(stats.stars_5) || 0,
                        4: Number(stats.stars_4) || 0,
                        3: Number(stats.stars_3) || 0,
                        2: Number(stats.stars_2) || 0,
                        1: Number(stats.stars_1) || 0
                    }
                }
            });
        });
    });
});

// 2. Submit a new review (Resident only)
app.post("/api/reviews", requireStudent, (req, res) => {
    const userId = req.session.userId;
    const { rating, category, title, comment } = req.body;

    const starRating = Number(rating);
    if (!starRating || starRating < 1 || starRating > 5) {
        return res.status(400).json({ success: false, error: "Please provide a valid rating between 1 and 5 stars." });
    }
    if (!comment || !comment.trim()) {
        return res.status(400).json({ success: false, error: "Please share a few words in your review feedback." });
    }

    // Lookup resident details
    const studentSql = `
        SELECT name, room_no, resident_type 
        FROM students 
        WHERE user_id = ? OR LOWER(TRIM(email)) = LOWER(TRIM(?))
        LIMIT 1
    `;

    db.query(studentSql, [userId, req.session.email || ""], (err, students) => {
        let studentName = req.session.name || "Resident";
        let roomNo = "Unassigned";
        let residentType = "Resident";

        if (!err && students && students.length > 0) {
            studentName = students[0].name || studentName;
            roomNo = students[0].room_no || "Unassigned";
            residentType = students[0].resident_type || "Resident";
        }

        const insertSql = `
            INSERT INTO reviews 
            (user_id, student_name, room_no, resident_type, rating, category, title, comment, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Published')
        `;

        db.query(insertSql, [
            userId,
            escapeHtml(studentName),
            escapeHtml(roomNo),
            escapeHtml(residentType),
            starRating,
            escapeHtml(category || "Overall Stay"),
            escapeHtml((title && title.trim()) ? title.trim() : `${starRating}-Star Rating`),
            escapeHtml(comment.trim())
        ], (insErr, result) => {
            if (insErr) {
                console.error("Insert review error:", insErr);
                return res.status(500).json({ success: false, error: "Failed to submit review." });
            }

            res.json({
                success: true,
                message: "Thank you for your valuable feedback! Your review has been published.",
                review_id: result.insertId
            });
        });
    });
});

// 3. Get reviews submitted by current resident
app.get("/api/student-reviews/my", requireStudent, (req, res) => {
    const userId = req.session.userId;
    const sql = `
        SELECT 
            review_id,
            rating,
            category,
            title,
            comment,
            status,
            admin_reply,
            DATE_FORMAT(admin_replied_at, '%d %b %Y, %h:%i %p') AS admin_replied_at,
            DATE_FORMAT(created_at, '%d %b %Y, %h:%i %p') AS review_date
        FROM reviews
        WHERE user_id = ?
        ORDER BY review_id DESC
    `;

    db.query(sql, [userId], (err, results) => {
        if (err) return res.status(500).json({ success: false, error: "Database error" });
        res.json({ success: true, reviews: results || [] });
    });
});

// 4. Admin - Get all reviews with administrative controls
app.get("/api/admin/reviews", requireAdmin, (req, res) => {
    const filterRating = req.query.rating;
    const filterCategory = req.query.category;
    const filterStatus = req.query.status;

    let sql = `
        SELECT 
            r.review_id,
            r.user_id,
            r.student_name,
            r.room_no,
            r.resident_type,
            r.rating,
            r.category,
            r.title,
            r.comment,
            r.status,
            r.admin_reply,
            DATE_FORMAT(r.admin_replied_at, '%d %b %Y, %h:%i %p') AS admin_replied_at,
            DATE_FORMAT(r.created_at, '%d %b %Y, %h:%i %p') AS review_date,
            u.email,
            COALESCE(s.phone, u.phone) AS phone
        FROM reviews r
        LEFT JOIN users u ON u.user_id = r.user_id
        LEFT JOIN students s ON s.user_id = r.user_id
        WHERE 1=1
    `;
    const params = [];

    if (filterRating && filterRating !== "all") {
        sql += ` AND r.rating = ?`;
        params.push(Number(filterRating));
    }
    if (filterCategory && filterCategory !== "all") {
        sql += ` AND r.category = ?`;
        params.push(filterCategory);
    }
    if (filterStatus && filterStatus !== "all") {
        sql += ` AND r.status = ?`;
        params.push(filterStatus);
    }

    sql += ` ORDER BY r.review_id DESC`;

    db.query(sql, params, (err, reviews) => {
        if (err) {
            console.error("Admin reviews query error:", err);
            return res.status(500).json({ success: false, error: "Database error" });
        }

        // Global analytics
        const statsSql = `
            SELECT 
                COUNT(*) AS total_reviews,
                COALESCE(AVG(rating), 5.0) AS average_rating,
                SUM(CASE WHEN rating >= 4 THEN 1 ELSE 0 END) AS positive_count,
                SUM(CASE WHEN rating <= 2 THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN admin_reply IS NOT NULL AND TRIM(admin_reply) != '' THEN 1 ELSE 0 END) AS replied_count
            FROM reviews
        `;

        db.query(statsSql, (sErr, statsRes) => {
            const stats = (statsRes && statsRes.length > 0) ? statsRes[0] : {};
            const total = Number(stats.total_reviews) || 0;
            const avg = total > 0 ? Number(Number(stats.average_rating).toFixed(1)) : 5.0;

            res.json({
                success: true,
                reviews: reviews || [],
                stats: {
                    total_reviews: total,
                    average_rating: avg,
                    positive_count: Number(stats.positive_count) || 0,
                    critical_count: Number(stats.critical_count) || 0,
                    replied_count: Number(stats.replied_count) || 0
                }
            });
        });
    });
});

// 5. Admin - Reply to a resident review
app.post("/api/admin/reviews/:id/reply", requireAdmin, (req, res) => {
    const reviewId = req.params.id;
    const { reply } = req.body;

    if (!reply || !reply.trim()) {
        return res.status(400).json({ success: false, error: "Reply text is required." });
    }

    const sql = `
        UPDATE reviews 
        SET admin_reply = ?, admin_replied_at = NOW() 
        WHERE review_id = ?
    `;

    db.query(sql, [escapeHtml(reply.trim()), reviewId], (err, result) => {
        if (err) {
            console.error("Admin review reply error:", err);
            return res.status(500).json({ success: false, error: "Failed to post reply." });
        }
        res.json({ success: true, message: "Official response posted successfully!" });
    });
});

// 6. Admin - Update review status (Published / Featured / Hidden)
app.put("/api/admin/reviews/:id/status", requireAdmin, (req, res) => {
    const reviewId = req.params.id;
    const { status } = req.body;

    if (!status || !["Published", "Featured", "Hidden"].includes(status)) {
        return res.status(400).json({ success: false, error: "Invalid review status." });
    }

    db.query("UPDATE reviews SET status = ? WHERE review_id = ?", [status, reviewId], (err) => {
        if (err) return res.status(500).json({ success: false, error: "Failed to update review status." });
        res.json({ success: true, message: `Review marked as ${status}.` });
    });
});

// 7. Admin - Delete a review
app.delete("/api/admin/reviews/:id", requireAdmin, (req, res) => {
    const reviewId = req.params.id;
    db.query("DELETE FROM reviews WHERE review_id = ?", [reviewId], (err) => {
        if (err) return res.status(500).json({ success: false, error: "Failed to delete review." });
        res.json({ success: true, message: "Review deleted successfully." });
    });
});


// ==================== PROCESS CRASH PROTECTION ====================
process.on("uncaughtException", (err) => {
    console.error("Uncaught Exception intercepted:", err.message);
});

process.on("unhandledRejection", (reason) => {
    console.error("Unhandled Rejection intercepted:", reason);
});

// ==================== START SERVER ====================
const server = app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running at http://0.0.0.0:${PORT}`);
});

// Recommended Render keep-alive and headers timeout to eliminate 502 Bad Gateway
server.keepAliveTimeout = 120000;
server.headersTimeout = 120000;