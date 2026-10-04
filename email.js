const nodemailer = require("nodemailer");

// High-performance pooled SMTP transport for instant message dispatch
const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true, // SSL port 465 is faster and avoids STARTTLS latency
    pool: true,   // Keep socket connections open to eliminate handshake delays
    maxConnections: 5,
    maxMessages: 100,
    rateDelta: 1000,
    rateLimit: 5,
    auth: {
        user: process.env.EMAIL_USER || "pachikoruabhi2007@gmail.com",
        pass: process.env.EMAIL_PASS || "cblmzltozvsmsnvi"
    }
});

// Verify SMTP connection on startup
transporter.verify((error, success) => {
    if (error) {
        console.error("❌ Gmail SMTP Connection Error:", error);
    } else {
        console.log("✓ Gmail SMTP Transporter is ready to send emails!");
    }
});

// 1. Password Reset OTP Email
async function sendOTP(toEmail, otp) {
    const mailOptions = {
        from: '"HostelHub Security" <pachikoruabhi2007@gmail.com>',
        to: toEmail,
        priority: "high",
        headers: {
            "X-Priority": "1 (Highest)",
            "X-MSMail-Priority": "High",
            "Importance": "High"
        },
        subject: `HostelHub Password Reset Code: ${otp}`,
        date: new Date(),
        xMailer: false,
        text: `Your password reset code is: ${otp}\n\nThis code is valid for 5 minutes.\n\nHostelHub Administration`,
        html: `
            <div style="font-family: Arial, sans-serif; font-size: 15px; color: #222; line-height: 1.6; max-width: 500px;">
                <p>Hello,</p>
                <p>Use the 6-digit code below to reset your account password:</p>
                <p style="font-size: 26px; font-weight: bold; letter-spacing: 4px; color: #1e3a8a; margin: 16px 0;">
                    ${otp}
                </p>
                <p>This code is valid for 5 minutes. If you did not request this, please ignore this email.</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log("OTP email sent successfully to", toEmail);
        return true;
    } catch (error) {
        console.error("OTP email delivery error:", error);
        return false;
    }
}

// 2. Registration Gmail Existence & Ownership Verification OTP
async function sendRegistrationOTP(toEmail, otp, name) {
    const mailOptions = {
        from: '"Abhi - HostelHub" <pachikoruabhi2007@gmail.com>',
        to: toEmail,
        subject: `Your registration code: ${otp}`,
        date: new Date(),
        xMailer: false,
        text: `Hello ${name || 'Resident'},\n\nYour hostel registration code is: ${otp}\n\nThis code is valid for 10 minutes.\n\nThank you,\nHostelHub Administration`,
        html: `
            <div style="font-family: Arial, sans-serif; font-size: 15px; color: #222; line-height: 1.6; max-width: 500px;">
                <p>Hello <strong>${name || 'Resident'}</strong>,</p>
                <p>Your verification code for HostelHub registration is:</p>
                <p style="font-size: 26px; font-weight: bold; letter-spacing: 4px; color: #1e3a8a; margin: 16px 0;">
                    ${otp}
                </p>
                <p>This code will expire in 10 minutes.</p>
                <p style="color: #666; font-size: 13px; margin-top: 24px; border-top: 1px solid #eee; padding-top: 12px;">
                    Hostel Management System<br>
                    Contact: pachikoruabhi2007@gmail.com
                </p>
            </div>
        `
    };

    try {
        const info = await transporter.sendMail(mailOptions);
        console.log(`[SMTP SUCCESS] Registration OTP ${otp} dispatched to ${toEmail}. MessageID: ${info ? info.messageId : 'ok'}`);
        return { success: true, messageId: info ? info.messageId : null };
    } catch (error) {
        console.error("[SMTP ERROR] Registration email delivery failed:", error);
        return { success: false, error: error.message };
    }
}

// 3. Welcome & Admission Confirmation Email with Entry Date & Details
async function sendWelcomeEmail(toEmail, name, details) {
    const checkIn = details.check_in_date || "Today";
    const stayType = details.stay_type || "Monthly Stay";
    const occupation = details.resident_type || "Jobholder";
    const foodPlan = details.food_plan || "With Food";
    const roomInfo = details.room_no ? `Room ${details.room_no}` : "To be assigned on arrival";

    const mailOptions = {
        from: '"HostelHub Admission" <pachikoruabhi2007@gmail.com>',
        to: toEmail,
        subject: "🎉 Welcome to HostelHub - Registration Confirmed!",
        html: `
            <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 540px; margin: 0 auto; padding: 28px; border: 1px solid #e2e8f0; border-radius: 16px; background: #ffffff;">
                <div style="background: linear-gradient(135deg, #4f46e5 0%, #4338ca 100%); color: white; padding: 22px; border-radius: 12px; text-align: center; margin-bottom: 20px;">
                    <h1 style="margin: 0 0 6px 0; font-size: 22px;">Welcome to HostelHub!</h1>
                    <p style="margin: 0; font-size: 13.5px; opacity: 0.9;">Your Resident Registration is Confirmed</p>
                </div>
                <p style="font-size: 14.5px; color: #1e293b;">Dear <strong>${name}</strong>,</p>
                <p style="font-size: 14px; color: #475569; line-height: 1.6;">
                    Thank you for choosing our hostel. Your account has been registered with this Gmail address. All future invoices, receipts, and announcements will be sent to this inbox.
                </p>
                <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 18px; margin: 20px 0;">
                    <h4 style="margin: 0 0 12px 0; font-size: 14px; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px;">Admission Summary</h4>
                    <table style="width: 100%; font-size: 13.5px; border-collapse: collapse;">
                        <tr><td style="padding: 6px 0; color: #64748b;">Selected Room:</td><td style="padding: 6px 0; font-weight: 700; color: #4f46e5;">${roomInfo}</td></tr>
                        <tr><td style="padding: 6px 0; color: #64748b;">Hostel Entry / Join Date:</td><td style="padding: 6px 0; font-weight: 700; color: #0f172a;">${checkIn}</td></tr>
                        <tr><td style="padding: 6px 0; color: #64748b;">Profile Category:</td><td style="padding: 6px 0; font-weight: 700; color: #0f172a;">${occupation}</td></tr>
                        <tr><td style="padding: 6px 0; color: #64748b;">Stay Plan:</td><td style="padding: 6px 0; font-weight: 700; color: #0f172a;">${stayType}</td></tr>
                        <tr><td style="padding: 6px 0; color: #64748b;">Food Plan:</td><td style="padding: 6px 0; font-weight: 700; color: #0f172a;">${foodPlan}</td></tr>
                    </table>
                </div>
                <p style="font-size: 13px; color: #64748b; line-height: 1.5;">
                    You can log in to your Resident Portal anytime at <a href="http://localhost:3000/login" style="color: #4f46e5; font-weight: 700;">HostelHub Portal</a> using your registered Gmail and the password you created to view room details, pay rent via Razorpay / UPI, and submit queries.
                </p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log("Welcome email sent to", toEmail);
        return true;
    } catch (e) {
        console.warn("Welcome email note:", e.message);
        return false;
    }
}

// 4. Google Login Security OTP Email
async function sendGoogleLoginOTP(toEmail, otp, name) {
    const residentName = name || "Resident";
    const mailOptions = {
        from: '"HostelHub Security" <pachikoruabhi2007@gmail.com>',
        to: toEmail,
        priority: "high",
        headers: {
            "X-Priority": "1 (Highest)",
            "X-MSMail-Priority": "High",
            "Importance": "High"
        },
        subject: `HostelHub Verification Code: ${otp}`,
        date: new Date(),
        text: `Hello ${residentName},\n\nYour security verification code for Google Sign-In is: ${otp}\n\nThis code will expire in 5 minutes.\n\nHostelHub Security`,
        html: `
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 28px; border: 1px solid #e2e8f0; border-radius: 16px; background: #ffffff;">
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="display: inline-block; width: 50px; height: 50px; line-height: 50px; border-radius: 50%; background: #eff6ff; font-size: 26px;">
                        🛡️
                    </div>
                    <h2 style="color: #1e293b; margin: 12px 0 4px; font-size: 20px;">Google Sign-In Verification</h2>
                    <p style="color: #64748b; font-size: 13.5px; margin: 0;">HostelHub Security Authentication</p>
                </div>
                
                <p style="font-size: 14.5px; color: #334155; line-height: 1.5;">
                    Hello <strong>${residentName}</strong>,
                </p>
                <p style="font-size: 14px; color: #475569; line-height: 1.5;">
                    A sign-in request was initiated via Google with <strong>${toEmail}</strong>. To verify your identity and protect your hostel records, enter this 6-digit one-time code:
                </p>
                
                <div style="text-align: center; margin: 26px 0;">
                    <div style="display: inline-block; background: #f8fafc; border: 2px dashed #4285f4; border-radius: 12px; padding: 12px 32px;">
                        <span style="font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #1e3a8a; font-family: monospace;">
                            ${otp}
                        </span>
                    </div>
                </div>
                
                <div style="background: #f1f5f9; border-radius: 8px; padding: 12px; font-size: 12.5px; color: #64748b; line-height: 1.4;">
                    ⏳ <strong>Important:</strong> This one-time password expires in <strong>5 minutes</strong>. If you did not initiate this login, please ignore this email.
                </div>
                
                <p style="margin-top: 24px; padding-top: 14px; border-top: 1px solid #f1f5f9; font-size: 12px; color: #94a3b8; text-align: center;">
                    Hostel Management System Security • pachikoruabhi2007@gmail.com
                </p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`[GOOGLE SECURITY OTP] Dispatched code ${otp} to ${toEmail}`);
        return true;
    } catch (err) {
        console.error("Google security OTP delivery error:", err);
        return false;
    }
}

module.exports = sendOTP;
module.exports.sendOTP = sendOTP;
module.exports.sendRegistrationOTP = sendRegistrationOTP;
module.exports.sendWelcomeEmail = sendWelcomeEmail;
module.exports.sendGoogleLoginOTP = sendGoogleLoginOTP;
module.exports.transporter = transporter;