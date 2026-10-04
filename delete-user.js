const mysql = require("mysql2");

const targetEmail = process.argv[2];

if (!targetEmail) {
    console.log("\n❌ Please provide an email address to delete.");
    console.log("Example: node delete-user.js pachikoruabhi2007@gmail.com\n");
    process.exit(1);
}

const cleanEmail = targetEmail.trim().toLowerCase();

const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "Abhi$132007",
    database: "hostel_management"
});

db.connect((err) => {
    if (err) {
        console.error("❌ Database connection error:", err.message);
        process.exit(1);
    }

    console.log(`\n🔍 Searching for user with email: ${cleanEmail}...`);

    db.query("SELECT user_id, name, email, role FROM users WHERE LOWER(TRIM(email)) = ?", [cleanEmail], (findErr, rows) => {
        if (findErr) {
            console.error("❌ Error querying users table:", findErr.message);
            db.end();
            process.exit(1);
        }

        if (!rows || rows.length === 0) {
            console.log(`⚠️ No user found with email: ${cleanEmail}`);
            db.end();
            process.exit(0);
        }

        const user = rows[0];
        const userId = user.user_id;
        console.log(`✓ Found user: [ID: ${userId}] ${user.name} (${user.email}) - Role: ${user.role}`);

        // If user was assigned to a room, decrease occupied beds
        db.query("SELECT room_no FROM students WHERE user_id = ?", [userId], (sErr, sRows) => {
            if (!sErr && sRows && sRows.length > 0 && sRows[0].room_no) {
                const roomNo = sRows[0].room_no;
                db.query("UPDATE rooms SET occupied_beds = GREATEST(0, occupied_beds - 1) WHERE room_no = ?", [roomNo], () => {
                    console.log(`✓ Decremented bed occupancy for Room ${roomNo}`);
                });
            }

            // Delete from all linked tables
            const queries = [
                { table: "fees", sql: "DELETE FROM fees WHERE user_id = ?" },
                { table: "students", sql: "DELETE FROM students WHERE user_id = ?" },
                { table: "complaints", sql: "DELETE FROM complaints WHERE user_id = ?" },
                { table: "payments", sql: "DELETE FROM payments WHERE user_id = ?" },
                { table: "vacating_notices", sql: "DELETE FROM vacating_notices WHERE user_id = ?" },
                { table: "users", sql: "DELETE FROM users WHERE user_id = ?" }
            ];

            let completed = 0;
            queries.forEach((q) => {
                db.query(q.sql, [userId], (delErr) => {
                    if (delErr) {
                        console.warn(`Notice: Could not delete from ${q.table}:`, delErr.message);
                    }
                    completed++;
                    if (completed === queries.length) {
                        console.log(`\n🎉 User ${cleanEmail} (ID: ${userId}) has been completely deleted from the database!`);
                        console.log("You can now re-register with this email cleanly.\n");
                        db.end();
                    }
                });
            });
        });
    });
});
