const mysql = require("mysql2");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");

// Load .env file if present
const envPath = path.join(__dirname, ".env");
if (fs.existsSync(envPath)) {
    const envConfig = fs.readFileSync(envPath, "utf-8");
    envConfig.split("\n").forEach(line => {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#")) {
            const [key, ...values] = trimmed.split("=");
            if (key && values.length > 0 && !process.env[key.trim()]) {
                process.env[key.trim()] = values.join("=").trim().replace(/(^['"]|['"]$)/g, '');
            }
        }
    });
}

const dbConfig = process.env.DATABASE_URL || {
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "Abhi$132007",
    database: process.env.DB_NAME || "hostel_management",
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306
};

const poolConfig = typeof dbConfig === "string" ? dbConfig : {
    ...dbConfig,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000
};

const connection = mysql.createPool(poolConfig);

function initSchema() {
    console.log("Initializing database schema and ensuring all tables exist...");

    // 1. Create users table
    const createUsersTableSql = `
        CREATE TABLE IF NOT EXISTS users (
            user_id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            phone VARCHAR(30) DEFAULT '',
            password VARCHAR(255) NOT NULL,
            role VARCHAR(50) DEFAULT 'student',
            profile_photo VARCHAR(255) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `;
    connection.query(createUsersTableSql, (uErr) => {
        if (uErr) console.error("Error creating users table:", uErr.message);
        else console.log("✓ users table ready.");

        // 2. Create rooms table
        const createRoomsTableSql = `
            CREATE TABLE IF NOT EXISTS rooms (
                room_id INT AUTO_INCREMENT PRIMARY KEY,
                room_no VARCHAR(50) NOT NULL UNIQUE,
                room_type VARCHAR(50) DEFAULT 'Shared',
                total_beds INT DEFAULT 3,
                occupied_beds INT DEFAULT 0,
                monthly_rent DECIMAL(10,2) DEFAULT 6500,
                ac_type VARCHAR(20) DEFAULT 'Non-AC'
            )
        `;
        connection.query(createRoomsTableSql, (rmErr) => {
            if (rmErr) console.error("Error creating rooms table:", rmErr.message);
            else console.log("✓ rooms table ready.");

            // 3. Create students table
            const createStudentsTableSql = `
                CREATE TABLE IF NOT EXISTS students (
                    student_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT DEFAULT NULL,
                    name VARCHAR(100) NOT NULL,
                    room_no VARCHAR(50) DEFAULT NULL,
                    phone VARCHAR(30) DEFAULT '',
                    email VARCHAR(150) DEFAULT NULL,
                    resident_type VARCHAR(50) DEFAULT 'Jobholder',
                    company_or_college VARCHAR(150) DEFAULT NULL,
                    designation_or_course VARCHAR(100) DEFAULT NULL,
                    office_address VARCHAR(255) DEFAULT NULL,
                    id_proof_type VARCHAR(50) DEFAULT 'Aadhaar Card',
                    id_proof_number VARCHAR(100) DEFAULT NULL,
                    native_city VARCHAR(100) DEFAULT NULL,
                    stay_type VARCHAR(50) DEFAULT 'Monthly Stay',
                    check_in_date VARCHAR(30) DEFAULT NULL,
                    expected_checkout_date VARCHAR(30) DEFAULT NULL,
                    monthly_rent DECIMAL(10,2) DEFAULT 6500,
                    security_deposit DECIMAL(10,2) DEFAULT 0,
                    food_plan VARCHAR(50) DEFAULT 'With Food',
                    emergency_name VARCHAR(100) DEFAULT NULL,
                    emergency_phone VARCHAR(30) DEFAULT NULL,
                    dietary_preference VARCHAR(50) DEFAULT 'Pure Veg',
                    profile_photo VARCHAR(255) DEFAULT NULL,
                    id_proof_file VARCHAR(255) DEFAULT NULL,
                    id_proof_filename VARCHAR(255) DEFAULT NULL,
                    id_proof_status VARCHAR(50) DEFAULT 'Pending Verification',
                    id_proof_rejection_reason TEXT DEFAULT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            `;
            connection.query(createStudentsTableSql, (sErr) => {
                if (sErr) console.error("Error creating students table:", sErr.message);
                else console.log("✓ students table ready.");

                // 4. Create fees table
                const createFeesTableSql = `
                    CREATE TABLE IF NOT EXISTS fees (
                        fee_id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT DEFAULT NULL,
                        student_name VARCHAR(100) NOT NULL,
                        total_fee DECIMAL(10,2) NOT NULL DEFAULT 0,
                        paid_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
                        pending_amount DECIMAL(10,2) NOT NULL DEFAULT 0,
                        status VARCHAR(50) DEFAULT 'Pending',
                        fee_type VARCHAR(50) DEFAULT 'Monthly Stay Fee',
                        month_name VARCHAR(50) DEFAULT 'October 2026',
                        billing_month VARCHAR(10) DEFAULT '2026-10',
                        due_date VARCHAR(30) DEFAULT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                `;
                connection.query(createFeesTableSql, (fErr) => {
                    if (fErr) console.error("Error creating fees table:", fErr.message);
                    else console.log("✓ fees table ready.");

                    // 5. Create complaints table
                    const createComplaintsTableSql = `
                        CREATE TABLE IF NOT EXISTS complaints (
                            complaint_id INT AUTO_INCREMENT PRIMARY KEY,
                            student_id INT DEFAULT NULL,
                            student_name VARCHAR(100) DEFAULT '',
                            room_no VARCHAR(50) DEFAULT '',
                            complaint_text TEXT,
                            status VARCHAR(50) DEFAULT 'Pending',
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    `;
                    connection.query(createComplaintsTableSql, (cErr) => {
                        if (cErr) console.error("Error creating complaints table:", cErr.message);
                        else console.log("✓ complaints table ready.");

                        // 6. Create vacating_notices table
                        const createNoticeTableSql = `
                            CREATE TABLE IF NOT EXISTS vacating_notices (
                                notice_id INT AUTO_INCREMENT PRIMARY KEY,
                                resident_id INT,
                                resident_name VARCHAR(100),
                                room_no VARCHAR(50),
                                resident_type VARCHAR(50) DEFAULT 'Jobholder',
                                reason VARCHAR(100) DEFAULT 'Job Transfer',
                                notice_date VARCHAR(30),
                                expected_vacate_date VARCHAR(30),
                                notes TEXT,
                                status VARCHAR(50) DEFAULT 'Pending Review',
                                deposit_refund_amount DECIMAL(10,2) DEFAULT 0,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                            )
                        `;
                        connection.query(createNoticeTableSql, (vErr) => {
                            if (vErr) console.error("Error creating vacating_notices table:", vErr.message);
                            else console.log("✓ vacating_notices table ready.");

                            // 7. Create payments table
                            const createPaymentsTableSql = `
                                CREATE TABLE IF NOT EXISTS payments (
                                    payment_id INT AUTO_INCREMENT PRIMARY KEY,
                                    user_id INT,
                                    student_name VARCHAR(100),
                                    amount DECIMAL(10,2) NOT NULL,
                                    payment_mode VARCHAR(50) DEFAULT 'UPI',
                                    upi_id VARCHAR(100),
                                    utr_number VARCHAR(100),
                                    status VARCHAR(50) DEFAULT 'Success',
                                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                )
                            `;
                            connection.query(createPaymentsTableSql, (payErr) => {
                                if (payErr) console.error("Error creating payments table:", payErr.message);
                                else console.log("✓ payments table ready.");

                                // 8. Create food_menu table
                                const createFoodMenuTableSql = `
                                    CREATE TABLE IF NOT EXISTS food_menu (
                                        menu_id INT AUTO_INCREMENT PRIMARY KEY,
                                        menu_date VARCHAR(20) NOT NULL UNIQUE,
                                        day_name VARCHAR(20) NOT NULL,
                                        breakfast_items TEXT,
                                        breakfast_special VARCHAR(255) DEFAULT '',
                                        breakfast_time VARCHAR(50) DEFAULT '7:30 AM - 10:00 AM',
                                        lunch_items TEXT,
                                        lunch_special VARCHAR(255) DEFAULT '',
                                        lunch_time VARCHAR(50) DEFAULT '12:30 PM - 3:00 PM',
                                        dinner_items TEXT,
                                        dinner_special VARCHAR(255) DEFAULT '',
                                        dinner_time VARCHAR(50) DEFAULT '7:30 PM - 10:00 PM',
                                        special_announcement TEXT,
                                        is_feast_day TINYINT(1) DEFAULT 0,
                                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                                    )
                                `;
                                connection.query(createFoodMenuTableSql, (foodErr) => {
                                    if (foodErr) console.error("Error creating food_menu table:", foodErr.message);
                                    else {
                                        console.log("✓ food_menu table ready.");
                                        seedInitialFoodMenu();
                                    }

                                    // 9. Create hostel_settings table
                                    const createSettingsTableSql = `
                                        CREATE TABLE IF NOT EXISTS hostel_settings (
                                            setting_id INT PRIMARY KEY,
                                            hostel_name VARCHAR(150) DEFAULT 'Executive PG & Private Hostel',
                                            hostel_tagline VARCHAR(200) DEFAULT 'Modern Living & Homely Accommodation',
                                            hostel_address TEXT,
                                            contact_phone VARCHAR(50) DEFAULT '9876543210',
                                            contact_email VARCHAR(100) DEFAULT 'info@hostelpg.com',
                                            warden_name VARCHAR(100) DEFAULT 'Chief Warden Desk',
                                            warden_phone VARCHAR(50) DEFAULT '9704844011',
                                            gate_closing_time VARCHAR(50) DEFAULT '10:30 PM',
                                            wifi_ssid VARCHAR(100) DEFAULT 'Hostel_HighSpeed_Fiber',
                                            wifi_password VARCHAR(100) DEFAULT 'HostelWifi@2026',
                                            hostel_upi_id VARCHAR(100) DEFAULT 'hostel.fees@okhdfcbank',
                                            hostel_upi_name VARCHAR(100) DEFAULT 'Hostel Management',
                                            hostel_upi_mobile VARCHAR(50) DEFAULT '9704844011',
                                            default_monthly_rent DECIMAL(10,2) DEFAULT 6500,
                                            default_security_deposit DECIMAL(10,2) DEFAULT 5000,
                                            notice_period_days INT DEFAULT 15,
                                            mess_morning_time VARCHAR(50) DEFAULT '7:30 AM - 10:00 AM',
                                            mess_lunch_time VARCHAR(50) DEFAULT '12:30 PM - 3:00 PM',
                                            mess_dinner_time VARCHAR(50) DEFAULT '7:30 PM - 10:00 PM',
                                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                                        )
                                    `;
                                    connection.query(createSettingsTableSql, (setErr) => {
                                        if (setErr) console.error("Error creating hostel_settings table:", setErr.message);
                                        else {
                                            console.log("✓ hostel_settings table ready.");
                                            const seedSettingSql = `
                                                INSERT IGNORE INTO hostel_settings
                                                (setting_id, hostel_name, hostel_address, contact_phone, warden_phone, hostel_upi_id, hostel_upi_mobile)
                                                VALUES
                                                (1, 'Executive PG & Private Hostel', 'Plot 42, Silicon Valley Colony, Madhapur, Hyderabad, TS - 500081', '9876543210', '9704844011', 'hostel.fees@okhdfcbank', '9704844011')
                                            `;
                                            connection.query(seedSettingSql, () => {});
                                        }

                                        // 10. Create reviews table
                                        const createReviewsTableSql = `
                                            CREATE TABLE IF NOT EXISTS reviews (
                                                review_id INT AUTO_INCREMENT PRIMARY KEY,
                                                user_id INT,
                                                student_name VARCHAR(100),
                                                room_no VARCHAR(50),
                                                resident_type VARCHAR(50) DEFAULT 'Resident',
                                                rating INT NOT NULL,
                                                category VARCHAR(50) DEFAULT 'Overall Stay',
                                                title VARCHAR(150),
                                                comment TEXT,
                                                status VARCHAR(50) DEFAULT 'Published',
                                                admin_reply TEXT DEFAULT NULL,
                                                admin_replied_at DATETIME DEFAULT NULL,
                                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                            )
                                        `;
                                        connection.query(createReviewsTableSql, (rErr) => {
                                            if (rErr) console.error("Error creating reviews table:", rErr.message);
                                            else console.log("✓ reviews table ready.");

                                            // 11. Seed default admin user
                                            connection.query("SELECT user_id FROM users WHERE role = 'admin' LIMIT 1", async (adminCheckErr, adminRows) => {
                                                if (!adminCheckErr && (!adminRows || adminRows.length === 0)) {
                                                    try {
                                                        const hash = await bcrypt.hash("Admin@12345", 10);
                                                        connection.query(
                                                            "INSERT INTO users (name, email, phone, password, role) VALUES ('System Administrator', 'admin@hostel.com', '9876543210', ?, 'admin')",
                                                            [hash],
                                                            (insErr) => {
                                                                if (!insErr) console.log("✓ Default admin account ready: admin@hostel.com / Admin@12345");
                                                            }
                                                        );
                                                    } catch (bErr) {
                                                        console.warn("Could not hash default admin password:", bErr.message);
                                                    }
                                                }

                                                // Ensure owner email is always Admin
                                                connection.query("UPDATE users SET role = 'admin' WHERE LOWER(TRIM(email)) = 'pachikoruabhi2007@gmail.com'", () => {});
                                            });

                                            // 12. Seed default rooms if empty
                                            connection.query("SELECT COUNT(*) AS count FROM rooms", (rmCntErr, rmCntRows) => {
                                                if (!rmCntErr && rmCntRows && rmCntRows[0].count === 0) {
                                                    const sampleRooms = [
                                                        ['101', 'Single', 1, 0, 8500, 'AC'],
                                                        ['102', 'Double', 2, 0, 7500, 'AC'],
                                                        ['103', 'Triple', 3, 0, 6500, 'Non-AC'],
                                                        ['104', 'Triple', 3, 0, 6500, 'Non-AC'],
                                                        ['105', 'Four-Sharing', 4, 0, 5500, 'Non-AC'],
                                                        ['201', 'Single', 1, 0, 8500, 'AC'],
                                                        ['202', 'Double', 2, 0, 7500, 'AC'],
                                                        ['203', 'Triple', 3, 0, 6500, 'Non-AC'],
                                                        ['204', 'Triple', 3, 0, 6500, 'Non-AC'],
                                                        ['205', 'Four-Sharing', 4, 0, 5500, 'Non-AC']
                                                    ];
                                                    sampleRooms.forEach(([no, type, total, occ, rent, ac]) => {
                                                        connection.query(
                                                            "INSERT IGNORE INTO rooms (room_no, room_type, total_beds, occupied_beds, monthly_rent, ac_type) VALUES (?, ?, ?, ?, ?, ?)",
                                                            [no, type, total, occ, rent, ac],
                                                            () => {}
                                                        );
                                                    });
                                                    console.log("✓ Initial 10 rooms seeded successfully.");
                                                }
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

function cleanupOldUsers() {
    const keepEmail = "257r1a66p7@cmrtc.ac.in";
    console.log(`[Sanitizer] Cleaning database: Preserving admin accounts and ${keepEmail}...`);

    // 1. Delete non-whitelisted users
    const delUsersSql = "DELETE FROM users WHERE role != 'admin' AND LOWER(TRIM(email)) != LOWER(?)";
    connection.query(delUsersSql, [keepEmail], (err, uRes) => {
        if (!err && uRes && uRes.affectedRows > 0) {
            console.log(`✓ Deleted ${uRes.affectedRows} non-whitelisted user accounts.`);
        }

        // 2. Delete non-whitelisted students
        const delStudentsSql = "DELETE FROM students WHERE LOWER(TRIM(email)) != LOWER(?)";
        connection.query(delStudentsSql, [keepEmail], (sErr, sRes) => {
            if (!sErr && sRes && sRes.affectedRows > 0) {
                console.log(`✓ Deleted ${sRes.affectedRows} non-whitelisted student records.`);
            }

            // 3. Delete fees for deleted users
            const delFeesSql = `
                DELETE FROM fees 
                WHERE user_id NOT IN (SELECT user_id FROM users)
                   OR (user_id IS NULL AND LOWER(TRIM(student_name)) NOT IN (SELECT LOWER(TRIM(name)) FROM users))
            `;
            connection.query(delFeesSql, () => {
                // 4. Delete payments for deleted users
                const delPaySql = `
                    DELETE FROM payments 
                    WHERE user_id NOT IN (SELECT user_id FROM users)
                `;
                connection.query(delPaySql, () => {
                    // 5. Delete complaints for deleted users
                    connection.query("DELETE FROM complaints WHERE student_id NOT IN (SELECT user_id FROM users)", () => {});

                    // 6. Delete vacating notices for deleted users
                    connection.query("DELETE FROM vacating_notices WHERE resident_id NOT IN (SELECT user_id FROM users)", () => {});

                    // 7. Delete reviews for deleted users
                    connection.query("DELETE FROM reviews WHERE user_id NOT IN (SELECT user_id FROM users)", () => {});

                    // 8. Accurately recalculate room occupancy so only 257r1a66p7's room (if assigned) has occupied bed
                    connection.query(`
                        UPDATE rooms r
                        SET occupied_beds = (
                            SELECT COUNT(*) FROM students s WHERE s.room_no = r.room_no
                        )
                    `, (rErr) => {
                        if (!rErr) {
                            console.log("✓ Rooms occupancy reset to live resident count.");
                        }
                    });
                });
            });
        });
    });
}

function seedInitialFoodMenu() {
    connection.query("SELECT COUNT(*) AS cnt FROM food_menu", (err, res) => {
        if (!err && res && res[0].cnt === 0) {
            const today = new Date();
            const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
            
            const weeklySample = [
                {
                    dayOffset: 0,
                    dayName: "Sunday",
                    breakfast: "Ghee Masala Dosa, Hot Sambar, Allam Chutney, Filter Coffee",
                    bSpecial: "Crispy Medu Vada (2 pcs)",
                    lunch: "Hyderabadi Chicken Dum Biryani / Paneer Biryani, Mirchi Ka Salan, Raita, Gulab Jamun",
                    lSpecial: "Sunday Royal Feast: Biryani & Ice Cream",
                    dinner: "Butter Phulka (3 pcs), Kadai Paneer, Jeera Rice, Dal Tadka, Fruit Custard",
                    dSpecial: "Fruit Custard & Sweet Corn Soup",
                    announce: "🎉 Sunday Special Feast Day: Special Biryani Counter open till 3:30 PM!",
                    isFeast: 1
                },
                {
                    dayOffset: 1,
                    dayName: "Monday",
                    breakfast: "Steamed Idli (3 pcs), Vada, Coconut Chutney, Tomato Chutney, Tea/Coffee",
                    bSpecial: "Carrot Halwa / Kesari Bath",
                    lunch: "Steamed Sona Masoori Rice, Dal Palak, Aloo Gobi Fry, Tomato Rasam, Fresh Curd, Appalam",
                    lSpecial: "Special Aloo Gobi Dry Fry",
                    dinner: "Soft Chapatis, Mix Veg Kurma, Veg Pulao, Dal Fry, Buttermilk",
                    dSpecial: "Semiya Payasam (Kheer)",
                    announce: "Healthy Week Ahead: Fresh green leafy vegetables served daily.",
                    isFeast: 0
                },
                {
                    dayOffset: 2,
                    dayName: "Tuesday",
                    breakfast: "Puri Sabzi (3 puris) with Aloo Masala, Poha, Coconut Chutney, Tea/Coffee",
                    bSpecial: "Hot Sweet Jalebi",
                    lunch: "Steamed Rice, Gongura Pappu, Capsicum Besan Curry, Pepper Rasam, Curd, Papad",
                    lSpecial: "Authentic Gongura Pappu",
                    dinner: "Methi Phulka, Paneer Butter Masala, Ghee Rice, Dal Tadka, Cut Fruits",
                    dSpecial: "Rich Paneer Butter Masala",
                    announce: "Fresh seasonal fruits served with dinner.",
                    isFeast: 0
                },
                {
                    dayOffset: 3,
                    dayName: "Wednesday",
                    breakfast: "Mysore Masala Dosa, Upma, Sambhar, Ginger Chutney, Tea/Coffee",
                    bSpecial: "Mysore Bonda (4 pcs)",
                    lunch: "Steamed Rice, Dal Makhani, Chicken Curry / Shahi Paneer, Jeera Rice, Curd, Fryums",
                    lSpecial: "Non-Veg: Andhra Chicken Curry | Veg: Shahi Paneer",
                    dinner: "Tawa Paratha, Veg Korma, Steamed Rice, Sambar, Raita",
                    dSpecial: "Moong Dal Halwa",
                    announce: "Wednesday Mid-Week Special: Egg / Chicken curry available for dinner.",
                    isFeast: 1
                },
                {
                    dayOffset: 4,
                    dayName: "Thursday",
                    breakfast: "Semiya Upma, Medu Vada, Coconut Chutney, Sambar, Tea/Coffee",
                    bSpecial: "Sweet Sheera / Kesari",
                    lunch: "Steamed Rice, Drumstick Sambar, Bhindi Kurkuri (Okra Fry), Tomato Rasam, Curd",
                    lSpecial: "Crispy Bhindi Fry & Fresh Curd",
                    dinner: "Chapatis, Chana Masala, Veg Biryani, Onion Raita, Buttermilk",
                    dSpecial: "Chole Bhature special counter",
                    announce: "North-Indian Special Night for Thursday dinner.",
                    isFeast: 0
                },
                {
                    dayOffset: 5,
                    dayName: "Friday",
                    breakfast: "Set Dosa with Vadacurry / Coconut Chutney, Idli, Tea/Coffee",
                    bSpecial: "Punugulu with Peanut Chutney",
                    lunch: "Steamed Rice, Spinach Dal, Chicken Fry / Crispy Babycorn, Garlic Rasam, Curd, Papad",
                    lSpecial: "Friday Special: Chicken Fry & Paneer 65",
                    dinner: "Phulkas, Egg Curry / Malai Kofta, Peas Pulao, Dal Tadka",
                    dSpecial: "Rasgulla Sweet",
                    announce: "Weekend welcome menu with sweet treats.",
                    isFeast: 0
                },
                {
                    dayOffset: 6,
                    dayName: "Saturday",
                    breakfast: "Rava Dosa / Onion Uttapam, Coconut Chutney, Sambar, Tea/Coffee",
                    bSpecial: "Crispy Onion Pakoda",
                    lunch: "Bagara Rice, Dal Tadka, Meal Maker / Soya Chunks Curry, Mirchi Bhajji, Curd",
                    lSpecial: "Telangana Bagara Rice & Dal",
                    dinner: "Ghee Chapatis, Veg Manchurian Gravy, Fried Rice, Sweet Corn Soup",
                    dSpecial: "Indo-Chinese Fusion Night",
                    announce: "Saturday night Indo-Chinese dinner special!",
                    isFeast: 0
                }
            ];

            weeklySample.forEach((sample, i) => {
                const d = new Date(today);
                d.setDate(today.getDate() + i);
                const dateStr = d.toISOString().split("T")[0];
                const dayName = days[d.getDay()];

                const insertSql = `
                    INSERT INTO food_menu 
                    (menu_date, day_name, breakfast_items, breakfast_special, breakfast_time,
                     lunch_items, lunch_special, lunch_time,
                     dinner_items, dinner_special, dinner_time,
                     special_announcement, is_feast_day)
                    VALUES (?, ?, ?, ?, '7:30 AM - 10:00 AM', ?, ?, '12:30 PM - 3:00 PM', ?, ?, '7:30 PM - 10:00 PM', ?, ?)
                    ON DUPLICATE KEY UPDATE day_name = VALUES(day_name)
                `;

                connection.query(insertSql, [
                    dateStr,
                    dayName,
                    sample.breakfast,
                    sample.bSpecial,
                    sample.lunch,
                    sample.lSpecial,
                    sample.dinner,
                    sample.dSpecial,
                    sample.announce,
                    sample.isFeast
                ], () => {});
            });
            console.log("✓ Initial 7-day food menu seeded successfully.");
        }
    });
}

connection.getConnection((err, conn) => {
    if (err) {
        console.error("MySQL connection pool test failed:", err.message);
        return;
    }

    console.log("MySQL connected successfully via Connection Pool!");
    conn.release();
    initSchema();
});

connection.on("error", (err) => {
    console.error("MySQL socket error:", err.message);
    if (err.code === "PROTOCOL_CONNECTION_LOST" || err.code === "ECONNRESET") {
        console.warn("MySQL connection reset or lost. Reconnecting is handled gracefully.");
    }
});

module.exports = connection;