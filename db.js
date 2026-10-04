const mysql = require("mysql2");
const fs = require("fs");
const path = require("path");

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

const connection = mysql.createConnection(dbConfig);

function initSchema() {
    // 0. Clean up test data: Retain only admin and 257r1a66p7@cmrtc.ac.in
    cleanupOldUsers();

    // 1. Upgrade students table for private hostel & PG residents (jobholders, transfer employees, students)
    connection.query("SHOW TABLES LIKE 'students'", (err, tables) => {
        if (err || !tables || tables.length === 0) return;

        connection.query("SHOW COLUMNS FROM students", (colErr, cols) => {
            if (colErr || !cols) return;
            const existing = cols.map(c => c.Field.toLowerCase());

            const columnsToAdd = [
                { name: "resident_type", def: "VARCHAR(50) DEFAULT 'Jobholder'" },
                { name: "company_or_college", def: "VARCHAR(150) DEFAULT NULL" },
                { name: "designation_or_course", def: "VARCHAR(100) DEFAULT NULL" },
                { name: "office_address", def: "VARCHAR(255) DEFAULT NULL" },
                { name: "id_proof_type", def: "VARCHAR(50) DEFAULT 'Aadhaar Card'" },
                { name: "id_proof_number", def: "VARCHAR(100) DEFAULT NULL" },
                { name: "native_city", def: "VARCHAR(100) DEFAULT NULL" },
                { name: "stay_type", def: "VARCHAR(50) DEFAULT 'Monthly Stay'" },
                { name: "check_in_date", def: "VARCHAR(30) DEFAULT NULL" },
                { name: "expected_checkout_date", def: "VARCHAR(30) DEFAULT NULL" },
                { name: "monthly_rent", def: "DECIMAL(10,2) DEFAULT 0" },
                { name: "security_deposit", def: "DECIMAL(10,2) DEFAULT 0" },
                { name: "food_plan", def: "VARCHAR(50) DEFAULT 'With Food'" },
                { name: "emergency_name", def: "VARCHAR(100) DEFAULT NULL" },
                { name: "emergency_phone", def: "VARCHAR(30) DEFAULT NULL" },
                { name: "dietary_preference", def: "VARCHAR(50) DEFAULT 'Pure Veg'" },
                { name: "profile_photo", def: "VARCHAR(255) DEFAULT NULL" },
                { name: "id_proof_file", def: "VARCHAR(255) DEFAULT NULL" },
                { name: "id_proof_filename", def: "VARCHAR(255) DEFAULT NULL" },
                { name: "id_proof_status", def: "VARCHAR(50) DEFAULT 'Pending Verification'" },
                { name: "id_proof_rejection_reason", def: "TEXT DEFAULT NULL" }
            ];

            columnsToAdd.forEach(col => {
                if (!existing.includes(col.name.toLowerCase())) {
                    connection.query(`ALTER TABLE students ADD COLUMN ${col.name} ${col.def}`, (alterErr) => {
                        if (alterErr) console.warn(`Could not add column ${col.name}:`, alterErr.message);
                        else console.log(`✓ Added column ${col.name} to students table.`);
                    });
                }
            });
        });
    });

    // 1b. Upgrade users table with profile_photo
    connection.query("SHOW COLUMNS FROM users", (uColErr, uCols) => {
        if (!uColErr && uCols) {
            const uExisting = uCols.map(c => c.Field.toLowerCase());
            if (!uExisting.includes("profile_photo")) {
                connection.query("ALTER TABLE users ADD COLUMN profile_photo VARCHAR(255) DEFAULT NULL", () => {
                    console.log("✓ Added profile_photo to users table.");
                });
            }
        }
    });

    // 2. Upgrade rooms table with monthly rent and AC specification
    connection.query("SHOW TABLES LIKE 'rooms'", (err, tables) => {
        if (err || !tables || tables.length === 0) return;
        connection.query("SHOW COLUMNS FROM rooms", (colErr, cols) => {
            if (colErr || !cols) return;
            const existing = cols.map(c => c.Field.toLowerCase());
            if (!existing.includes("monthly_rent")) {
                connection.query("ALTER TABLE rooms ADD COLUMN monthly_rent DECIMAL(10,2) DEFAULT 6500", () => {});
            }
            if (!existing.includes("ac_type")) {
                connection.query("ALTER TABLE rooms ADD COLUMN ac_type VARCHAR(20) DEFAULT 'Non-AC'", () => {});
            }
        });
    });

    // 3. Create vacating_notices table for transfer employees & vacating residents
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
    connection.query(createNoticeTableSql, (err) => {
        if (err) console.error("Error creating vacating_notices table:", err.message);
        else console.log("✓ vacating_notices table ready.");

        connection.query(
            "DELETE FROM users WHERE email IN ('resident.rahul@gmail.com', 'admin.hostel@gmail.com')",
            () => {}
        );

        // 4. Create payments table for UPI & fee transactions
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

            // 5. Enforce UNIQUE email on users table to guarantee no email can be registered twice
            connection.query("SHOW INDEX FROM users WHERE Column_name = 'email'", (idxErr, idxResults) => {
                if (!idxErr && (!idxResults || idxResults.length === 0)) {
                    connection.query("ALTER TABLE users ADD UNIQUE KEY unique_user_email (email)", (addIdxErr) => {
                        if (!addIdxErr) console.log("✓ Enforced UNIQUE email constraint on users table.");
                    });
                }
            });

            // 5b. Upgrade fees table for monthly stay records & advance tracking
            connection.query("SHOW TABLES LIKE 'fees'", (feeTableErr, feeTables) => {
                if (!feeTableErr && feeTables && feeTables.length > 0) {
                    connection.query("SHOW COLUMNS FROM fees", (colErr, cols) => {
                        if (!colErr && cols) {
                            const existing = cols.map(c => c.Field.toLowerCase());
                            const feeCols = [
                                { name: "month_name", def: "VARCHAR(50) DEFAULT 'October 2026'" },
                                { name: "billing_month", def: "VARCHAR(10) DEFAULT '2026-10'" },
                                { name: "due_date", def: "VARCHAR(30) DEFAULT NULL" },
                                { name: "fee_type", def: "VARCHAR(50) DEFAULT 'Monthly Stay Fee'" }
                            ];
                            feeCols.forEach(col => {
                                if (!existing.includes(col.name.toLowerCase())) {
                                    connection.query(`ALTER TABLE fees ADD COLUMN ${col.name} ${col.def}`, () => {
                                        console.log(`✓ Added column ${col.name} to fees table.`);
                                    });
                                }
                            });
                        }
                    });
                }
            });

            // 6. Create food_menu table for day-to-day mess menu management
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
            });

            // 7. Create hostel_settings table for system configurations
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
            });

            // 8. Create reviews table for resident ratings and reviews
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

connection.connect((err) => {
    if (err) {
        console.log("MySQL connection failed:", err.message);
        return;
    }

    console.log("MySQL connected successfully!");
    initSchema();
});

module.exports = connection;