const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const multer = require("multer");
const session = require("express-session");
const path = require("path");

const app = express();

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 2 * 1024 * 1024
    }
});

app.use(express.json());

app.use(session({
    secret: "lms_portal_secret_key_change_this",
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        maxAge: 1000 * 60 * 10
    }
}));

const frontendPath = path.join(
    __dirname,
    "..",
    "Seller's Portal",
    "HTML5Application",
    "public_html"
);

console.log("Frontend path:", frontendPath);

app.use(express.static(frontendPath));


const pool = new Pool({
    host: "localhost",
    port: 5432,
    database: "LMS_PORTAL",
    user: "postgres",
    password: "d@rnasour123"
});

/* AUTH */

app.post("/api/login", async function (req, res) {
    try {
        const { userId, password } = req.body;

        if (!userId || !password) {
            return res.status(400).json({
                success: false,
                message: "User ID and password are required."
            });
        }

        const result = await pool.query(`
            SELECT 
                ch_user_id,
                vc_user_name,
                ch_group_id,
                ch_entity_id,
                vc_email_address,
                bt_isactive,
                bt_activated,
                vc_user_password
            FROM "LMS_PORTAL"."mf_system_user"
            WHERE ch_co_id = '01'
              AND TRIM(ch_user_id) = $1
            LIMIT 1
        `, [userId.trim()]);

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: "Invalid User ID or password."
            });
        }

        const user = result.rows[0];

        if (!user.bt_isactive) {
            return res.status(403).json({
                success: false,
                message: "This user account is inactive."
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.vc_user_password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                success: false,
                message: "Invalid User ID or password."
            });
        }

        req.session.user = {
            userId: user.ch_user_id.trim(),
            userName: user.vc_user_name,
            entityId: user.ch_entity_id ? user.ch_entity_id.trim() : "",
            groupId: user.ch_group_id ? user.ch_group_id.trim() : "",
            email: user.vc_email_address || ""
        };

        await pool.query(`
            UPDATE "LMS_PORTAL"."mf_system_user"
            SET sd_date_lastlogin = NOW()
            WHERE ch_co_id = '01'
              AND TRIM(ch_user_id) = $1
        `, [userId.trim()]);

        res.json({
            success: true,
            message: "Login successful.",
            user: req.session.user
        });

    } catch (error) {
        console.error("LOGIN ERROR:", error);

        res.status(500).json({
            success: false,
            message: "Login failed.",
            error: error.message
        });
    }
});

app.get("/api/me", requireAuth, async function (req, res) {

    try {

        const result = await pool.query(`
            SELECT
                TRIM(su.ch_user_id)           AS ch_user_id,
                su.vc_user_name,
                TRIM(su.ch_group_id)          AS ch_group_id,
                TRIM(su.ch_entity_id)         AS ch_entity_id,
                su.vc_email_address,
                e.vc_first_name,
                e.vc_last_name,
                e.vc_org_name

            FROM "LMS_PORTAL"."mf_system_user" su

            LEFT JOIN "LMS_PORTAL"."mf_entity" e
                ON TRIM(e.ch_entity_id) = TRIM(su.ch_entity_id)

            WHERE su.ch_co_id = '01'
              AND TRIM(su.ch_user_id) = $1

            LIMIT 1
        `, [req.session.user.userId]);

        if (result.rows.length === 0) {
            return res.status(401).json({
                authenticated: false
            });
        }

        const user = result.rows[0];

        res.json({
            authenticated: true,
            user: {
                userId: user.ch_user_id,
                userName: user.vc_user_name,
                entityId: user.ch_entity_id,
                groupId: user.ch_group_id,
                email: user.vc_email_address,

                firstName: user.vc_first_name,
                lastName: user.vc_last_name,
                organizationName: user.vc_org_name
            }
        });

    } catch (error) {

        console.error("API /api/me ERROR:", error);

        res.status(500).json({
            authenticated: false,
            message: error.message
        });

    }

});

app.post("/api/logout", function (req, res) {
    req.session.destroy(function () {
        res.clearCookie("connect.sid");

        res.json({
            success: true
        });
    });
});

/* REUSABLE AUTH MIDDLEWARE */

function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized."
        });
    }

    next();
}

/* MASTER DATA */
app.get("/api/branches",requireAuth, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_branch_companies();
        `);

        res.json(result.rows[0].get_branch_companies || []);

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Failed to load branch companies",
            error: error.message
        });
    }
});

app.get("/api/unit-categories",requireAuth, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_unit_categories();
        `);

        res.json(result.rows[0].get_unit_categories || []);

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Failed to load unit categories",
            error: error.message
        });
    }
});

app.get("/api/system-groups",requireAuth, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_system_groups();
        `);

        res.json(result.rows[0].get_system_groups || []);

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Failed to load system groups",
            error: error.message
        });
    }
});

app.get("/api/entities",requireAuth, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_entities();
        `);

        res.json(result.rows[0].get_entities || []);

    } catch (error) {
        console.error(error);

        res.status(500).json({
            message: "Failed to load entities",
            error: error.message
        });
    }
});

/* USERS */

app.get("/api/users",requireAuth, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_system_users();
        `);

        res.json(result.rows[0].get_system_users || []);

    } catch (error) {
        console.error("GET USERS ERROR:", error);

        res.status(500).json({
            message: "Failed to load users",
            error: error.message
        });
    }
});

app.post("/api/users",requireAuth, upload.single("profilePhoto"), async function (req, res) {
    try {
        const {
            userId,
            userName,
            groupId,
            password,
            entityId,
            emailAddress,
            cellphoneNo,
            isActive
        } = req.body;

        if (!userId || !userName || !groupId || !password) {
            return res.status(400).json({
                success: false,
                message: "User ID, name, role, and password are required."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const profilePhoto = req.file ? req.file.buffer : null;

        await pool.query(`
            INSERT INTO "LMS_PORTAL"."mf_system_user" (
                ch_co_id,
                ch_user_id,
                vc_user_name,
                ch_group_id,
                vc_user_password,
                ch_entity_id,
                vc_email_address,
                vc_cellphone_no,
                bt_isactive,
                bt_activated,
                vc_profile_photo,
                sd_date_lastlogin
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL
            )
        `, [
            "01",
            userId,
            userName,
            groupId,
            hashedPassword,
            entityId || null,
            emailAddress || null,
            cellphoneNo || null,
            isActive === "true",
            true,
            profilePhoto
        ]);

        res.json({
            success: true,
            message: "User created successfully."
        });

    } catch (error) {
        console.error(error);

        if (error.code === "23505") {
            return res.status(409).json({
                success: false,
                message: "User ID already exists."
            });
        }

        res.status(500).json({
            success: false,
            message: "Failed to create user.",
            error: error.message
        });
    }
});

app.put("/api/users/:userId",requireAuth, upload.single("profilePhoto"), async function (req, res) {
    try {
        const originalUserId = req.params.userId;

        const {
            userId,
            userName,
            groupId,
            password,
            entityId,
            emailAddress,
            cellphoneNo,
            isActive
        } = req.body;

        let hashedPassword = null;

        if (password && password.trim() !== "") {
            hashedPassword = await bcrypt.hash(password, 12);
        }

        const profilePhoto = req.file ? req.file.buffer : null;

        await pool.query(`
            UPDATE "LMS_PORTAL"."mf_system_user"
            SET
                ch_user_id = $1,
                vc_user_name = $2,
                ch_group_id = $3,
                vc_user_password = COALESCE($4, vc_user_password),
                ch_entity_id = $5,
                vc_email_address = $6,
                vc_cellphone_no = $7,
                bt_isactive = $8,
                vc_profile_photo = COALESCE($9, vc_profile_photo)
            WHERE ch_co_id = '01'
              AND TRIM(ch_user_id) = $10
        `, [
            userId,
            userName,
            groupId,
            hashedPassword,
            entityId || null,
            emailAddress || null,
            cellphoneNo || null,
            isActive === "true",
            profilePhoto,
            originalUserId.trim()
        ]);

        res.json({
            success: true,
            message: "User updated successfully."
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            success: false,
            message: "Failed to update user.",
            error: error.message
        });
    }
});

app.get("/api/me/photo", requireAuth, async function (req, res) {
    try {
        const userId = req.session.user.userId;

        const result = await pool.query(`
            SELECT vc_profile_photo
            FROM "LMS_PORTAL"."mf_system_user"
            WHERE ch_co_id = '01'
              AND TRIM(ch_user_id) = $1
            LIMIT 1
        `, [userId]);

        if (
            result.rows.length === 0 ||
            !result.rows[0].vc_profile_photo
        ) {
            return res.status(404).send("No profile photo");
        }

        res.setHeader("Content-Type", "image/jpeg");
        res.send(result.rows[0].vc_profile_photo);

    } catch (error) {
        console.error("PROFILE PHOTO ERROR:", error);
        res.status(500).send("Failed to load profile photo");
    }
});

app.get("/api/users/:userId/photo", requireAuth, async function (req, res) {

    try {

        const userId = req.params.userId;

        const result = await pool.query(`
            SELECT vc_profile_photo
            FROM "LMS_PORTAL"."mf_system_user"
            WHERE ch_co_id = '01'
              AND TRIM(ch_user_id) = $1
        `, [userId]);

        if (
            result.rows.length === 0 ||
            !result.rows[0].vc_profile_photo
        ) {
            return res.status(404).send("No photo");
        }

        res.setHeader("Content-Type", "image/jpeg");
        res.send(result.rows[0].vc_profile_photo);

    } catch (error) {

        console.error(error);

        res.status(500).send("Unable to load photo");
    }

});

//UNIT INVENTORY
app.get("/api/units", requireAuth, async function (req, res) {
    try {
        const { buildingId, categoryId } = req.query;
 
        // buildingId is expected to be mf_unit.ch_proj_code (e.g. "BCT").
        // If /api/branches returns a different code, adjust here or in the SP.
        const proj = buildingId && buildingId !== "all" ? buildingId : null;
        const cat  = categoryId && categoryId !== "all" ? categoryId : null;
 
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_unit_inventory($1, $2);
        `, [proj, cat]);
 
        res.json(result.rows[0].get_unit_inventory || []);
 
    } catch (error) {
        console.error("GET UNITS ERROR:", error);
 
        res.status(500).json({
            message: "Failed to load unit inventory",
            error: error.message
        });
    }
});

//GET PROJECT
app.get("/api/projects", requireAuth, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_projects();
        `);
 
        res.json(result.rows[0].get_projects || []);
 
    } catch (error) {
        console.error("GET PROJECTS ERROR:", error);
 
        res.status(500).json({
            message: "Failed to load projects",
            error: error.message
        });
    }
});
 
app.get("/api/units", requireAuth, async function (req, res) {
    try {
        const { buildingId, categoryId } = req.query;

        // buildingId is mf_project.ch_proj_code (e.g. "BCT"), which
        // matches mf_unit.ch_proj_code directly -- see /api/projects.
        const proj = buildingId && buildingId !== "all" ? buildingId : null;
        const cat  = categoryId && categoryId !== "all" ? categoryId : null;

        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_unit_inventory($1, $2);
        `, [proj, cat]);

        res.json(result.rows[0].get_unit_inventory || []);

    } catch (error) {
        console.error("GET UNITS ERROR:", error);

        res.status(500).json({
            message: "Failed to load unit inventory",
            error: error.message
        });
    }
});

app.get("/api/contract-aging", requireAuth, async function (req, res) {
    try {
        const { buildingId } = req.query;
 
        // buildingId is mf_project.ch_proj_code (e.g. "BCT"), same as Unit Inventory
        const proj = buildingId && buildingId !== "all" ? buildingId : null;
 
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_contract_aging($1);
        `, [proj]);
 
        res.json(result.rows[0].get_contract_aging || []);
 
    } catch (error) {
        console.error("GET CONTRACT AGING ERROR:", error);
 
        res.status(500).json({
            message: "Failed to load contract aging",
            error: error.message
        });
    }
});

/* ADD TO server.js (next to /api/contract-aging), then restart the server. */

app.get("/api/for-renewal", requireAuth, async function (req, res) {
    try {
        const { buildingId } = req.query;
        const proj = buildingId && buildingId !== "all" ? buildingId : null;

        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_for_renewal($1);
        `, [proj]);

        res.json(result.rows[0].get_for_renewal || []);

    } catch (error) {
        console.error("GET FOR RENEWAL ERROR:", error);

        res.status(500).json({
            message: "Failed to load for renewal",
            error: error.message
        });
    }
});

/* ADD TO server.js (next to the other /api routes), then restart the server. */

app.get("/api/dashboard", requireAuth, async function (req, res) {
    try {
        const result = await pool.query(`SELECT "LMS_PORTAL".get_dashboard();`);

        res.json(result.rows[0].get_dashboard || []);

    } catch (error) {
        console.error("GET DASHBOARD ERROR:", error);

        res.status(500).json({
            message: "Failed to load dashboard",
            error: error.message
        });
    }
});

/* ADD TO server.js (next to the other /api routes), then restart the server. */

app.get("/api/report", requireAuth, async function (req, res) {
    try {
        const allowed = ["rent-roll", "occupancy", "contract-expiry", "vacancy-aging"];
        const { report, buildingId, categoryId, from, to } = req.query;

        if (!allowed.includes(report)) {
            return res.status(400).json({ message: "Unknown report" });
        }

        const isDate = v => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);

        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_report($1, $2, $3, $4, $5);
        `, [
            report,
            buildingId && buildingId !== "all" ? buildingId : null,
            categoryId && categoryId !== "all" ? categoryId : null,
            isDate(from) ? from : null,
            isDate(to) ? to : null
        ]);

        res.json(result.rows[0].get_report || []);

    } catch (error) {
        console.error("GET REPORT ERROR:", error);

        res.status(500).json({
            message: "Failed to generate report",
            error: error.message
        });
    }
});

/* SERVER */

app.listen(3000, function () {
    console.log("LMS Portal API running at http://localhost:3000");
});