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

/* LOGIN REQUIRED + NO BROWSER CACHE
   - every page under /pages (except /pages/Account, the login area) needs a session,
     otherwise the visitor is sent to the login page
   - pages and API answers are sent with "no-store", so after logging out the browser's
     Back button cannot show a cached copy of a protected page (it asks the server,
     which redirects to the login page) */

const LOGIN_PAGE = "/pages/Account/login.html";

app.use(function (req, res, next) {
    let requested;

    try {
        requested = decodeURIComponent(req.path);
    } catch (e) {
        return res.status(400).send("Bad request");
    }

    requested = path.posix.normalize(requested.replace(/\\/g, "/")).toLowerCase();

    const isApi  = requested.startsWith("/api/");
    const isPage = requested.startsWith("/pages/") &&
                   !requested.startsWith("/pages/account/") &&
                   (requested.endsWith(".html") || requested.endsWith(".htm") || requested.endsWith("/"));

    // the login page itself must never come from the cache either
    const isLogin = requested === "/pages/account/login.html";

    if (isApi || isPage || isLogin) {
        res.set({
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0"
        });
    }

    if (isPage && !req.session.user) {
        return res.redirect(LOGIN_PAGE);
    }

    // already logged in: Back / typing the login URL goes straight to the dashboard
    if (isLogin && req.session.user) {
        return res.redirect("/pages/Dashboard/dashboard.html");
    }

    next();
});

/* ACCESS LEVEL
   Only System Administrators (ch_group_id 001) may use User Management.
   This guard MUST stay above express.static, otherwise the pages are served
   before it can run. */

const ADMIN_GROUP_ID = "001";

app.use(function (req, res, next) {
    let requested;

    try {
        requested = decodeURIComponent(req.path);
    } catch (e) {
        return res.status(400).send("Bad request");
    }

    // decoded + normalised, so /pages/admin, /pages/%41dmin and /pages/x/../Admin all match
    requested = path.posix.normalize(requested.replace(/\\/g, "/")).toLowerCase();

    if (requested !== "/pages/admin" && !requested.startsWith("/pages/admin/")) {
        return next();
    }

    if (!req.session.user) {
        return res.redirect("/pages/Account/login.html");
    }

    if (req.session.user.groupId !== ADMIN_GROUP_ID) {
        return res.redirect("/pages/Dashboard/dashboard.html");
    }

    next();
});

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

        // drop whatever the browser cached for this site
        res.set("Clear-Site-Data", '"cache"');

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

function requireAdmin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({
            success: false,
            message: "Unauthorized."
        });
    }

    if (req.session.user.groupId !== ADMIN_GROUP_ID) {
        return res.status(403).json({
            success: false,
            message: "Only System Administrators can do this."
        });
    }

    next();
}

/* SUBSIDIARY ACCESS
   System Administrators (001) and Managers (002) see every subsidiary.
   Everyone else (003, 004 ...) only sees the mf_project rows that match their
   own branches in mf_system_access (ch_co_id + ch_branch_id, one row per branch).
   No row = no subsidiary.
   Read from the database on every request, so a change applies immediately. */

const ALL_SUBSIDIARY_GROUPS = ["001", "002"];

async function getAccess(req) {
    const userId = req.session.user.userId;

    // role comes from mf_system_user
    const u = await pool.query(`
        SELECT TRIM(ch_group_id) AS group_id
        FROM "LMS_PORTAL"."mf_system_user"
        WHERE ch_co_id = '01'
          AND TRIM(ch_user_id) = $1
        LIMIT 1
    `, [userId]);

    if (u.rows.length === 0) {
        return { all: false, projects: [] };
    }

    if (ALL_SUBSIDIARY_GROUPS.includes(u.rows[0].group_id)) {
        return { all: true, projects: [] };
    }

    // a user can have several rows in mf_system_access (one per branch)
    const projects = await pool.query(`
        SELECT DISTINCT
            TRIM(p.ch_proj_code)  AS id,
            TRIM(p.vc_proj_name)  AS name
        FROM "LMS_PORTAL"."mf_system_access" a
        JOIN "LMS_PORTAL"."mf_project" p
          ON TRIM(p.ch_co_id) = TRIM(a.ch_co_id)
         AND TRIM(p.ch_branch_id) = TRIM(a.ch_branch_id)
        WHERE LOWER(TRIM(a.ch_user_id)) = LOWER($1)
          AND p.bt_isactive IS DISTINCT FROM FALSE
        ORDER BY 2
    `, [userId]);

    return { all: false, projects: projects.rows };
}

// Tells the pages whether they may show "All Subsidiary" in their dropdowns.
// Users who see every subsidiary, or who have more than one, get "All Subsidiary"
// as the default option ("all" then means all of THEIR subsidiaries).
function setAccessHeader(res, access) {
    const showAll = access.all || access.projects.length > 1;
    res.setHeader("X-All-Subsidiary", showAll ? "1" : "0");
}

// Which project codes to query for the subsidiary the page asked for.
//   [null]          -> everything (only for users who can see all)
//   ["BCT", ...]    -> those projects
//   denied = true   -> they asked for a subsidiary they may not see
async function projectScope(req, buildingId) {
    const access = await getAccess(req);
    const wanted = buildingId && buildingId !== "all" ? buildingId : null;

    if (access.all) {
        return { access, codes: [wanted], denied: false };
    }

    const allowed = access.projects.map(p => p.id);

    if (wanted === null) {
        return { access, codes: allowed, denied: false };
    }

    if (allowed.includes(wanted)) {
        return { access, codes: [wanted], denied: false };
    }

    return { access, codes: [], denied: true };
}

// Runs a "get_xxx" function once per project code and joins the JSON arrays.
async function collectRows(codes, runner) {
    let rows = [];

    for (const code of codes) {
        rows = rows.concat(await runner(code));
    }

    return rows;
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

app.get("/api/system-groups", requireAdmin, async function (req, res) {
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

app.get("/api/entities", requireAdmin, async function (req, res) {
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

app.get("/api/users", requireAdmin, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_system_users();
        `);

        // only users that have portal access (bt_portal_access = 1)
        const portal = await pool.query(`
            SELECT DISTINCT LOWER(TRIM(ch_user_id)) AS id
            FROM "LMS_PORTAL"."mf_system_user"
            WHERE ch_co_id = '01'
              AND bt_portal_access = TRUE
        `);
        const portalIds = new Set(portal.rows.map(r => r.id));

        // one row per branch in mf_system_user -> list each user once
        const seen = new Set();
        const users = (result.rows[0].get_system_users || []).filter(function (u) {
            const key = String(u.userId ?? u.ch_user_id ?? u.id ?? "").trim();
            if (!key) return true;
            if (!portalIds.has(key.toLowerCase())) return false;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        res.json(users);

    } catch (error) {
        console.error("GET USERS ERROR:", error);

        res.status(500).json({
            message: "Failed to load users",
            error: error.message
        });
    }
});

/* BRANCH ACCESS (mf_system_access) -- one row per user per branch.
   Values travel as "coId:branchId" (the mf_project key of a subsidiary). */

async function saveBranchAccess(userId, oldUserId, entityId, branchesRaw) {
    let list;

    try {
        list = JSON.parse(branchesRaw);
    } catch (e) {
        throw new Error("Invalid branch access list.");
    }

    if (!Array.isArray(list)) {
        throw new Error("Invalid branch access list.");
    }

    const wanted = [...new Set(list.map(String))].map(function (v) {
        const [co, branch] = v.split(":");
        return { co: (co || "").trim(), branch: (branch || "").trim() };
    }).filter(x => x.co && x.branch);

    // only real subsidiaries
    const valid = wanted.length === 0 ? { rows: [] } : await pool.query(`
        SELECT DISTINCT TRIM(p.ch_co_id) AS co, TRIM(p.ch_branch_id) AS branch
        FROM "LMS_PORTAL"."mf_project" p
        JOIN json_to_recordset($1::json) AS w(co text, branch text)
          ON TRIM(p.ch_co_id) = w.co AND TRIM(p.ch_branch_id) = w.branch
    `, [JSON.stringify(wanted)]);

    let entity = entityId || null;

    if (!entity) {
        const e = await pool.query(`
            SELECT TRIM(ch_entity_id) AS ch_entity_id
            FROM "LMS_PORTAL"."mf_system_user"
            WHERE ch_co_id = '01' AND TRIM(ch_user_id) = $1
            LIMIT 1
        `, [userId]);
        entity = e.rows.length ? e.rows[0].ch_entity_id : null;
    }

    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        await client.query(`
            DELETE FROM "LMS_PORTAL"."mf_system_access"
            WHERE LOWER(TRIM(ch_user_id)) = LOWER($1)
               OR LOWER(TRIM(ch_user_id)) = LOWER($2)
        `, [userId, oldUserId || userId]);

        for (const v of valid.rows) {
            await client.query(`
                INSERT INTO "LMS_PORTAL"."mf_system_access"
                    (ch_co_id, ch_user_id, ch_branch_id, ch_entity_id)
                VALUES ($1, $2, $3, $4)
            `, [v.co, userId, v.branch, entity]);
        }

        await client.query("COMMIT");

    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}

// a user that is limited by branch must keep at least one subsidiary
function emptyBranchList(branchesRaw) {
    if (branchesRaw === undefined) return false;

    try {
        const list = JSON.parse(branchesRaw);
        return !Array.isArray(list) || list.length === 0;
    } catch (e) {
        return true;
    }
}

const BRANCH_REQUIRED_MESSAGE = "Select at least one subsidiary under Branch Access.";

async function renameBranchAccess(oldUserId, newUserId) {
    if (oldUserId.toLowerCase() === newUserId.toLowerCase()) return;

    await pool.query(`
        UPDATE "LMS_PORTAL"."mf_system_access"
        SET ch_user_id = $2
        WHERE LOWER(TRIM(ch_user_id)) = LOWER($1)
    `, [oldUserId, newUserId]);
}

// all subsidiaries, for the Branch Access checkboxes (admin pages)
app.get("/api/branch-options", requireAdmin, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT
                TRIM(ch_co_id)      AS co_id,
                TRIM(ch_branch_id)  AS branch_id,
                TRIM(ch_proj_code)  AS id,
                TRIM(vc_proj_name)  AS name
            FROM "LMS_PORTAL"."mf_project"
            WHERE bt_isactive IS DISTINCT FROM FALSE
            ORDER BY vc_proj_name
        `);

        res.json(result.rows);

    } catch (error) {
        console.error("GET BRANCH OPTIONS ERROR:", error);
        res.status(500).json({ message: "Failed to load subsidiaries" });
    }
});

// branches a user currently has in mf_system_access.
// ?withUserBranch=1 (Add User page) also includes the ch_branch_id the user
// already has on mf_system_user, so they come pre-checked when the user is created.
app.get("/api/users/:userId/branches", requireAdmin, async function (req, res) {
    try {
        const userId = req.params.userId.trim();
        const withUser = req.query.withUserBranch === "1";

        const result = await pool.query(`
            SELECT TRIM(ch_co_id) || ':' || TRIM(ch_branch_id) AS value
            FROM "LMS_PORTAL"."mf_system_access"
            WHERE LOWER(TRIM(ch_user_id)) = LOWER($1)

            UNION

            SELECT TRIM(ch_co_id) || ':' || TRIM(ch_branch_id)
            FROM "LMS_PORTAL"."mf_system_user"
            WHERE $2::boolean
              AND LOWER(TRIM(ch_user_id)) = LOWER($1)
              AND NULLIF(TRIM(ch_branch_id), '') IS NOT NULL
        `, [userId, withUser]);

        res.json(result.rows.map(r => r.value));

    } catch (error) {
        console.error("GET USER BRANCHES ERROR:", error);
        res.status(500).json({ message: "Failed to load branch access" });
    }
});

app.put("/api/users/:userId", requireAdmin, upload.single("profilePhoto"), async function (req, res) {
    try {
        const originalUserId = req.params.userId;

        if (emptyBranchList(req.body.branches)) {
            return res.status(400).json({ success: false, message: BRANCH_REQUIRED_MESSAGE });
        }

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

        // Branch Access: replace this user's mf_system_access rows
        // (page does not send it for roles that see every subsidiary)
        if (req.body.branches !== undefined) {
            await saveBranchAccess(userId.trim(), originalUserId.trim(), entityId, req.body.branches);
        } else {
            await renameBranchAccess(originalUserId.trim(), userId.trim());
        }

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
 
        // buildingId is mf_project.ch_proj_code (e.g. "BCT"), limited to the
        // subsidiaries this user may see.
        const scope = await projectScope(req, buildingId);
        const cat   = categoryId && categoryId !== "all" ? categoryId : null;

        if (scope.denied) {
            return res.status(403).json({ message: "No access to this subsidiary." });
        }

        res.json(await collectRows(scope.codes, async function (code) {
            const result = await pool.query(`
                SELECT "LMS_PORTAL".get_unit_inventory($1, $2);
            `, [code, cat]);

            return result.rows[0].get_unit_inventory || [];
        }));
 
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
        const access = await getAccess(req);
        setAccessHeader(res, access);

        if (!access.all) {
            return res.json(access.projects);
        }

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
 
//CONTRACT AGING
app.get("/api/contract-aging", requireAuth, async function (req, res) {
    try {
        const { buildingId } = req.query;
 
        const scope = await projectScope(req, buildingId);

        if (scope.denied) {
            return res.status(403).json({ message: "No access to this subsidiary." });
        }

        res.json(await collectRows(scope.codes, async function (code) {
            const result = await pool.query(`
                SELECT "LMS_PORTAL".get_contract_aging($1);
            `, [code]);

            return result.rows[0].get_contract_aging || [];
        }));
 
    } catch (error) {
        console.error("GET CONTRACT AGING ERROR:", error);
 
        res.status(500).json({
            message: "Failed to load contract aging",
            error: error.message
        });
    }
});

//FOR RENEWAL

app.get("/api/for-renewal", requireAuth, async function (req, res) {
    try {
        const { buildingId } = req.query;

        const scope = await projectScope(req, buildingId);

        if (scope.denied) {
            return res.status(403).json({ message: "No access to this subsidiary." });
        }

        res.json(await collectRows(scope.codes, async function (code) {
            const result = await pool.query(`
                SELECT "LMS_PORTAL".get_for_renewal($1);
            `, [code]);

            return result.rows[0].get_for_renewal || [];
        }));

    } catch (error) {
        console.error("GET FOR RENEWAL ERROR:", error);

        res.status(500).json({
            message: "Failed to load for renewal",
            error: error.message
        });
    }
});

//DASHBOARD
app.get("/api/dashboard", requireAuth, async function (req, res) {
    try {
        const access = await getAccess(req);
        setAccessHeader(res, access);

        const result = await pool.query(`SELECT "LMS_PORTAL".get_dashboard();`);
        let rows = result.rows[0].get_dashboard || [];

        if (!access.all) {
            const allowed = access.projects.map(p => p.id);
            rows = rows.filter(r => allowed.includes(r.id));
        }

        res.json(rows);

    } catch (error) {
        console.error("GET DASHBOARD ERROR:", error);

        res.status(500).json({
            message: "Failed to load dashboard",
            error: error.message
        });
    }
});

//REPORTS
app.get("/api/report", requireAuth, async function (req, res) {
    try {
        const allowed = ["rent-roll", "occupancy", "contract-expiry", "vacancy-aging"];
        const { report, buildingId, categoryId, from, to } = req.query;

        if (!allowed.includes(report)) {
            return res.status(400).json({ message: "Unknown report" });
        }

        const isDate = v => typeof v === "string" && /^\d{4}-\d{2}-\d{2}$/.test(v);

        const scope = await projectScope(req, buildingId);

        if (scope.denied) {
            return res.status(403).json({ message: "No access to this subsidiary." });
        }

        res.json(await collectRows(scope.codes, async function (code) {
            const result = await pool.query(`
                SELECT "LMS_PORTAL".get_report($1, $2, $3, $4, $5);
            `, [
                report,
                code,
                categoryId && categoryId !== "all" ? categoryId : null,
                isDate(from) ? from : null,
                isDate(to) ? to : null
            ]);

            return result.rows[0].get_report || [];
        }));

    } catch (error) {
        console.error("GET REPORT ERROR:", error);

        res.status(500).json({
            message: "Failed to generate report",
            error: error.message
        });
    }
});

//ADD USER (portal access)
/* Lookup list: system users that do NOT have portal access yet */
app.get("/api/portal-candidates", requireAdmin, async function (req, res) {
    try {
        const result = await pool.query(`
            SELECT "LMS_PORTAL".get_portal_candidates();
        `);

        res.json(result.rows[0].get_portal_candidates || []);

    } catch (error) {
        console.error("GET PORTAL CANDIDATES ERROR:", error);

        res.status(500).json({
            message: "Failed to load system users",
            error: error.message
        });
    }
});

/* Create portal user.
      - the user already exists in mf_system_user (picked from the lookup):
        that row is updated (password, role, status ...) and bt_portal_access = 1
      - the user does not exist yet: a new row is inserted with bt_portal_access = 1
      - the user already has portal access: refused (409)                       */
app.post("/api/users", requireAdmin, upload.single("profilePhoto"), async function (req, res) {
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

        if (emptyBranchList(req.body.branches)) {
            return res.status(400).json({ success: false, message: BRANCH_REQUIRED_MESSAGE });
        }

        const cleanUserId = userId.trim();
        const hashedPassword = await bcrypt.hash(password, 12);
        const profilePhoto = req.file ? req.file.buffer : null;

        // 1) existing system user WITHOUT portal access -> upgrade that row
        const updated = await pool.query(`
            UPDATE "LMS_PORTAL"."mf_system_user"
            SET
                vc_user_name      = $2,
                ch_group_id       = $3,
                vc_user_password  = $4,
                ch_entity_id      = COALESCE($5, ch_entity_id),
                vc_email_address  = $6,
                vc_cellphone_no   = $7,
                bt_isactive       = $8,
                bt_activated      = TRUE,
                vc_profile_photo  = COALESCE($9, vc_profile_photo),
                bt_portal_access  = TRUE
            WHERE ch_co_id = '01'
              AND TRIM(ch_user_id) = $1
              AND bt_portal_access = FALSE
        `, [
            cleanUserId,
            userName,
            groupId,
            hashedPassword,
            entityId || null,
            emailAddress || null,
            cellphoneNo || null,
            isActive === "true",
            profilePhoto
        ]);

        if (updated.rowCount > 0) {
            if (req.body.branches !== undefined) {
                await saveBranchAccess(cleanUserId, cleanUserId, entityId, req.body.branches);
            }

            return res.json({
                success: true,
                message: "User created successfully."
            });
        }

        // 2) already a portal user?
        const exists = await pool.query(`
            SELECT 1
            FROM "LMS_PORTAL"."mf_system_user"
            WHERE ch_co_id = '01'
              AND TRIM(ch_user_id) = $1
        `, [cleanUserId]);

        if (exists.rowCount > 0) {
            return res.status(409).json({
                success: false,
                message: "User ID already exists."
            });
        }

        // 3) brand-new user -> insert
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
                sd_date_lastlogin,
                bt_portal_access
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULL, TRUE
            )
        `, [
            "01",
            cleanUserId,
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

        if (req.body.branches !== undefined) {
            await saveBranchAccess(cleanUserId, cleanUserId, entityId, req.body.branches);
        }

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

/* SERVER */

app.listen(3000, function () {
    console.log("LMS Portal API running at http://localhost:3000");
});