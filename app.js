require("dotenv").config();
const express = require("express");
const path = require("path");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2");

const app = express();
const PORT = process.env.PORT || 3000;

// Database Connection Pool
const db = mysql
  .createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "expense_manager_db",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  })
  .promise();

// Middleware
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "a-very-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // Set to true if using HTTPS
  })
);

// Authentication Middleware
function checkAuth(req, res, next) {
  if (req.session.userId) {
    next();
  } else {
    res.status(401).redirect("/login");
  }
}

// --- HTML Page Routes ---
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "views", "home.html"))
);
app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "views", "login.html"))
);
app.get("/register", (req, res) =>
  res.sendFile(path.join(__dirname, "views", "register.html"))
);
app.get("/dashboard", checkAuth, (req, res) =>
  res.sendFile(path.join(__dirname, "views", "dashboard.html"))
);
app.get("/expenses", checkAuth, (req, res) =>
  res.sendFile(path.join(__dirname, "views", "expenses.html"))
);

// --- API Routes ---

// User Authentication
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const avatar = `https://i.pravatar.cc/150?u=${email}`; // Dummy avatar
  await db.query(
    "INSERT INTO users (name, email, password, avatar_url) VALUES (?, ?, ?, ?)",
    [name, email, hashedPassword, avatar]
  );
  res.redirect("/login");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const [rows] = await db.query("SELECT * FROM users WHERE email = ?", [email]);
  if (rows.length > 0 && (await bcrypt.compare(password, rows[0].password))) {
    req.session.userId = rows[0].id;
    res.redirect("/dashboard");
  } else {
    res.send("Invalid credentials");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// Get User Info API
app.get("/api/user", checkAuth, async (req, res) => {
  const [rows] = await db.query(
    "SELECT id, name, email, avatar_url FROM users WHERE id = ?",
    [req.session.userId]
  );
  res.json(rows[0]);
});

// Categories API
app.get("/api/categories", checkAuth, async (req, res) => {
  const [categories] = await db.query(
    "SELECT * FROM categories WHERE user_id = ?",
    [req.session.userId]
  );
  res.json(categories);
});

app.post("/api/categories", checkAuth, async (req, res) => {
  const { name, budget } = req.body;
  await db.query(
    "INSERT INTO categories (user_id, name, budget) VALUES (?, ?, ?)",
    [req.session.userId, name, budget]
  );
  res.json({ message: "Category added" });
});

// Expenses API
app.get("/api/expenses", checkAuth, async (req, res) => {
  const query = `
        SELECT e.id, e.description, e.amount, e.expense_date, c.name as category_name 
        FROM expenses e JOIN categories c ON e.category_id = c.id 
        WHERE e.user_id = ? ORDER BY e.expense_date DESC
    `;
  const [expenses] = await db.query(query, [req.session.userId]);
  res.json(expenses);
});

app.post("/api/expenses", checkAuth, async (req, res) => {
  const { category_id, description, amount, expense_date } = req.body;
  await db.query(
    "INSERT INTO expenses (user_id, category_id, description, amount, expense_date) VALUES (?, ?, ?, ?, ?)",
    [req.session.userId, category_id, description, amount, expense_date]
  );
  res.json({ message: "Expense added" });
});
// API to get budget status
app.get('/api/budget-status', checkAuth, async (req, res) => {
    const query = `
        SELECT 
            c.id, 
            c.name, 
            c.budget, 
            IFNULL(SUM(e.amount), 0) AS total_spent
        FROM categories c
        LEFT JOIN expenses e ON c.id = e.category_id 
            AND e.user_id = ? 
            AND MONTH(e.expense_date) = MONTH(CURDATE()) 
            AND YEAR(e.expense_date) = YEAR(CURDATE())
        WHERE c.user_id = ?
        GROUP BY c.id, c.name, c.budget
        ORDER BY c.name;
    `;
    try {
        const [results] = await db.query(query, [req.session.userId, req.session.userId]);
        res.json(results);
    } catch (error) {
        console.error("Failed to get budget status:", error);
        res.status(500).json({ message: "Server error" });
    }
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);
