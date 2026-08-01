import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import Database from "better-sqlite3";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import multer from "multer";
import fs from "fs";
import { createRequire } from "module";

const require = createRequire(import.meta.url);
const pdf = require("pdf-parse");
import mammoth from "mammoth";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const uploadDir = "uploads/";
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
const upload = multer({ dest: uploadDir });
const db = new Database("vidyamitra.db");
db.exec("PRAGMA foreign_keys = ON;");
const JWT_SECRET = process.env.JWT_SECRET || "vidyamitra-secret-key";

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS resumes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    content TEXT,
    score INTEGER,
    analysis TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS quiz_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    domain TEXT,
    score INTEGER,
    total INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS interview_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    role TEXT,
    feedback TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS saved_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    company TEXT,
    location TEXT,
    salary TEXT,
    type TEXT,
    posted TEXT,
    url TEXT,
    source TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS job_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    keyword TEXT,
    location TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err: any, decoded: any) => {
      if (err) return res.sendStatus(403);
      
      // Verify user still exists in DB to prevent FK errors with stale tokens
      const user = db.prepare("SELECT id FROM users WHERE id = ?").get(decoded.id);
      if (!user) {
        return res.status(401).json({ error: "User no longer exists" });
      }
      
      req.user = decoded;
      next();
    });
  };

  // --- Auth Routes ---
  app.post("/api/auth/register", async (req, res) => {
    const { password, name } = req.body;
    const email = req.body.email?.trim().toLowerCase();
    const trimmedPassword = password?.trim();
    
    if (!email || !trimmedPassword || !name) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const hashedPassword = await bcrypt.hash(trimmedPassword, 10);
    try {
      const info = db.prepare("INSERT INTO users (email, password, name) VALUES (?, ?, ?)").run(email, hashedPassword, name);
      const userId = Number(info.lastInsertRowid);
      const token = jwt.sign({ id: userId, email }, JWT_SECRET);
      res.json({ token, user: { id: userId, email, name } });
    } catch (e) {
      res.status(400).json({ error: "Email already exists" });
    }
  });

  app.post("/api/auth/login", async (req, res) => {
    const { password } = req.body;
    const email = req.body.email?.trim().toLowerCase();
    const trimmedPassword = password?.trim();

    if (!email || !trimmedPassword) {
      return res.status(400).json({ error: "Missing email or password" });
    }

    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email) as any;
    if (!user || !(await bcrypt.compare(trimmedPassword, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const userId = Number(user.id);
    const token = jwt.sign({ id: userId, email: user.email }, JWT_SECRET);
    res.json({ token, user: { id: userId, email: user.email, name: user.name } });
  });

  // --- Data Services ---
  app.post("/api/resume/extract", authenticateToken, upload.single("resume"), async (req: any, res) => {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });

    try {
      const dataBuffer = fs.readFileSync(req.file.path);
      let text = "";

      if (req.file.mimetype === "application/pdf" || req.file.originalname.endsWith(".pdf")) {
        let pdfParser: any = pdf;
        if (typeof pdfParser !== 'function' && pdfParser && typeof pdfParser.default === 'function') {
          pdfParser = pdfParser.default;
        }
        if (typeof pdfParser !== 'function' && pdfParser && typeof pdfParser.pdf === 'function') {
          pdfParser = pdfParser.pdf;
        }
        if (typeof pdfParser !== 'function') {
          throw new Error("PDF parser is not a function.");
        }
        const pdfData = await pdfParser(dataBuffer);
        text = pdfData.text;
      } else if (
        req.file.mimetype === "application/vnd.openxmlformats-officedocument.wordprocessingml.document" ||
        req.file.originalname.endsWith(".docx")
      ) {
        const result = await mammoth.extractRawText({ buffer: dataBuffer });
        text = result.value;
      } else if (req.file.mimetype === "text/plain" || req.file.originalname.endsWith(".txt")) {
        text = dataBuffer.toString("utf8");
      } else {
        throw new Error("Unsupported file format.");
      }

      // Cleanup
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.json({ text });
    } catch (e: any) {
      if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
      res.status(500).json({ error: "Extraction failed", details: e.message });
    }
  });

  app.post("/api/resume/save", authenticateToken, async (req: any, res) => {
    const { text, analysis } = req.body;
    try {
      const userId = Number(req.user.id);
      const score = typeof analysis.score === 'number' ? analysis.score : 0;
      db.prepare("INSERT INTO resumes (user_id, content, score, analysis) VALUES (?, ?, ?, ?)").run(userId, text, score, JSON.stringify(analysis));
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: "Failed to save analysis" });
    }
  });

  app.post("/api/interview/save", authenticateToken, async (req: any, res) => {
    const { role, feedback } = req.body;
    try {
      const userId = Number(req.user.id);
      db.prepare("INSERT INTO interview_sessions (user_id, role, feedback) VALUES (?, ?, ?)").run(userId, role, JSON.stringify(feedback));
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: "Failed to save interview" });
    }
  });

  app.post("/api/quiz/submit", authenticateToken, async (req: any, res) => {
    const { domain, score, total } = req.body;
    try {
      const userId = Number(req.user.id);
      db.prepare("INSERT INTO quiz_results (user_id, domain, score, total) VALUES (?, ?, ?, ?)").run(userId, domain, score, total);
      res.json({ success: true });
    } catch (e: any) {
      console.error("Quiz submission error:", e);
      res.status(500).json({ error: "Failed to save quiz results", details: e.message });
    }
  });

  app.get("/api/dashboard/stats", authenticateToken, (req: any, res) => {
    const userId = Number(req.user.id);
    const resumes = db.prepare("SELECT * FROM resumes WHERE user_id = ? ORDER BY created_at DESC").all(userId);
    const quizzes = db.prepare("SELECT * FROM quiz_results WHERE user_id = ? ORDER BY created_at DESC").all(userId);
    const interviews = db.prepare("SELECT * FROM interview_sessions WHERE user_id = ? ORDER BY created_at DESC").all(userId);
    const savedJobs = db.prepare("SELECT * FROM saved_jobs WHERE user_id = ? ORDER BY created_at DESC").all(userId);
    const jobAlerts = db.prepare("SELECT * FROM job_alerts WHERE user_id = ? ORDER BY created_at DESC").all(userId);
    res.json({ resumes, quizzes, interviews, savedJobs, jobAlerts });
  });

  app.post("/api/jobs/save", authenticateToken, async (req: any, res) => {
    const { title, company, location, salary, type, posted, url, source } = req.body;
    try {
      const userId = Number(req.user.id);
      db.prepare(`
        INSERT INTO saved_jobs (user_id, title, company, location, salary, type, posted, url, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(userId, title, company, location, salary, type, posted, url, source);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: "Failed to save job" });
    }
  });

  app.get("/api/jobs/saved", authenticateToken, (req: any, res) => {
    try {
      const userId = Number(req.user.id);
      const jobs = db.prepare("SELECT * FROM saved_jobs WHERE user_id = ? ORDER BY created_at DESC").all(userId);
      res.json(jobs);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to fetch saved jobs" });
    }
  });

  app.delete("/api/jobs/saved/:id", authenticateToken, (req: any, res) => {
    try {
      const userId = Number(req.user.id);
      const jobId = req.params.id;
      db.prepare("DELETE FROM saved_jobs WHERE id = ? AND user_id = ?").run(jobId, userId);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: "Failed to delete saved job" });
    }
  });

  app.post("/api/jobs/alerts", authenticateToken, async (req: any, res) => {
    const { keyword, location } = req.body;
    try {
      const userId = Number(req.user.id);
      db.prepare("INSERT INTO job_alerts (user_id, keyword, location) VALUES (?, ?, ?)").run(userId, keyword, location);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: "Failed to create job alert" });
    }
  });

  app.get("/api/jobs/alerts", authenticateToken, (req: any, res) => {
    try {
      const userId = Number(req.user.id);
      const alerts = db.prepare("SELECT * FROM job_alerts WHERE user_id = ? ORDER BY created_at DESC").all(userId);
      res.json(alerts);
    } catch (e: any) {
      res.status(500).json({ error: "Failed to fetch job alerts" });
    }
  });

  app.delete("/api/jobs/alerts/:id", authenticateToken, (req: any, res) => {
    try {
      const userId = Number(req.user.id);
      const alertId = req.params.id;
      db.prepare("DELETE FROM job_alerts WHERE id = ? AND user_id = ?").run(alertId, userId);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: "Failed to delete job alert" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
