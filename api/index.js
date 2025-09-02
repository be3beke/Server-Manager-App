const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

// middleware for auth
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "missing token" });
  const token = h.split(" ")[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: "invalid token" });
  }
}

// routes
app.get("/", (req, res) => {
  res.send("API is running 🚀");
});

// login example
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const q = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  const user = q.rows[0];
  if (!user) return res.status(400).json({ error: "invalid credentials" });
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(400).json({ error: "invalid credentials" });
  const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
  res.json({ token, user: { id: user.id, email: user.email } });
});

// simple servers list
app.get("/api/servers", auth, async (req, res) => {
  const q = await pool.query("SELECT * FROM servers ORDER BY created_at DESC");
  res.json(q.rows);
});

io.on("connection", (socket) => {
  console.log("client connected", socket.id);
  socket.on("disconnect", () =>
    console.log("client disconnected", socket.id)
  );
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => console.log(`API listening on port ${PORT}`));
