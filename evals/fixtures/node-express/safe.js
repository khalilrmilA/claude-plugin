// Safe-but-suspicious code. A good reviewer reports NOTHING here.
const express = require("express");
const { execFile } = require("child_process");
const db = require("./db");

const router = express.Router();

// Parameterized query: value is bound, not concatenated into SQL.
router.get("/search", (req, res) => {
  db.query("SELECT id, name FROM products WHERE name = ?", [req.query.q], (e, rows) =>
    res.json(rows)
  );
});

// res.json escapes by default; this is not HTML injection.
router.get("/profile", (req, res) => {
  res.json({ name: req.query.name });
});

// Fixed command, argument array, no shell.
router.get("/version", (req, res) => {
  execFile("git", ["--version"], (e, out) => res.send(out));
});

// Redirect only to a fixed internal path, not to user input.
router.get("/home", (req, res) => res.redirect("/dashboard"));

module.exports = router;
