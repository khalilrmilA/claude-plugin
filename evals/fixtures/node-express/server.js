const express = require("express");
const { exec } = require("child_process");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const db = require("./db");

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

// Reflected XSS: user input written into an HTML response without escaping.
app.get("/greet", (req, res) => {
  const name = req.query.name;
  res.set("Content-Type", "text/html");
  res.send("<h1>Welcome " + name + "</h1>");
});

// NoSQL injection: request body used directly as a Mongo filter.
app.post("/login", (req, res) => {
  db.users.findOne({ user: req.body.user, pass: req.body.pass }, (e, u) => {
    res.json({ ok: !!u });
  });
});

// Command injection: user input concatenated into a shell command.
app.get("/dns", (req, res) => {
  exec("nslookup " + req.query.domain, (e, out) => res.send(out));
});

// Broken JWT: signature is not verified (decode instead of verify).
app.get("/me", (req, res) => {
  const token = req.headers.authorization || "";
  const claims = jwt.decode(token.replace("Bearer ", ""));
  res.json({ userId: claims && claims.sub });
});

// IDOR: any logged-in user can read any order by id; no ownership check.
app.get("/orders/:id", requireLogin, (req, res) => {
  db.orders.findById(req.params.id, (e, o) => res.json(o));
});

// Mass assignment + privilege escalation: whole body saved, including role.
app.post("/users", requireLogin, (req, res) => {
  db.users.create(req.body, (e, u) => res.json(u));
});

// Open redirect.
app.get("/out", (req, res) => res.redirect(req.query.url));

// Business logic: price and quantity taken from the client; quantity not
// validated, so a negative quantity yields a negative charge (refund).
app.post("/checkout", requireLogin, (req, res) => {
  const total = req.body.price * req.body.quantity;
  db.charges.create({ user: req.user.id, amount: total }, () =>
    res.json({ charged: total })
  );
});

function requireLogin(req, res, next) {
  if (!req.headers.authorization) return res.status(401).end();
  req.user = { id: 1 };
  next();
}

module.exports = app;
