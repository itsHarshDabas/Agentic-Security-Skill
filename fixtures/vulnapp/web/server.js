// Intentionally vulnerable Express app; see ../README.md.
const express = require("express");
const { exec } = require("child_process");
const path = require("path");
const _ = require("lodash");

const app = express();
app.use(express.json());

app.get("/greet", (req, res) => {
  res.send("<h1>Hi " + req.query.name + "</h1>"); // SEED:js-xss
});

app.get("/calc", (req, res) => {
  res.json({ result: eval(req.query.expr) }); // SEED:js-eval
});

app.get("/lookup", (req, res) => {
  exec("nslookup " + req.query.host, (err, out) => res.send(out)); // SEED:js-command-injection
});

app.get("/static", (req, res) => {
  res.sendFile(path.join(__dirname, "public", req.query.file)); // SEED:js-path-traversal
});

app.post("/merge", (req, res) => {
  res.json(_.merge({}, req.body)); // DECOY:lodash-merge
});

app.listen(3000);
