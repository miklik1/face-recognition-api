const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const knex = require("knex");

const saltRounds = 10;

const db = knex({
  client: "pg",
  connection: {
    connectionStrin: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    host: process.env.DATABASE_HOST,
    port: 5432,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PW,
    database: process.env.DATABASE_DB,
  },
});

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Sign In Route
app.post("/signin", (req, res) => {
  console.log(req.body);
  const { email, password } = req.body;

  db.select("email", "hash")
    .from("login")
    .where("email", "=", email)
    .then((data) => {
      const isValid = bcrypt.compareSync(password, data[0].hash);
      if (isValid) {
        return db
          .select("*")
          .from("users")
          .where("email", "=", email)
          .then((user) => res.json(user[0]))
          .catch(() => res.status(400).json("Unable to get user"));
      } else {
        res.status(400).json("Wrong credentials");
      }
    })
    .catch(() => res.status(400).json("Wrong credentials"));
  console.log(res.body);
});

// Register Route
app.post("/register", (req, res) => {
  console.log("Received request:", req.body);

  const { email, name, password } = req.body;
  const hash = bcrypt.hashSync(password, saltRounds);

  db.transaction((trx) => {
    trx
      .insert({
        hash: hash,
        email: email,
      })
      .into("login")
      .returning("email")
      .then((loginEmail) => {
        return trx("users")
          .returning("*")
          .insert({
            email: loginEmail[0].email,
            name: name,
            joined: new Date(),
          })
          .then((user) => res.json(user[0]));
      })
      .then(trx.commit)
      .catch(trx.rollback);
  }).catch(() => res.status(400).json("Unable to register"));
});

// Profile Route
app.get("/profile/:id", (req, res) => {
  const { id } = req.params;

  db.select("*")
    .from("users")
    .where({ id })
    .then((user) => {
      if (user.length) {
        res.json(user[0]);
      } else {
        res.status(404).json("User not found");
      }
    })
    .catch(() => res.status(400).json("Error getting user"));
});

// Image Route
app.put("/image", (req, res) => {
  const { id } = req.body;

  db("users")
    .where("id", "=", id)
    .increment("entries", 1)
    .returning("entries")
    .then((entries) => res.json(entries[0].entries))
    .catch(() => res.status(400).json("Unable to get entries"));
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`App is running on port ${PORT}`);
});
