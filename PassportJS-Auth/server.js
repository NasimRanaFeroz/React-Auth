if (process.env.NODE_ENV !== "production") {
  require("dotenv").config();
}

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const passport = require("passport");
const flash = require("express-flash");
const session = require("express-session");
const mongoose = require("mongoose");
const port = 3000;

mongoose
  .connect(process.env.MONGODB_URI || port)
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((err) => {
    console.log("Error connecting to MongoDB:", err);
  });

const User = require("./models/user");

const initializePassport = require("./passport-config");
initializePassport(
  passport,
  (email) => User.findOne({ email }),
  (id) => User.findById(id)
);

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.S_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("index.ejs", { name: req.user.username });
  } else {
    res.redirect("/login");
  }
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/login");
  });
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  try {
    const existingUser = await User.findOne({ email: req.body.email });
    if (existingUser) {
      return res.redirect("/register");
    }

    const user = new User({
      username: req.body.name,
      email: req.body.email,
      password: req.body.password,
    });

    await user.save();
    res.redirect("/login");
  } catch (err) {
    console.log(err);
    res.redirect("/register");
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
