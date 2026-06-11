const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname));

app.use(session({
    secret: "stridentwalkssecret",
    resave: false,
    saveUninitialized: true
}));

// Load users
let users = JSON.parse(fs.readFileSync("users.json", "utf8"));


// ---------------------- LOGIN ----------------------
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (!user) {
        return res.send("<h1>Login failed</h1><p>User not found.</p>");
    }

    // Compare hashed password
    if (bcrypt.compareSync(password, user.password)) {
        req.session.user = user.username;
        return res.redirect("/dashboard.html");
    }

    return res.send("<h1>Login failed</h1><p>Incorrect password.</p>");
});


// ---------------------- REGISTER ----------------------
app.post("/register", (req, res) => {
    const { username, password, email } = req.body;

    // Check if username exists
    const exists = users.find(u => u.username === username);
    if (exists) {
        return res.send("<h1>Username already taken</h1>");
    }

    // Hash password
    const hashed = bcrypt.hashSync(password, 10);

    // Add new user
    const newUser = { username, password: hashed, email };
    users.push(newUser);

    // Save to file
    fs.writeFileSync("users.json", JSON.stringify(users, null, 2));

    res.send("<h1>Registration successful!</h1><p>You can now log in.</p>");
});


// ---------------------- WHOAMI ----------------------
app.get("/whoami", (req, res) => {
    res.json({ user: req.session.user || null });
});


// ---------------------- PROTECT DASHBOARD ----------------------
app.get("/dashboard.html", (req, res, next) => {
    if (!req.session.user) {
        return res.redirect("/login.html");
    }
    next();
});


// ---------------------- LOGOUT ----------------------
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/login.html");
    });
});


// ---------------------- START SERVER ----------------------
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
