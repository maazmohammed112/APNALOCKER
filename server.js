if (process.env.NODE_ENV !== "production") {
    require("dotenv").config();
}

const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const passport = require("passport");
const initializePassport = require("./passport-config");
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const mongoose = require("mongoose");
const User = require("./models/User"); // Import User model
const path = require("path"); // Import path module

// Initialize Passport
initializePassport(
    passport,
    email => User.findOne({ email }),
    id => User.findById(id)
);

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/userauth", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
.then(() => console.log("MongoDB connected"))
.catch(err => console.error("MongoDB connection error:", err));

// Middleware
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

// Set EJS as view engine
app.set('view engine', 'ejs'); // Add this line
app.set('views', path.join(__dirname, 'views')); // Ensure views folder is recognized

// Logout route
app.post('/logout', (req, res) => {
    req.logout((err) => {
        if (err) {
            console.log(err);
            return next(err);
        }
        res.redirect('/login');
    });
});

// Routes

// Home route (after login)
app.get('/', checkAuthenticated, (req, res) => {
    res.render("index.ejs", { name: req.user.name });
});

// Login route (GET)
app.get('/login', checkNotAuthenticated, (req, res) => {
    const name = req.session.username || 'Guest';
    res.render("login.ejs", { name: name, error: null }); // Add error handling to template
});

// Login route (POST)
app.post('/login', checkNotAuthenticated, async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return res.render('login', { error: 'Email not registered' }); // Error if email not found
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.render('login', { error: 'Incorrect password' }); // Error if password doesn't match
    }

    // Use passport to authenticate
    req.login(user, (err) => {
        if (err) {
            return res.render('login', { error: 'Login failed' }); // Error if login fails
        }
        req.session.username = user.name;
        res.redirect('/');
    });
});

// Registration route (GET)
app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render("register.ejs", { error: null }); // Add error handling to template
});

// Registration route (POST)
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });

    if (existingUser) {
        return res.render('register', { error: 'Email already registered' }); // Error if email already exists
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            name,
            email,
            password: hashedPassword
        });
        await user.save(); // Save the new user to the database
        res.redirect("/login");
    } catch (e) {
        console.log(e);
        res.render('register', { error: 'Registration failed' }); // Error if registration fails
    }
});

// Logout route
app.delete("/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.session.username = undefined; // Clear username from session
        res.redirect("/login");
    });
});

// Authentication check middleware
function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

// Non-authenticated check middleware
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect("/");
    }
    next();
}

// Start server
app.listen(3001, () => {
    console.log("Server is running on port 3001");
});
