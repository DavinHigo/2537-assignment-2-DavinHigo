require("./utils.js");

const { MongoClient } = require('mongodb');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const Joi = require('joi');
const bcrypt = require('bcrypt');

const app = express();

require('dotenv').config();

app.set("view engine", "ejs");

const port = process.env.PORT || 3000;
const mongoUri = process.env.MONGO_URI;
const nodeSessionSecret = process.env.NODE_SESSION_SECRET;

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session && req.session.user) {
        // User is authenticated
        next();
    } else {
        // User is not authenticated, redirect to login page
        res.redirect('/login');
    }
}

function isAdmin(req, res, next) {
    const user = req.session && req.session.user;
    if (user && user.type === 'admin') {
        // User is an admin, proceed to the next middleware
        next();
    } else {
        // User is not authorized, respond with 403 Forbidden
        res.status(403).render('403', { user: null });
    }
}


async function connectToMongo() {
    const client = new MongoClient(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });

    try {
        await client.connect();
        console.log('Connected to MongoDB!');

        // Configure session middleware
        app.use(session({
            secret: nodeSessionSecret,
            resave: false,
            saveUninitialized: false,
            store: MongoStore.create({
                mongoUrl: mongoUri,
                crypto: {
                    secret: nodeSessionSecret,
                    algorithm: 'aes-256-cbc',
                    hash: {
                        algorithm: 'sha256',
                        iterations: 1000,
                    },
                },
            }),
            cookie: {
                maxAge: 1 * 60 * 60 * 1000 // Session expiration (1 hour)
            }
        }));

        // Middleware for body parsing and public folder
        app.use(express.urlencoded({ extended: false }));
        app.use(express.static(path.join(__dirname, 'public')));

        app.get('/', (req, res) => {
            // Pass user data to the template (if user is logged in)
            const user = req.session && req.session.user;
            res.render('index', { user });
        });

        // Generate a random number
        function getRandomInt(max) {
            return Math.floor(Math.random() * max);
        }

        app.get('/members', isAuthenticated, (req, res) => {
            // Create image path
            const num = getRandomInt(3);
            const img = `/${num + 1}.jpg`;
            const { username } = req.session.user;
            res.render('members', { img, username });
        });

        app.get('/logout', (req, res) => {
            // Destroy session
            req.session.destroy(err => {
                if (err) {
                    console.error('Error destroying session:', err);
                }
                res.redirect('/');
            });
        });

        app.get('/signup', (req, res) => {
            if (req.session && req.session.user) {
                res.redirect('/');
            }
            else {
                res.render('signup');
            }
        });

        app.post('/signup', async (req, res) => {
            // Validate input using Joi
            const schema = Joi.object({
                username: Joi.string().alphanum().min(3).max(30).required(),
                email: Joi.string().email().required(),
                password: Joi.string().min(6).required()
            });

            try {
                const { username, email, password } = await schema.validateAsync(req.body);

                // Hash the password using bcrypt
                const hashedPassword = await bcrypt.hash(password, 10);

                const usersCollection = client.db().collection('users');
                await usersCollection.insertOne({ username, email, password: hashedPassword, type: 'user' });

                req.session.user = { username, email, type: 'user' };
                res.redirect('/members');
            } catch (error) {
                console.error("Error registering user:", error);
                res.status(500).send('Failed to register user');
            }
        });

        app.get('/login', (req, res) => {
            if (req.session && req.session.user) {
                res.redirect('/');
            }
            else {
                res.render('login');
            }
        });

        app.post('/login', async (req, res) => {
            // Validate input using Joi
            const schema = Joi.object({
                email: Joi.string().email().required(),
                password: Joi.string().required()
            });

            try {
                const { email, password } = await schema.validateAsync(req.body);

                const usersCollection = client.db().collection('users');
                const user = await usersCollection.findOne({ email });

                if (!user || !(await bcrypt.compare(password, user.password))) {
                    return res.status(401).send('Invalid email/password. <br><a href="/login">Try again</a>');
                }

                req.session.user = { username: user.username, email: user.email, type: user.type };
                return res.redirect('/members');
            } catch (error) {
                console.error("Error logging in:", error);
                res.status(401).send('Invalid email/password. <br><a href="/login">Try again</a>');
            }
        });

        app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
            const user = req.user; // Assuming req.user contains the logged-in user object

            // Check if there's a logged-in user and if the user is an admin
            if (user && user.type === 'admin') {
                // Render admin page with user data
                res.render('admin', { user: user, users: userList });
            } else {
                // If user is not logged in or is not an admin, send 403 Forbidden status
                res.status(403).render('403', { user: null }); // Pass null user to template
            }
        });




        app.post('/admin/promote/:userName', async (req, res) => {
            try {
                const { userName } = req.params;
                const usersCollection = client.db().collection('users');

                // Update user type to 'admin' based on user name
                const result = await usersCollection.updateOne(
                    { username: userName },
                    { $set: { type: 'admin' } }
                );

                if (result.modifiedCount === 1) {
                    console.log(`User '${userName}' promoted to admin`);
                }

                res.redirect('/admin'); // Redirect back to the admin page
            } catch (error) {
                console.error('Error promoting user:', error);
                res.status(500).send('Internal Server Error');
            }
        });

        // Route to handle demoting a user to regular user
        app.post('/admin/demote/:userName', async (req, res) => {
            try {
                const { userName } = req.params;
                const usersCollection = client.db().collection('users');

                // Update user type to 'user' based on user name
                const result = await usersCollection.updateOne(
                    { username: userName },
                    { $set: { type: 'user' } }
                );

                if (result.modifiedCount === 1) {
                    console.log(`User '${userName}' demoted to user`);
                }

                res.redirect('/admin'); // Redirect back to the admin page
            } catch (error) {
                console.error('Error demoting user:', error);
                res.status(500).send('Internal Server Error');
            }
        });

        // Handle 404 Not Found
        app.get('*', (req, res) => {
            res.status(404).render('error'); // Render the 'error404.ejs' template
        });

        // Start the server
        app.listen(port, () => {
            console.log(`Server is running on port ${port}`);
        });

    } catch (err) {
        console.error("Connection error:", err);
        process.exit(1); // Exit with error if connection fails
    }
}

connectToMongo().catch(console.error);
