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

        //middle ware for bady parsing and public folder
        app.use(express.urlencoded({ extended: false }));
        app.use(express.static(path.join(__dirname, 'public')));

        app.get('/', (req, res) => {
            // Pass user data to the template (if user is logged in)
            const user = req.session && req.session.user;

            // Render the 'index' template with dynamic data
            res.render('index', { user });
        });


        //random number generator
        function getRandomInt(max) {
            return Math.floor(Math.random() * max);
        }

        //members area 
        app.get('/members', (req, res) => {
            //create img path
            let num = getRandomInt(3);
            let img = `/${num + 1}.jpg`;

            if (req.session && req.session.user) {


                const { username } = req.session.user;
                res.render('members', { img, username });
            } else {
                res.redirect('/');
            }
        });

        //logout
        app.get('/logout', (req, res) => {
            //destroy session
            req.session.destroy(err => {
                if (err) {
                    console.error('Error destroying session:', err);
                }
                res.redirect('/');
            });
        });

        // Route for rendering signup form
        app.get('/signup', (req, res) => {
            res.render('signup');
        });

        // signup form
        app.post('/signup', async (req, res) => {
            const { username, email, password } = req.body;

            // Validate input using Joi
            const schema = Joi.object({
                username: Joi.string().alphanum().min(3).max(30).required(),
                email: Joi.string().email().required(),
                password: Joi.string().min(6).required()
            });

            try {
                await schema.validateAsync({ username, email, password }); // Validates username, email, password
            } catch (error) {
                return res.status(401).send('All fields must be filled. <br><a href="/signup">Try again</a>');
            }

            // Hash the password using bcrypt
            const hashedPassword = await bcrypt.hash(password, 10); // Use salt rounds of 10

            const usersCollection = client.db().collection('users');
            try {
                // Save user with default type 'user'
                await usersCollection.insertOne({ username, email, password: hashedPassword, type: 'user' });
                req.session.user = { username, email, type: 'user' }; // Store user in session with type 'user'
                res.redirect('/members'); // Redirect to members area
            } catch (err) {
                console.error("Error registering user:", err);
                res.status(500).send('Failed to register user');
            }
        });

        // Route for rendering login form
        app.get('/login', (req, res) => {
            res.render('login');
        });


        app.post('/login', async (req, res) => {
            const { email, password } = req.body;

            // Validate input using Joi
            const schema = Joi.object({
                email: Joi.string().email().required(),
                password: Joi.string().required()
            });

            try {
                await schema.validateAsync({ email, password }); // Validates email and password
            } catch (error) {
                return res.status(401).send('Invalid email/password. <br><a href="/login">Try again</a>');
            }

            const usersCollection = client.db().collection('users');
            const user = await usersCollection.findOne({ email });

            if (!user) {
                console.log('User not found');
                return res.status(401).send('Invalid email/password. <br><a href="/login">Try again</a>');
            }

            // Compare hashed password with provided password using bcrypt
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (!passwordMatch) {
                console.log('Incorrect password');
                return res.status(401).send('Invalid email/password. <br><a href="/login">Try again</a>');
            }

            // If login is successful, store user in session with type 'user' and redirect
            req.session.user = { username: user.username, email: user.email, type: 'user' };
            return res.redirect('/members');
        });


        app.get('/admin', (req, res) => {
            res.render('admin');
        });

        // Route for handling 404 Not Found
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
