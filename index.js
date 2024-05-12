require("./utils.js");

const { MongoClient } = require('mongodb');
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const Joi = require('joi');
const bcrypt = require('bcrypt');

const app = express();

// Load environment variables from .env file
require('dotenv').config();

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

        // session authentication
        app.get('/', (req, res) => {
            if (req.session && req.session.user) {
                // User is logged in
                const { username } = req.session.user;
                res.send(`
      <p>Hello, ${username}!</p>
      <button onclick="window.location='/members'">Members Area</button>
      <button onclick="window.location='/logout'">Logout</button>
    `);
            } else {
                // User is not logged in
                res.send(`
      <button onclick="window.location='/signup'">Sign Up</button>
      <button onclick="window.location='/login'">Login</button>
    `);
            }
        });

        //random number generator
        function getRandomInt(max) {
            return Math.floor(Math.random() * max);
        }

        //members area 
        app.get('/members', (req, res) => {
            if (req.session && req.session.user) {

                //create img path
                let num = getRandomInt(3);
                let img = `/${num + 1}.jpg`;

                const { username } = req.session.user;
                res.send(`
      <h1>Hello, ${username}.</h1>
      <img src="${img}" alt="Random Image" style="max-width: 500px; max-height: 500px; width: auto; height: auto;">
      <br><button onclick="window.location='/logout'">Logout</button>
    `);
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
            res.send(`
                <h1>Sign Up</h1>
                <form action="/signup" method="POST">
                <input type="text" name="username" placeholder="Username"><br>
                <input type="email" name="email" placeholder="Email"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <button type="submit">Sign Up</button>
                </form>
            `);
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
                await schema.validateAsync({ username, email, password });
            } catch (error) {
                return res.status(401).send('All fields must be filled. <br><a href="/signup">Try again</a>');
            }

            // Hash the password using bcrypt
            const hashedPassword = await bcrypt.hash(password, 10); // Use salt rounds of 10

            const usersCollection = client.db().collection('users');
            try {
                await usersCollection.insertOne({ username, email, password: hashedPassword });
                req.session.user = { username, email }; // Store user in session
                res.redirect('/members'); // Redirect to members area
            } catch (err) {
                console.error("Error registering user:", err);
                res.status(500).send('Failed to register user');
            }
        });

        // Route for rendering login form
        app.get('/login', (req, res) => {
            res.send(`
        <h1>Login</h1>
        <form action="/login" method="POST">
          <input type="email" name="email" placeholder="Email">
          <input type="password" name="password" placeholder="Password">
          <button type="submit">Login</button>
        </form>
      `);
        });

        app.post('/login', async (req, res) => {
            const { email, password } = req.body;

            // Validate input using Joi
            const schema = Joi.object({
                email: Joi.string().email().required(),
                password: Joi.string().required()
            });

            try {
                await schema.validateAsync({ email, password });
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

            // If login is successful, store user in session and redirect
            req.session.user = { username: user.username };
            return res.redirect('/members');
        });



        // Route for handling 404 Not Found
        app.get('*', (req, res) => {
            res.status(404).send('Page not found - 404');
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
