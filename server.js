const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config(); // Load environment variables from .env file

const app = express();
const port = process.env.PORT || 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false, // Adjust this based on your environment
    },
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

const hashPassword = async (password) => {
    const saltRounds = 10;
    return bcrypt.hash(password, saltRounds);
};

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        const hashedPassword = await hashPassword(password);

        const result = await pool.query('INSERT INTO users (name, email, password) VALUES ($1, $2, $3)', [name, email, hashedPassword]);
        console.log(result.rows);
        res.send('Account created successfully!');
    } catch (error) {
        console.error('Error in query execution:', error);
        res.status(500).send('Error creating account');
    }
});

app.post('/signin', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

        if (result.rows.length > 0) {
            const hashedPassword = result.rows[0].password;

            const passwordMatch = await bcrypt.compare(password, hashedPassword);

            if (passwordMatch) {
                res.redirect('/fieldmate0/index.html');
            } else {
                res.send('Invalid email or password');
            }
        } else {
            res.send('Invalid email or password');
        }
    } catch (error) {
        console.error('Error in query execution:', error);
        res.status(500).send('Error in query execution');
    }
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
