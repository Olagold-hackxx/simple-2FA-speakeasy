const express = require('express');
const bodyParser = require('body-parser');
const speakeasy = require('speakeasy');
const bcrypt = require('bcrypt');
const ejs = require('ejs')
const session = require('express-session');

const app = express();
const port = 3000;


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({ secret: 'secret-key', resave: false, saveUninitialized: true }));


app.set('view engine', 'ejs');

// In-memory storage for simplicity will be replaced with a database in a real app)
const users = {
  john: {
    username: 'john',
    password: 'password123',
    secret: speakeasy.generateSecret().base32,
    loggedIn: false,
  },
};

app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

// Endpoint for user registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if the username is already taken
  if (users[username]) {
    return res.status(400).json({ message: 'Username already exists' });
  }

  // Hash the password
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Create a new secret for the user
  const secret = speakeasy.generateSecret();
  users[username] = { hashedPassword, secret: secret.base32, isVerified: false };

  res.json({ secret: secret.base32, username });
});

// Endpoint for user login and token verification
app.post('/login', async (req, res) => {
  const { username, password, token } = req.body;
  const user = users[username];

  if (!user) {
    return res.status(404).json({ message: 'User not found' });
  }

  // Verify the password
  const passwordMatch = await bcrypt.compare(password, user.hashedPassword);

  if (!passwordMatch) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  // Verify the provided token
  const verified = speakeasy.totp.verify({
    secret: user.secret,
    encoding: 'base32',
    token,
  });

  if (verified) {
    // Mark user as verified (optional)
    user.isVerified = true;
    res.json({ message: 'Login successful' });
  } else {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
