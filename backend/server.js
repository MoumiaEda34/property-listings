const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');

const app = express();
const PORT = 8081;
const SECRET_KEY = 'your-secret-key';

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'signup'
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

app.use(cors({ origin: 'http://localhost:3000', credentials: true }));
app.use(express.json());

// JWT Verification Middleware
const verifyJwt = (req, res, next) => {
  const token = req.headers['access-token'];

  if (!token) {
    return res.status(403).json({ message: 'Token missing. Please provide it.' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Not Authenticated' });
    } else {
      req.userId = decoded.id;
      next();
    }
  });
};

// Protected route
app.get('/checkauth', verifyJwt, (req, res) => {
  return res.status(200).json({ message: 'Authenticated', userId: req.userId });
});

// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM login WHERE `email` = ? AND `password` = ?';
  db.query(sql, [email, password], (err, data) => {
    if (err) {
      return res.status(500).json({ message: 'Database error', error: err });
    }

    if (data.length > 0) {
      const user = data[0];
      const token = jwt.sign({ email: user.email, id: user.id }, SECRET_KEY, { expiresIn: '1h' });

      return res.status(200).json({
        login: true,
        token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email
        }
      });
    } else {
      return res.status(401).json({ login: false, message: 'Invalid credentials' });
    }
  });
});

// Signup route
app.post('/signup', (req, res) => {
  const { name, email, password } = req.body;

  // Step 1: Check if email already exists
  const checkEmailSql = "SELECT * FROM login WHERE email = ?";
  db.query(checkEmailSql, [email], (checkErr, result) => {
    if (checkErr) {
      console.error("Email check error:", checkErr);
      return res.status(500).json({ message: "Database error while checking email" });
    }

    if (result.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // Step 2: Insert the user
    const insertSql = "INSERT INTO login (`name`, `email`, `password`) VALUES (?, ?, ?)";
    db.query(insertSql, [name, email, password], (insertErr, data) => {
      if (insertErr) {
        console.error("Insert error:", insertErr);
        return res.status(500).json({ message: "Database error while inserting user" });
      }

      return res.status(200).json({ message: "Success", data });
    });
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
