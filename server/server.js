const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
const cors = require('cors');
const forge = require('node-forge');
const crypto = require('crypto');

const app = express();
const port = 3001;
app.use(cors());
app.options('*', cors()); 

app.use(bodyParser.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'my-app',
});

db.connect();

// Define database schema and tables
db.query(`
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('normal', 'privileged', 'admin') NOT NULL
  )
`);

db.query(`
  CREATE TABLE IF NOT EXISTS customers (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    address VARCHAR(255) NOT NULL,
    phone VARCHAR(20) NOT NULL,
    creditCard VARCHAR(255) NOT NULL,
    medicalRecords VARCHAR(255) NOT NULL
  )
`);

// Define middleware for authentication
const authenticateUser = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    const verified = jwt.verify(token, 'your_secret_key');
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ message: 'Invalid token' });
  }
};

// Define login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Validate user credentials
  const user = await getUserByUsername(username);
  if (!user) return res.status(400).json({ message: 'Invalid credentials' });

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).json({ message: 'Invalid credentials' });

  // Generate JWT
  const token = jwt.sign({ id: user.id, role: user.role }, 'your_secret_key');
  res.json({ token });
});

// Define search route
app.get('/search', authenticateUser, async (req, res) => {
    const { role } = req.user;
    const searchTerm = req.query.term;
  
    try {
      let query;
  
      if (searchTerm === '*') {
        // Fetch all customers based on user role
        query = 'SELECT * FROM customers';
      } else {
        // Fetch customers based on search term and user role
        query = `SELECT * FROM customers WHERE name LIKE '%${searchTerm}%' OR email LIKE '%${searchTerm}%'`;
      }
  
      db.query(query, (err, results) => {
        if (err) throw err;
        res.json(results);
      });
    } catch (error) {
      console.error('Search failed', error);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  

// Define route to add user
app.post('/add-user', async (req, res) => {
  const { username, password, role } = req.body;

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert user into the database
  db.query('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role], (err, results) => {
    if (err) throw err;
    res.json({ message: 'User added successfully' });
  });
});

// Define route to add customer
app.post('/add-customer', async (req, res) => {
  const { name, email, address, phone, creditCard, medicalRecords } = req.body;

  const encryptedCreditCard = encrypt3DES(creditCard, "A5dghfghA5dghfghA5dghfghA5dghfgh")
  const encryptedMedicalRecords = encrypt3DES(medicalRecords, "A5dghfghA5dghfghA5dghfghA5dghfgh")

  // Insert customer into the database
  db.query(
    'INSERT INTO customers (name, email, address, phone, creditCard, medicalRecords) VALUES (?, ?, ?, ?, ?, ?)',
    [name, email, address, phone, encryptedCreditCard, encryptedMedicalRecords],
    (err, results) => {
      if (err) throw err;
      res.json({ message: 'Customer added successfully' });
    }
  );
});

function encrypt3DES(input, key) {
    var md5Key = forge.md.md5.create();
    md5Key.update(key);
    md5Key = md5Key.digest().toHex();
  
    var cipher = forge.cipher.createCipher('3DES-ECB', md5Key.substring(0, 24));
    cipher.start();
    cipher.update(forge.util.createBuffer(Buffer.from(input, "utf8").toString("binary")));
    cipher.finish();
    var encrypted = cipher.output;
  
    return Buffer.from(encrypted.getBytes(), "binary").toString("base64")
  }

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

// Helper functions to interact with the database
const getUserByUsername = async (username) => {
  return new Promise((resolve, reject) => {
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
      if (err) reject(err);
      resolve(results[0]);
    });
  });
};






  

