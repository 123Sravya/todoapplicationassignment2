import logo from './logo.svg';
import './App.css';
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const app = express();

const SECRET_KEY = 'your_jwt_secret_key'; // Use a more secure key in production

app.use(express.json());

// Initialize SQLite3 database
const db = new sqlite3.Database('./todo_app.db');

// Create tables if they don't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)`);

db.run(`CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT CHECK(status IN ('pending', 'in progress', 'done', 'completed')),
    userId TEXT,
    FOREIGN KEY (userId) REFERENCES users(id)
)`);

// Middleware to authenticate JWT
function authenticateJWT(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Access denied' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// User Signup
app.post('/auth/signup', (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);
    const userId = uuidv4();

    const query = `INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)`;
    db.run(query, [userId, name, email, hashedPassword], function (err) {
        if (err) return res.status(400).json({ message: 'Email already exists' });
        res.status(201).json({ message: 'User registered successfully' });
    });
});

// User Login
app.post('/auth/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err || !user) return res.status(400).json({ message: 'Invalid email or password' });
        
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        if (!passwordIsValid) return res.status(401).json({ message: 'Invalid password' });

        const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    });
});

// Get Profile (Authenticated)
app.get('/api/profile', authenticateJWT, (req, res) => {
    db.get(`SELECT id, name, email FROM users WHERE id = ?`, [req.user.userId], (err, user) => {
        if (err || !user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    });
});

// Update Profile (Authenticated)
app.put('/api/profile', authenticateJWT, (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = password ? bcrypt.hashSync(password, 8) : undefined;

    const query = `UPDATE users SET name = ?, email = ?, password = ? WHERE id = ?`;
    const params = [name, email, hashedPassword || req.user.password, req.user.userId];

    db.run(query, params, function (err) {
        if (err) return res.status(400).json({ message: 'Error updating profile' });
        res.json({ message: 'Profile updated successfully' });
    });
});

// Get All Tasks (Authenticated)
app.get('/api/todos', authenticateJWT, (req, res) => {
    db.all(`SELECT * FROM tasks WHERE userId = ?`, [req.user.userId], (err, tasks) => {
        if (err) return res.status(400).json({ message: 'Error fetching tasks' });
        res.json(tasks);
    });
});

// Create a Task (Authenticated)
app.post('/api/todos', authenticateJWT, (req, res) => {
    const { title, description, status } = req.body;
    const taskId = uuidv4();
    const query = `INSERT INTO tasks (id, title, description, status, userId) VALUES (?, ?, ?, ?, ?)`;

    db.run(query, [taskId, title, description, status, req.user.userId], function (err) {
        if (err) return res.status(400).json({ message: 'Error creating task' });
        res.status(201).json({ message: 'Task created successfully' });
    });
});

// Update a Task (Authenticated)
app.put('/api/todos/:id', authenticateJWT, (req, res) => {
    const { title, description, status } = req.body;
    const { id } = req.params;

    const query = `UPDATE tasks SET title = ?, description = ?, status = ? WHERE id = ? AND userId = ?`;
    db.run(query, [title, description, status, id, req.user.userId], function (err) {
        if (err || this.changes === 0) return res.status(400).json({ message: 'Task not found or update failed' });
        res.json({ message: 'Task updated successfully' });
    });
});

// Delete a Task (Authenticated)
app.delete('/api/todos/:id', authenticateJWT, (req, res) => {
    const { id } = req.params;

    const query = `DELETE FROM tasks WHERE id = ? AND userId = ?`;
    db.run(query, [id, req.user.userId], function (err) {
        if (err || this.changes === 0) return res.status(400).json({ message: 'Task not found or delete failed' });
        res.json({ message: 'Task deleted successfully' });
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});





function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
      </header>
    </div>
  );
}

export default App;
