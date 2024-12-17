const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const authenticate = require('./authMiddleware'); 
const app = express();
const path = require('path');
const port = 3004;
app.use(express.json());
app.use(bodyParser.json());
app.use(cors());

const db = mysql.createConnection({
  host: 'localhost', 
  user: 'root',       
  password: 'root',       
  database: 'taskmanager' 
});

db.connect((err) => {
  if (err) {
    console.error(err.stack);
    return;
  }
  console.log('Connected to the database');
});

app.use(express.static(path.join(__dirname, '../frontend')));

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

app.post('/register', (req, res) => {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Email, username, and password are required' });
    }
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const query = 'INSERT INTO users (email, username, password) VALUES (?, ?, ?)';
    db.query(query, [email, username, hashedPassword], (err, result) => {
      if (err) {
        return res.status(500).json({ error: err });
      }
      res.status(201).json({ message: 'User has been registered successfully' });
    });
});
  
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], (err, result) => {
    if (err) {
      return res.status(500).json({ error: err });
    }
    if (result.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }
    const user = result[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ error: err });
      }
      if (!isMatch) {
        return res.status(401).json({ message: 'Password did not match' });
      }
      const token = jwt.sign({ userId: user.id, username: user.username }, 'secret_key', { expiresIn: '1h' });
      res.status(200).json({ message: 'Login successful', token });
    });
  });
});

app.post('/tasks', authenticate, (req, res) => {
    const { title, priority, status, start_time, end_time, hours } = req.body;
    if (!title || !priority || !status || !start_time || !end_time || !hours) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    const sql = `INSERT INTO tasks (title, priority, status, start_time, end_time, hours, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    const params = [title, priority, status, start_time, end_time, hours, req.user.userId];
    db.query(sql, params, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
});

app.get('/tasks', authenticate, (req, res) => {
    const sql = `SELECT * FROM tasks WHERE user_id = ?`;
    db.query(sql, [req.user.userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
});

app.put('/tasks/:id', authenticate, (req, res) => {
    const taskId = req.params.id;
    const { title, priority, status, start_time, end_time, hours } = req.body;
    const sql = `UPDATE tasks SET title = ?, priority = ?, status = ?, start_time = ?, end_time = ?, hours = ? WHERE id = ? AND user_id = ?`;
    const params = [title, priority, status, start_time, end_time, hours, taskId, req.user.userId]; 
    db.query(sql, params, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
});

app.delete('/tasks/:id', authenticate, (req, res) => {
    const taskId = req.params.id;
    const sql = `DELETE FROM tasks WHERE id = ? AND user_id = ?`;
    const params = [taskId, req.user.userId];
    db.query(sql, params, (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
});

app.get('/tasks/priorityorder', authenticate, (req, res) => {
    const sql = `SELECT * FROM tasks WHERE user_id = ? ORDER BY priority DESC`;
    db.query(sql, [req.user.userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
})

app.get('/tasks/finished', authenticate, (req, res) => {
    const sql = `SELECT * FROM tasks WHERE user_id = ? AND status = 'Finished'`;
    db.query(sql, [req.user.userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
})

app.get('/tasks/unfinished', authenticate, (req, res) => {
    const sql = `SELECT * FROM tasks WHERE user_id = ? AND status = 'Pending'`;
    db.query(sql, [req.user.userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        return res.json(results);
    });
})

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
