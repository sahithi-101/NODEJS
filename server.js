const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3');

const app = express();
const PORT = 1024;
const SECRET = 'NodeJsProject';

const db = new sqlite3.Database('./data.db', () => {
  db.run('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, email TEXT UNIQUE, password TEXT)');
  db.run('CREATE TABLE IF NOT EXISTS todos (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, description TEXT, done INTEGER)');
  console.log('Database ready');
});

app.use(express.json());
app.use(express.static('public'));

app.get('/', (req, res) => res.sendFile(__dirname + '/public/index.html'));

app.post('/register', (req, res) => {
  const { username, email, password } = req.body;
  db.get('SELECT id FROM users WHERE email = ?', [email], (err, existing) => {
    if (existing) return res.status(400).json({ error: 'Email already used' });
    const hash = bcrypt.hashSync(password, 1);
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hash], function(err) {
        if (err) return res.status(400).json({ error: 'Email already used' });
        const token = jwt.sign({ id: this.lastID }, SECRET);
        res.json({ token, username, email });
      });
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Wrong email or password' });
    }
    const token = jwt.sign({ id: user.id }, SECRET);
    res.json({ token, username: user.username, email: user.email });
  });
});

app.get('/todos', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Bad token' });
    db.all('SELECT * FROM todos WHERE user_id = ?', [user.id], (err, rows) => res.json(rows));
  });
});

app.post('/todos', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Bad token' });
    const { title, description } = req.body;
    db.run('INSERT INTO todos (user_id, title, description, done) VALUES (?, ?, ?, 0)',
      [user.id, title, description], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        db.get('SELECT * FROM todos WHERE id = ?', [this.lastID], (err, row) => res.json(row));
      });
  });
});

app.put('/todos/:id', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Bad token' });
    const { title, description, done } = req.body;
    db.get('SELECT * FROM todos WHERE id = ? AND user_id = ?', [req.params.id, user.id], (err, old) => {
      if (!old) return res.status(404).json({ error: 'Not found' });
      db.run('UPDATE todos SET title=?, description=?, done=? WHERE id=? AND user_id=?',
        [title || old.title, description || old.description, done != null ? done : old.done, req.params.id, user.id], function(err) {
          if (err) return res.status(500).json({ error: err.message });
          db.get('SELECT * FROM todos WHERE id = ?', [req.params.id], (err, row) => res.json(row));
        });
    });
  });
});

app.delete('/todos/:id', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Bad token' });
    db.run('DELETE FROM todos WHERE id = ? AND user_id = ?', [req.params.id, user.id],
      () => res.json({ ok: true }));
  });
});

app.listen(PORT, () => console.log('Server: http://localhost:' + PORT));