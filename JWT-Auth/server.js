require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();
const port = 3001;

// Mock posts data
const posts = [
  { username: 'Nasim', title: 'Post 1' },
  { username: 'Nezam', title: 'Post 2' },
];

app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.get('/posts', authenticateToken, (req, res) => {
  res.render('index', { user: req.user });
});


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.listen(port, () => console.log(`Server running on port ${port}`));
