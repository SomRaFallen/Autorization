const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); // отдаём HTML и статические файлы

const USERS_FILE = './users.json';

// === Работа с JSON-файлом ===
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (err) {
    console.error('Ошибка чтения users.json:', err);
    return {};
  }
}

function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
  } catch (err) {
    console.error('Ошибка записи users.json:', err);
  }
}

let users = loadUsers();

// === РЕГИСТРАЦИЯ ===
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Введите имя и пароль' });

  if (users[username])
    return res.status(400).json({ error: 'Пользователь уже существует' });

  const passwordHash = await bcrypt.hash(password, 10);
  users[username] = { passwordHash };
  saveUsers(users);

  res.json({ message: 'Пользователь зарегистрирован' });
});

// === ВХОД ===
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user)
    return res.status(400).json({ error: 'Пользователь не найден' });

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid)
    return res.status(400).json({ error: 'Неверный пароль' });

  res.json({ message: 'Вход выполнен успешно' });
});

// === СМЕНА ПАРОЛЯ ===
app.post('/change-password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  const user = users[username];
  if (!user)
    return res.status(400).json({ error: 'Пользователь не найден' });

  const valid = await bcrypt.compare(oldPassword, user.passwordHash);
  if (!valid)
    return res.status(400).json({ error: 'Неверный старый пароль' });

  user.passwordHash = await bcrypt.hash(newPassword, 10);
  saveUsers(users);
  res.json({ message: 'Пароль изменён успешно' });
});

// === Главная страница ===
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));
