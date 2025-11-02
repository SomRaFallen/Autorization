const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'мой_секретный_ключ';

// ------------------ Middleware ------------------
app.use(bodyParser.json());

// Разрешаем CORS с любого домена (фронтенд отдельно)
app.use(cors({ origin: '*' }));

// Отдаём статические файлы фронтенда
app.use(express.static('public'));

// ------------------ Работа с JSON ------------------
const USERS_FILE = './users.json';
const STUDENTS_FILE = './students.json';

function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(USERS_FILE,'utf8')); } 
  catch { return {}; }
}
function saveUsers(users) { fs.writeFileSync(USERS_FILE, JSON.stringify(users,null,2)); }

function loadStudents() {
  if (!fs.existsSync(STUDENTS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(STUDENTS_FILE,'utf8')); }
  catch { return []; }
}
function saveStudents(students) { fs.writeFileSync(STUDENTS_FILE, JSON.stringify(students,null,2)); }

let users = loadUsers();
let students = loadStudents();

// ------------------ Регистрация ------------------
app.post('/register', async (req,res)=>{
  const { username,password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'Введите имя и пароль' });
  if(users[username]) return res.status(400).json({ error:'Пользователь уже существует' });

  const hash = await bcrypt.hash(password,10);
  users[username] = { passwordHash: hash, role:'mentor', students:[], mentors:[] };
  saveUsers(users);
  res.json({ message:'Пользователь зарегистрирован' });
});

// ------------------ Вход ------------------
app.post('/login', async (req,res)=>{
  const { username,password } = req.body;
  const user = users[username];
  if(!user) return res.status(400).json({ error:'Пользователь не найден' });

  const valid = await bcrypt.compare(password,user.passwordHash);
  if(!valid) return res.status(400).json({ error:'Неверный пароль' });

  const token = jwt.sign({ username, role:user.role }, SECRET_KEY, { expiresIn:'8h' });

  res.json({
    message:'Вход выполнен успешно',
    token,
    user:{ username, role:user.role, students:user.students||[], mentors:user.mentors||[] },
    users: Object.keys(users).map(u=>({ username:u, role:users[u].role, students:users[u].students||[], mentors:users[u].mentors||[] })),
    students
  });
});

// ------------------ Смена пароля ------------------
app.post('/change-password', async (req,res)=>{
  const { username, oldPassword, newPassword } = req.body;
  const user = users[username];
  if(!user) return res.status(400).json({ error:'Пользователь не найден' });

  const valid = await bcrypt.compare(oldPassword,user.passwordHash);
  if(!valid) return res.status(400).json({ error:'Неверный старый пароль' });

  user.passwordHash = await bcrypt.hash(newPassword,10);
  saveUsers(users);
  res.json({ message:'Пароль изменён успешно' });
});

// ------------------ Middleware авторизации ------------------
function authenticateToken(req,res,next){
  const authHeader = req.headers['authorization'];
  if(!authHeader) return res.status(401).json({ error:'Нет токена авторизации' });
  const token = authHeader.split(' ')[1];
  try{
    const payload = jwt.verify(token,SECRET_KEY);
    req.user = payload;
    next();
  } catch {
    res.status(403).json({ error:'Неверный токен' });
  }
}

// ------------------ API для dashboard ------------------

// Получить всех учеников
app.get('/api/students', authenticateToken, (req,res)=>{
  res.json({ students });
});

// Получить всех пользователей
app.get('/api/users', authenticateToken, (req,res)=>{
  res.json({ users: Object.keys(users).map(u=>({ username:u, role:users[u].role, students:users[u].students||[], mentors:users[u].mentors||[] })) });
});

// Сохранить данные ученика
app.post('/api/saveStudentData', authenticateToken, (req,res)=>{
  const { studentId, AHT, NSAT } = req.body;
  const student = students.find(s=>s.id===studentId);
  if(!student) return res.status(400).json({ error:'Ученик не найден' });

  student.AHT = AHT;
  student.NSAT = NSAT;
  saveStudents(students);
  res.json({ message:'Данные ученика сохранены' });
});

// Сохранить данные наставника
app.post('/api/saveMentorData', authenticateToken, (req,res)=>{
  const { mentorId, students:mentorStudents } = req.body;
  const mentor = Object.values(users).find(u=>u.id===mentorId);
  if(!mentor) return res.status(400).json({ error:'Наставник не найден' });

  mentor.students = mentorStudents.map(s=>s.id);
  saveUsers(users);
  saveStudents(students);
  res.json({ message:'Данные наставника сохранены' });
});

// ------------------ Главная страница ------------------
app.get('/', (req,res)=>{
  res.sendFile(path.join(__dirname,'public','index.html'));
});

// ------------------ Запуск сервера ------------------
app.listen(PORT, ()=>console.log(`✅ Сервер запущен на порту ${PORT}`));
