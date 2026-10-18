import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { db, asyncHandler } from '../db.js';
import { auth, signToken, publicUser } from '../access.js';

const r = Router();
const emailOk = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e || '');

r.post('/signup', asyncHandler(async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error: 'Enter your name.' });
  if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (!password || password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  const [existing] = await db.execute('SELECT 1 FROM users WHERE email=?', [email]);
  if (existing.length) return res.status(409).json({ error: 'An account with this email already exists.' });
  const [result] = await db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)',
    [name.trim(), email.trim(), bcrypt.hashSync(password, 10), 'customer']);
  const [users] = await db.execute('SELECT * FROM users WHERE id=?', [result.insertId]);
  const user = users[0];
  res.json({ token: signToken(user), user: publicUser(user) });
}));

r.post('/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  const [users] = await db.execute('SELECT * FROM users WHERE email=?', [email || '']);
  const user = users[0];
  if (!user || !bcrypt.compareSync(password || '', user.password_hash)) return res.status(401).json({ error: 'Email or password is incorrect.' });
  if (!user.active) return res.status(403).json({ error: 'This account is disabled. Contact an administrator.' });
  res.json({ token: signToken(user), user: publicUser(user) });
}));

r.get('/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));
export default r;
