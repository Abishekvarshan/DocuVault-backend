import { Router } from 'express';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import { db, IMAGE_DIR, asyncHandler } from '../db.js';
import { ALL_PERMS, publicUser } from '../access.js';

const r = Router();
const ROLES = ['admin', 'staff', 'customer'];
const need = (res, cond, msg) => (cond ? true : (res.status(400).json({ error: msg }), false));
const all = async (sql, params = []) => (await db.execute(sql, params))[0];
const one = async (sql, params = []) => (await all(sql, params))[0];

// ---- Users ----
r.get('/users', asyncHandler(async (req, res) => {
  const rows = await all(`SELECT u.*, (SELECT COUNT(*) FROM grants g WHERE g.user_id=u.id) grants FROM users u ORDER BY u.created_at DESC`);
  res.json({ users: rows.map((u) => ({ ...publicUser(u), grants: u.grants, createdAt: u.created_at })) });
}));
r.post('/users', asyncHandler(async (req, res) => {
  const { name, email, password, role = 'staff' } = req.body || {};
  if (!need(res, name?.trim() && email?.includes('@'), 'Enter a name and a valid email.')) return;
  if (!need(res, password?.length >= 8, 'Password must be at least 8 characters.')) return;
  if (!need(res, ROLES.includes(role), 'Unknown role.')) return;
  if ((await all('SELECT 1 FROM users WHERE email=?', [email])).length) return res.status(409).json({ error: 'That email is already registered.' });
  const [result] = await db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', [name.trim(), email.trim(), bcrypt.hashSync(password, 10), role]);
  res.status(201).json({ user: await one('SELECT * FROM users WHERE id=?', [result.insertId]).then(publicUser) });
}));
r.patch('/users/:id', asyncHandler(async (req, res) => {
  const u = await one('SELECT * FROM users WHERE id=?', [req.params.id]);
  if (!u) return res.status(404).json({ error: 'User not found.' });
  const { name = u.name, role = u.role, active = !!u.active, password } = req.body || {};
  const canCreateOrg = role === 'staff' ? !!(req.body?.canCreateOrg ?? u.can_create_org) : false;
  const canCreateFolders = role === 'staff' ? !!(req.body?.canCreateFolders ?? u.can_create_folders) : false;
  if (!need(res, ROLES.includes(role), 'Unknown role.')) return;
  if (u.id === req.user.id && (role !== 'admin' || !active)) return res.status(400).json({ error: 'You cannot demote or disable your own account.' });
  if (password && password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  await db.execute('UPDATE users SET name=?, role=?, active=?, can_create_org=?, can_create_folders=?, password_hash=? WHERE id=?',
    [name.trim(), role, active ? 1 : 0, canCreateOrg ? 1 : 0, canCreateFolders ? 1 : 0, password ? bcrypt.hashSync(password, 10) : u.password_hash, u.id]);
  res.json({ user: publicUser(await one('SELECT * FROM users WHERE id=?', [u.id])) });
}));
r.delete('/users/:id', asyncHandler(async (req, res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: 'You cannot delete your own account.' });
  await db.execute('DELETE FROM users WHERE id=?', [req.params.id]);
  res.json({ ok: true });
}));

// ---- Organizations ----
r.get('/orgs', asyncHandler(async (req, res) => {
  const organizations = await all(`SELECT o.*, (SELECT COUNT(*) FROM images i WHERE i.org_id=o.id) images, (SELECT COUNT(*) FROM folders f WHERE f.org_id=o.id) folders FROM organizations o ORDER BY name`);
  res.json({ organizations });
}));
r.post('/orgs', asyncHandler(async (req, res) => {
  const name = req.body?.name?.trim();
  if (!need(res, name, 'Enter an organization name.')) return;
  if ((await all('SELECT 1 FROM organizations WHERE name=?', [name])).length) return res.status(409).json({ error: 'An organization with this name already exists.' });
  const [result] = await db.execute('INSERT INTO organizations(name) VALUES(?)', [name]);
  res.status(201).json({ id: result.insertId });
}));
r.patch('/orgs/:id', asyncHandler(async (req, res) => {
  const name = req.body?.name?.trim();
  if (!need(res, name, 'Enter an organization name.')) return;
  try {
    await db.execute('UPDATE organizations SET name=? WHERE id=?', [name, req.params.id]);
    res.json({ ok: true });
  } catch (error) {
    if (error.code !== 'ER_DUP_ENTRY') throw error;
    res.status(409).json({ error: 'An organization with this name already exists.' });
  }
}));
r.delete('/orgs/:id', asyncHandler(async (req, res) => {
  const ids = await all('SELECT id FROM images WHERE org_id=?', [req.params.id]);
  await db.execute('DELETE FROM organizations WHERE id=?', [req.params.id]);
  ids.forEach(({ id }) => fs.rmSync(path.join(IMAGE_DIR, String(id)), { recursive: true, force: true }));
  res.json({ ok: true });
}));

// ---- Folders (nested, auto-numbered: 1, 1.1, 1.2, 2 ...) ----
r.get('/folders', asyncHandler(async (req, res) => {
  const rows = await all('SELECT f.*, (SELECT COUNT(*) FROM images i WHERE i.folder_id=f.id) images FROM folders f WHERE org_id=? ORDER BY id', [req.query.orgId]);
  res.json({ folders: rows.map((f) => ({ id: f.id, parentId: f.parent_id, code: f.code, name: f.name, images: f.images }))
    .sort((a, b) => a.code.localeCompare(b.code, undefined, { numeric: true })) });
}));
r.post('/folders', asyncHandler(async (req, res) => {
  const { orgId, parentId = null, name } = req.body || {};
  if (!need(res, name?.trim(), 'Enter a folder name.')) return;
  const parent = parentId ? await one('SELECT * FROM folders WHERE id=? AND org_id=?', [parentId, orgId]) : null;
  if (parentId && !parent) return res.status(400).json({ error: 'Parent folder not found.' });
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    await connection.execute('SELECT id FROM organizations WHERE id=? FOR UPDATE', [orgId]);
    const [sequence] = await connection.execute('SELECT MAX(seq) m FROM folders WHERE org_id=? AND parent_id <=> ?', [orgId, parent?.id ?? null]);
    const seq = (sequence[0].m || 0) + 1;
    const code = parent ? `${parent.code}.${seq}` : String(seq);
    const [result] = await connection.execute('INSERT INTO folders(org_id,parent_id,seq,code,name) VALUES(?,?,?,?,?)', [orgId, parent?.id ?? null, seq, code, name.trim()]);
    await connection.commit();
    res.status(201).json({ id: result.insertId, code });
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}));
r.patch('/folders/:id', asyncHandler(async (req, res) => {
  if (!need(res, req.body?.name?.trim(), 'Enter a folder name.')) return;
  await db.execute('UPDATE folders SET name=? WHERE id=?', [req.body.name.trim(), req.params.id]);
  res.json({ ok: true });
}));
r.delete('/folders/:id', asyncHandler(async (req, res) => {
  const f = await one('SELECT * FROM folders WHERE id=?', [req.params.id]);
  if (!f) return res.status(404).json({ error: 'Folder not found.' });
  const busy = await one('SELECT (SELECT COUNT(*) FROM folders WHERE parent_id=?) c, (SELECT COUNT(*) FROM images WHERE folder_id=?) i', [f.id, f.id]);
  if (busy.c || busy.i) return res.status(409).json({ error: 'Only empty folders can be deleted. Move or delete the contents first.' });
  await db.execute('DELETE FROM folders WHERE id=?', [f.id]);
  res.json({ ok: true });
}));

// ---- Access grants ----
r.get('/grants', asyncHandler(async (req, res) => {
  const rows = await all(`SELECT g.*, o.name org_name, f.code, f.name folder_name FROM grants g
    JOIN organizations o ON o.id=g.org_id LEFT JOIN folders f ON f.id=g.folder_id WHERE g.user_id=? ORDER BY o.name, f.code`, [req.query.userId]);
  res.json({ grants: rows.map((g) => ({ id: g.id, orgId: g.org_id, orgName: g.org_name, folderId: g.folder_id,
    folderLabel: g.folder_id ? `${g.code} ${g.folder_name}` : 'Entire organization', perms: g.perms.split(',') })) });
}));
r.put('/grants', asyncHandler(async (req, res) => {
  const { userId, orgId, folderId = null } = req.body || {};
  const perms = [...new Set((req.body?.perms || []).filter((p) => ALL_PERMS.includes(p)))];
  if (!need(res, userId && orgId, 'Choose a user and an organization.')) return;
  if (!need(res, perms.length, 'Select at least one permission.')) return;
  if (!perms.includes('view')) perms.unshift('view');
  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    await connection.execute('DELETE FROM grants WHERE user_id=? AND org_id=? AND folder_id <=> ?', [userId, orgId, folderId]);
    await connection.execute('INSERT INTO grants(user_id,org_id,folder_id,perms) VALUES(?,?,?,?)', [userId, orgId, folderId, perms.join(',')]);
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
  res.json({ ok: true });
}));
r.delete('/grants/:id', asyncHandler(async (req, res) => {
  await db.execute('DELETE FROM grants WHERE id=?', [req.params.id]);
  res.json({ ok: true });
}));

export default r;
