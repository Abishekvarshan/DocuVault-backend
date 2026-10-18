import jwt from 'jsonwebtoken';
import { db } from './db.js';

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
export const ALL_PERMS = ['view', 'download', 'upload', 'edit', 'move', 'delete'];
const CUSTOMER_PERMS = ['view', 'download']; // customers are read-only by design

export const signToken = (u) => jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' });
export const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, active: !!u.active });

export async function auth(req, res, next) {
  const h = req.headers.authorization;
  const token = h?.startsWith('Bearer ') ? h.slice(7) : req.query.token; // query token lets <img> tags load files
  let id;
  try {
    ({ id } = jwt.verify(token, SECRET));
  } catch {
    return res.status(401).json({ error: 'Please sign in again.' });
  }
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id=?', [id]);
    const user = rows[0];
    if (!user || !user.active) return res.status(401).json({ error: 'Your account is unavailable. Contact an administrator.' });
    req.user = user;
    next();
  } catch (error) {
    next(error);
  }
}

export const adminOnly = (req, res, next) =>
  req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Administrator access required.' });

/** Per-folder permission sets for a user inside one organization. Grants cascade to sub-folders. */
export async function permsFor(user, orgId) {
  const [folders] = await db.execute('SELECT id,parent_id,code,name,seq FROM folders WHERE org_id=? ORDER BY id', [orgId]);
  const map = new Map();
  if (user.role === 'admin') {
    folders.forEach((f) => map.set(f.id, new Set(ALL_PERMS)));
    return { folders, map };
  }
  const allowed = user.role === 'customer' ? CUSTOMER_PERMS : ALL_PERMS;
  const [grants] = await db.execute('SELECT folder_id,perms FROM grants WHERE user_id=? AND org_id=?', [user.id, orgId]);
  const byId = new Map(folders.map((f) => [f.id, f]));
  for (const f of folders) {
    const s = new Set();
    for (const g of grants) {
      const gf = g.folder_id == null ? null : byId.get(g.folder_id);
      if (g.folder_id == null || (gf && (gf.id === f.id || f.code.startsWith(gf.code + '.')))) {
        g.perms.split(',').filter((p) => allowed.includes(p)).forEach((p) => s.add(p));
      }
    }
    map.set(f.id, s.has('view') ? s : new Set());
  }
  return { folders, map };
}

export const folderPath = (folders, id) => {
  const byId = new Map(folders.map((f) => [f.id, f]));
  const parts = [];
  for (let f = byId.get(id); f; f = byId.get(f.parent_id)) parts.unshift(`${f.code} ${f.name}`);
  return parts.join(' / ');
};
