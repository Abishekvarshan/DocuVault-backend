import { Router } from 'express';
import multer from 'multer';
import sharp from 'sharp';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { db, IMAGE_DIR, asyncHandler } from '../db.js';
import { permsFor, folderPath } from '../access.js';

const r = Router();
const MAX = (Number(process.env.MAX_UPLOAD_MB) || 60) * 1024 * 1024;
const TYPES = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif', 'image/tiff': 'tif', 'image/avif': 'avif' };
const upload = multer({
  storage: multer.memoryStorage(), limits: { fileSize: MAX },
  fileFilter: (req, file, cb) => (TYPES[file.mimetype] ? cb(null, true) : cb(new Error('Unsupported file type. Use JPG, PNG, WebP, GIF, TIFF or AVIF.'))),
});
const VARIANTS = { thumb: [320, 70], web: [1280, 80], hd: [2560, 85] };
const dirOf = (id) => path.join(IMAGE_DIR, String(id));
const all = async (sql, params = []) => (await db.execute(sql, params))[0];
const one = async (sql, params = []) => (await all(sql, params))[0];

async function writeVariants(id, buf) {
  const dir = dirOf(id);
  fs.mkdirSync(dir, { recursive: true });
  const jobs = Object.entries(VARIANTS).map(([name, [w, q]]) =>
    sharp(buf, { failOn: 'none' }).rotate().resize({ width: w, height: w, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: q }).toFile(path.join(dir, `${name}.webp`)));
  await Promise.all(jobs);
}
const originalFile = (img) => path.join(dirOf(img.id), `original.${img.ext}`);

const dto = (row, p, uploader) => ({
  id: row.id, orgId: row.org_id, folderId: row.folder_id, documentId: row.document_id, title: row.title,
  tags: row.tags ? row.tags.split(',') : [], originalName: row.original_name, mime: row.mime, size: row.size,
  width: row.width, height: row.height, uploadedBy: uploader ?? null, createdAt: row.created_at, updatedAt: row.updated_at,
  perms: [...(p || [])],
});

async function guard(req, res, need) {
  const img = await one('SELECT * FROM images WHERE id=?', [req.params.id]);
  if (!img) {
    res.status(404).json({ error: 'Image not found.' });
    return null;
  }
  const ctx = await permsFor(req.user, img.org_id);
  const p = ctx.map.get(img.folder_id) || new Set();
  if (!p.has('view') || (need && !p.has(need))) {
    res.status(403).json({ error: need ? `You don't have permission to ${need} this image.` : 'You do not have access to this image.' });
    return null;
  }
  return { img, p, ctx };
}

r.get('/tree', asyncHandler(async (req, res) => {
  const orgs = req.user.role === 'admin'
    ? await all('SELECT * FROM organizations ORDER BY name')
    : await all('SELECT DISTINCT o.* FROM organizations o JOIN grants g ON g.org_id=o.id WHERE g.user_id=? ORDER BY o.name', [req.user.id]);
  const countsRows = await all('SELECT folder_id,COUNT(*) n FROM images GROUP BY folder_id');
  const counts = new Map(countsRows.map((c) => [c.folder_id, c.n]));
  const out = await Promise.all(orgs.map(async (o) => {
    const { folders, map } = await permsFor(req.user, o.id);
    const visible = new Set();
    for (const f of folders) if (map.get(f.id).size) {
      visible.add(f.id);
      for (let p = folders.find((x) => x.id === f.parent_id); p; p = folders.find((x) => x.id === p.parent_id)) visible.add(p.id);
    }
    return {
      id: o.id, name: o.name,
      folders: folders.filter((f) => visible.has(f.id)).map((f) => ({
        id: f.id, parentId: f.parent_id, code: f.code, name: f.name, count: counts.get(f.id) || 0, perms: [...map.get(f.id)],
      })).sort((a, b) => a.code.localeCompare(b.code, undefined, { numeric: true })),
    };
  }));
  res.json({ organizations: out });
}));

r.get('/images', asyncHandler(async (req, res) => {
  const { orgId, folderId, q, format, from, to, sort = 'newest', includeSub, limit = 120, offset = 0 } = req.query;
  if (!orgId) return res.status(400).json({ error: 'Choose an organization.' });
  const ctx = await permsFor(req.user, Number(orgId));
  let ids = [...ctx.map].filter(([, s]) => s.has('view')).map(([id]) => id);
  if (folderId) {
    const f = ctx.folders.find((x) => x.id === Number(folderId));
    if (!f || !ctx.map.get(f.id).has('view')) return res.status(403).json({ error: 'You do not have access to this folder.' });
    ids = ids.filter((id) => {
      const x = ctx.folders.find((y) => y.id === id);
      return x.id === f.id || (includeSub === '1' && x.code.startsWith(f.code + '.'));
    });
  }
  if (!ids.length) return res.json({ items: [], total: 0 });
  const where = ['i.org_id=?', `i.folder_id IN (${ids.map(() => '?').join(',')})`];
  const args = [Number(orgId), ...ids];
  if (q) {
    where.push('(i.document_id LIKE ? OR i.title LIKE ? OR i.original_name LIKE ? OR i.tags LIKE ?)');
    args.push(...Array(4).fill(`%${q}%`));
  }
  if (format) { where.push('i.mime=?'); args.push(format); }
  if (from) { where.push('DATE(i.created_at)>=DATE(?)'); args.push(from); }
  if (to) { where.push('DATE(i.created_at)<=DATE(?)'); args.push(to); }
  const order = {
    newest: 'i.created_at DESC, i.id DESC', oldest: 'i.created_at ASC',
    doc: 'i.document_id COLLATE utf8mb4_0900_ai_ci ASC',
    name: 'i.original_name COLLATE utf8mb4_0900_ai_ci ASC', size: 'i.size DESC',
  }[sort] || 'i.id DESC';
  const base = `FROM images i LEFT JOIN users u ON u.id=i.uploaded_by WHERE ${where.join(' AND ')}`;
  const total = (await one(`SELECT COUNT(*) n ${base}`, args)).n;
  const rows = await all(`SELECT i.*, u.name uname ${base} ORDER BY ${order} LIMIT ? OFFSET ?`,
    [...args, Math.min(Number(limit), 300), Number(offset)]);
  res.json({ total, items: rows.map((x) => dto(x, ctx.map.get(x.folder_id), x.uname)) });
}));

r.get('/images/:id', asyncHandler(async (req, res) => {
  const g = await guard(req, res); if (!g) return;
  const u = await one('SELECT name FROM users WHERE id=?', [g.img.uploaded_by]);
  const sizes = {};
  for (const v of ['thumb', 'web', 'hd']) {
    try { sizes[v] = fs.statSync(path.join(dirOf(g.img.id), `${v}.webp`)).size; } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  sizes.original = g.img.size;
  res.json({ ...dto(g.img, g.p, u?.name), folderPath: folderPath(g.ctx.folders, g.img.folder_id), variantSizes: sizes });
}));

r.get('/images/:id/file', asyncHandler(async (req, res) => {
  const variant = ['thumb', 'web', 'hd', 'original'].includes(req.query.variant) ? req.query.variant : 'web';
  const g = await guard(req, res, req.query.download ? 'download' : null); if (!g) return;
  const file = variant === 'original' ? originalFile(g.img) : path.join(dirOf(g.img.id), `${variant}.webp`);
  if (!fs.existsSync(file)) return res.status(404).json({ error: 'File is missing from storage.' });
  if (req.query.download) {
    const base = g.img.document_id.replace(/[^\w.-]+/g, '_');
    return res.download(file, `${base}-${variant}${path.extname(file)}`);
  }
  res.set('Cache-Control', 'private, max-age=300');
  res.sendFile(path.resolve(file));
}));

r.post('/images', upload.single('file'), asyncHandler(async (req, res) => {
  const folderId = Number(req.body.folderId);
  const documentId = (req.body.documentId || '').trim();
  if (!req.file) return res.status(400).json({ error: 'No file received.' });
  if (!documentId) return res.status(400).json({ error: 'Document ID is required for every upload.' });
  const folder = await one('SELECT * FROM folders WHERE id=?', [folderId]);
  if (!folder) return res.status(400).json({ error: 'Choose a folder to upload into.' });
  const ctx = await permsFor(req.user, folder.org_id);
  if (!ctx.map.get(folderId)?.has('upload')) return res.status(403).json({ error: 'You do not have upload permission for this folder.' });

  const hash = crypto.createHash('sha256').update(req.file.buffer).digest('hex');
  if (req.body.force !== '1') {
    const dup = await one('SELECT * FROM images WHERE org_id=? AND hash=?', [folder.org_id, hash]);
    if (dup && ctx.map.get(dup.folder_id)?.has('view'))
      return res.status(409).json({ error: 'This image already exists.', duplicate: { id: dup.id, documentId: dup.document_id, folderPath: folderPath(ctx.folders, dup.folder_id) } });
    if (dup) return res.status(409).json({ error: 'This image already exists in this organization.', duplicate: { id: dup.id, documentId: dup.document_id, folderPath: 'a folder you cannot access' } });
  }
  const meta = await sharp(req.file.buffer, { failOn: 'none' }).metadata();
  const swap = meta.orientation >= 5;
  const [result] = await db.execute(`INSERT INTO images(org_id,folder_id,document_id,title,tags,original_name,ext,mime,size,width,height,hash,uploaded_by)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, [folder.org_id, folderId, documentId, (req.body.title || '').trim(), '',
    Buffer.from(req.file.originalname, 'latin1').toString('utf8'), TYPES[req.file.mimetype], req.file.mimetype, req.file.size,
    swap ? meta.height : meta.width, swap ? meta.width : meta.height, hash, req.user.id]);
  const id = result.insertId;
  try {
    fs.mkdirSync(dirOf(id), { recursive: true });
    fs.writeFileSync(path.join(dirOf(id), `original.${TYPES[req.file.mimetype]}`), req.file.buffer);
    await writeVariants(id, req.file.buffer);
  } catch (error) {
    await db.execute('DELETE FROM images WHERE id=?', [id]);
    fs.rmSync(dirOf(id), { recursive: true, force: true });
    throw error;
  }
  const row = await one('SELECT * FROM images WHERE id=?', [id]);
  res.status(201).json({ image: dto(row, ctx.map.get(folderId), req.user.name) });
}));

r.patch('/images/:id', asyncHandler(async (req, res) => {
  const g = await guard(req, res, 'edit'); if (!g) return;
  const documentId = (req.body.documentId ?? g.img.document_id).trim();
  if (!documentId) return res.status(400).json({ error: 'Document ID is required.' });
  const tags = Array.isArray(req.body.tags) ? req.body.tags.map((t) => t.trim()).filter(Boolean).join(',') : g.img.tags;
  await db.execute('UPDATE images SET document_id=?, title=?, tags=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
    [documentId, (req.body.title ?? g.img.title).trim(), tags, g.img.id]);
  res.json({ image: dto(await one('SELECT * FROM images WHERE id=?', [g.img.id]), g.p) });
}));

r.post('/images/:id/rotate', asyncHandler(async (req, res) => {
  const g = await guard(req, res, 'edit'); if (!g) return;
  try {
    const deg = [90, 180, 270].includes(Number(req.body.degrees)) ? Number(req.body.degrees) : 90;
    const oriented = await sharp(originalFile(g.img), { failOn: 'none' }).rotate().toBuffer();
    const rotated = await sharp(oriented).rotate(deg).toBuffer();
    fs.writeFileSync(originalFile(g.img), rotated);
    await writeVariants(g.img.id, rotated);
    const m = await sharp(rotated).metadata();
    await db.execute('UPDATE images SET width=?,height=?,size=?,hash=?,updated_at=CURRENT_TIMESTAMP WHERE id=?',
      [m.width, m.height, rotated.length, crypto.createHash('sha256').update(rotated).digest('hex'), g.img.id]);
    res.json({ image: dto(await one('SELECT * FROM images WHERE id=?', [g.img.id]), g.p) });
  } catch (error) { res.status(500).json({ error: `Rotation failed: ${error.message}` }); }
}));

async function targetFolder(req, res) {
  const f = await one('SELECT * FROM folders WHERE id=?', [Number(req.body.folderId)]);
  if (!f) {
    res.status(400).json({ error: 'Choose a destination folder.' });
    return null;
  }
  const p = (await permsFor(req.user, f.org_id)).map.get(f.id);
  if (!p?.has('upload')) {
    res.status(403).json({ error: 'You cannot add images to the destination folder.' });
    return null;
  }
  return f;
}

r.post('/images/:id/move', asyncHandler(async (req, res) => {
  const g = await guard(req, res, 'move'); if (!g) return;
  const f = await targetFolder(req, res); if (!f) return;
  if (f.org_id !== g.img.org_id) return res.status(400).json({ error: 'Images can only move within the same organization.' });
  await db.execute('UPDATE images SET folder_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', [f.id, g.img.id]);
  res.json({ ok: true });
}));

r.post('/images/:id/copy', asyncHandler(async (req, res) => {
  const g = await guard(req, res, 'download'); if (!g) return;
  const f = await targetFolder(req, res); if (!f) return;
  const i = g.img;
  const [result] = await db.execute(`INSERT INTO images(org_id,folder_id,document_id,title,tags,original_name,ext,mime,size,width,height,hash,uploaded_by)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, [f.org_id, f.id, i.document_id, i.title, i.tags, i.original_name, i.ext, i.mime, i.size, i.width, i.height, i.hash, req.user.id]);
  fs.cpSync(dirOf(i.id), dirOf(result.insertId), { recursive: true });
  res.status(201).json({ image: dto(await one('SELECT * FROM images WHERE id=?', [result.insertId]), new Set()) });
}));

r.delete('/images/:id', asyncHandler(async (req, res) => {
  const g = await guard(req, res, 'delete'); if (!g) return;
  await db.execute('DELETE FROM images WHERE id=?', [g.img.id]);
  fs.rmSync(dirOf(g.img.id), { recursive: true, force: true });
  res.json({ ok: true });
}));

export default r;
