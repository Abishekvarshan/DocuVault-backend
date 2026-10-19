import { Router } from 'express';
import { db, asyncHandler } from '../db.js';
import { permsFor } from '../access.js';

const r = Router();
const all = async (sql, params = []) => (await db.execute(sql, params))[0];
const one = async (sql, params = []) => (await all(sql, params))[0];
const isAdmin = (user) => user.role === 'admin';

r.get('/access', asyncHandler(async (req, res) => {
  const admin = isAdmin(req.user);
  const canCreateOrg = admin || !!req.user.can_create_org;
  const canCreateFolders = admin || !!req.user.can_create_folders;
  if (!canCreateFolders) return res.json({ canCreateOrg, canCreateFolders, organizations: [] });

  const organizations = admin
    ? await all('SELECT id,name FROM organizations ORDER BY name')
    : await all(`SELECT DISTINCT o.id,o.name FROM organizations o
      JOIN grants g ON g.org_id=o.id WHERE g.user_id=? AND FIND_IN_SET('view',g.perms)>0 ORDER BY o.name`, [req.user.id]);

  const result = await Promise.all(organizations.map(async (org) => {
    const { folders, map } = await permsFor(req.user, org.id);
    const orgGrant = admin ? true : (await all('SELECT perms FROM grants WHERE user_id=? AND org_id=? AND folder_id IS NULL', [req.user.id, org.id]))
      .some((g) => g.perms.split(',').includes('view'));
    return {
      ...org,
      canCreateRoot: admin || orgGrant,
      folders: folders.filter((f) => admin || map.get(f.id)?.has('view'))
        .map((f) => ({ id: f.id, parentId: f.parent_id, code: f.code, name: f.name, canCreate: admin || map.get(f.id)?.has('view') })),
    };
  }));
  res.json({ canCreateOrg, canCreateFolders, organizations: result });
}));

r.post('/orgs', asyncHandler(async (req, res) => {
  if (!isAdmin(req.user) && !req.user.can_create_org) return res.status(403).json({ error: 'Organization creation is not enabled for your account.' });
  const name = req.body?.name?.trim();
  if (!name) return res.status(400).json({ error: 'Enter an organization name.' });
  try {
    const [created] = await db.execute('INSERT INTO organizations(name) VALUES(?)', [name]);
    if (!isAdmin(req.user)) {
      await db.execute('INSERT INTO grants(user_id,org_id,folder_id,perms) VALUES(?,?,NULL,?)', [req.user.id, created.insertId, 'view']);
    }
    res.status(201).json({ id: created.insertId });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'An organization with this name already exists.' });
    throw error;
  }
}));

r.post('/folders', asyncHandler(async (req, res) => {
  const { orgId, parentId = null, name } = req.body || {};
  if (!isAdmin(req.user) && !req.user.can_create_folders) return res.status(403).json({ error: 'Folder creation is not enabled for your account.' });
  if (!name?.trim()) return res.status(400).json({ error: 'Enter a folder name.' });
  const org = await one('SELECT id FROM organizations WHERE id=?', [orgId]);
  if (!org) return res.status(400).json({ error: 'Organization not found.' });

  let parent = null;
  if (parentId) {
    parent = await one('SELECT * FROM folders WHERE id=? AND org_id=?', [parentId, orgId]);
    if (!parent) return res.status(400).json({ error: 'Parent folder not found in this organization.' });
  }
  if (!isAdmin(req.user)) {
    if (parent) {
      const access = await permsFor(req.user, orgId);
      if (!access.map.get(parent.id)?.has('view')) return res.status(403).json({ error: 'You need access to the parent folder to create a subfolder.' });
    } else {
      const grants = await all('SELECT perms FROM grants WHERE user_id=? AND org_id=? AND folder_id IS NULL', [req.user.id, orgId]);
      if (!grants.some((g) => g.perms.split(',').includes('view'))) return res.status(403).json({ error: 'You need organization-level access to create a top-level folder.' });
    }
  }

  const connection = await db.getConnection();
  try {
    await connection.beginTransaction();
    await connection.execute('SELECT id FROM organizations WHERE id=? FOR UPDATE', [orgId]);
    const [sequence] = await connection.execute('SELECT MAX(seq) m FROM folders WHERE org_id=? AND parent_id <=> ?', [orgId, parent?.id ?? null]);
    const seq = (sequence[0].m || 0) + 1;
    const code = parent ? `${parent.code}.${seq}` : String(seq);
    const [created] = await connection.execute('INSERT INTO folders(org_id,parent_id,seq,code,name) VALUES(?,?,?,?,?)', [orgId, parent?.id ?? null, seq, code, name.trim()]);
    await connection.commit();
    res.status(201).json({ id: created.insertId, code });
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }
}));

export default r;
