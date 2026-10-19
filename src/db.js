import mysql from 'mysql2/promise';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const STORAGE_DIR = process.env.STORAGE_DIR || path.resolve(here, '..', '..', 'storage');
export const IMAGE_DIR = path.join(STORAGE_DIR, 'images');
fs.mkdirSync(IMAGE_DIR, { recursive: true });

const connectionOptions = {
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  supportBigNumbers: true,
  bigNumberStrings: false,
};
const databaseName = process.env.DB_NAME || 'documents';
export let db;
export const asyncHandler = (handler) => (req, res, next) =>
  Promise.resolve(handler(req, res, next)).catch(next);

const schemaFile = path.resolve(here, '..', 'schema.sql');

export async function initializeDatabase() {
  const bootstrap = await mysql.createConnection(connectionOptions);
  await bootstrap.query(`CREATE DATABASE IF NOT EXISTS \`${databaseName.replace(/`/g, '``')}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci`);
  await bootstrap.end();
  db = mysql.createPool({ ...connectionOptions, database: databaseName });

  const statements = fs.readFileSync(schemaFile, 'utf8').split(';').map((sql) => sql.trim()).filter(Boolean);
  for (const statement of statements) {
    if (/^(CREATE DATABASE|USE)\b/i.test(statement)) continue;
    await db.query(statement);
  }
  for (const [column, definition] of [
    ['can_create_org', 'TINYINT(1) NOT NULL DEFAULT 0'],
    ['can_create_folders', 'TINYINT(1) NOT NULL DEFAULT 0'],
  ]) {
    const [found] = await db.execute('SELECT 1 FROM information_schema.columns WHERE table_schema=? AND table_name=? AND column_name=?', [databaseName, 'users', column]);
    if (!found.length) await db.query(`ALTER TABLE users ADD COLUMN ${column} ${definition}`);
  }
  const [admins] = await db.execute('SELECT 1 FROM users WHERE role=? LIMIT 1', ['admin']);
  if (!admins.length) {
    const email = process.env.ADMIN_EMAIL || 'admin@example.com';
    const pass = process.env.ADMIN_PASSWORD || 'Admin@12345';
    await db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', [
      'Administrator', email, bcrypt.hashSync(pass, 10), 'admin',
    ]);
    console.log(`Seeded admin account: ${email} / ${pass}  (change this password)`);
  }
}
