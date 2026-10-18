import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { initializeDatabase } from './db.js';
import { auth, adminOnly } from './access.js';
import authRoutes from './routes/auth.js';
import workspace from './routes/workspace.js';
import admin from './routes/admin.js';

const app = express();
const allowedOrigins = (process.env.FRONTEND_URL || '').split(',').map((origin) => origin.trim()).filter(Boolean);
app.use(cors(allowedOrigins.length ? { origin: allowedOrigins } : undefined));
app.use(express.json({ limit: '1mb' }));

app.get('/api/health', (req, res) => res.json({ ok: true }));
app.use('/api/auth', authRoutes);
app.use('/api/workspace', auth, workspace);
app.use('/api/admin', auth, adminOnly, admin);
app.use('/api', (req, res) => res.status(404).json({ error: 'Endpoint not found.' }));

// Serve the built frontend when present (npm run build in /frontend)
const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'frontend', 'dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.get('*', (req, res) => res.sendFile(path.join(dist, 'index.html')));
}

app.use((err, req, res, next) => {
  const msg = err.code === 'LIMIT_FILE_SIZE' ? 'File is larger than the allowed upload size.' : err.message || 'Unexpected server error.';
  res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: msg });
});

const port = process.env.PORT || 4000;
initializeDatabase()
  .then(() => app.listen(port, () => console.log(`DocuVault API listening on http://localhost:${port}`)))
  .catch((error) => {
    console.error('Failed to initialize the MySQL database:', error);
    process.exitCode = 1;
  });
