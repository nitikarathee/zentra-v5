import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import apiRouter from './server/routes.ts';
import { initHindsight } from './server/hindsight.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;
  const isProd = process.env.NODE_ENV === 'production';

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Security headers for backend API (allow embedding in AI Studio preview iframe)
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Mount API routes
  app.use('/api', apiRouter);

  // Health check endpoint
  app.get('/health', (_req, res) => {
    res.json({
      status: 'healthy',
      platform: 'ZENTRA',
      version: '1.0.0',
      zeroTrustEngine: 'active',
      timestamp: new Date().toISOString()
    });
  });

  if (!isProd) {
    // Development mode: mount Vite dev server middlewares
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
    console.log('[ZENTRA] Vite dev middleware mounted.');
  } else {
    // Production mode: serve built assets from dist
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(distPath, 'index.html'));
    });
    console.log('[ZENTRA] Serving static files from dist.');
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[ZENTRA] Zero-Trust Engine online at http://0.0.0.0:${PORT}`);
    // Persistent agent memory (Hindsight): create the bank once. Never blocks or crashes the app.
    void initHindsight();
  });
}

startServer().catch((err) => {
  console.error('[ZENTRA] Server initialization failed:', err);
  process.exit(1);
});
