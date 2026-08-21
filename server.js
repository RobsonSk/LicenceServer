import fs from 'fs';
import https from 'https';
import http from 'http';
import express from 'express';
import cors from 'cors';
import exphbs from 'express-handlebars';
import dotenv from 'dotenv';
import path from 'path';

import { initDb } from './db.js';
import apiRoutes from './routes.js';
//import { setupSwagger } from './swagger.js';

dotenv.config();

const app = express();

// Enable CORS for external client applications
app.use(cors());

// Handlebars view engine setup
app.engine('handlebars', exphbs.engine({ defaultLayout: 'main' }));
app.set('view engine', 'handlebars');
app.set('views', './views');

// Middleware for parsing JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize SQLite Database
initDb().then(() => {
  console.log('[DB] Banco de dados SQLite inicializado com sucesso.');
}).catch(err => {
  console.error('[DB] Erro ao inicializar o banco de dados:', err);
});

// Swagger API Documentation
// try {
//   setupSwagger(app);
// } catch (e) {
//   console.log('[Swagger] Não foi possível carregar documentação Swagger:', e.message);
// }

// Rotas da API (Validador e Admin API)
app.use(apiRoutes);

// Rotas de Páginas Administrativas (HTML Handlebars)
app.get('/admin/login', (req, res) => {
  res.render('login');
});

app.get('/admin', (req, res) => {
  res.render('admin');
});

app.get('/', (req, res) => {
  res.redirect('/admin');
});

// Inicialização do Servidor HTTP / HTTPS
const PORT = process.env.PORT || 8443;
const USE_HTTPS = process.env.USE_HTTPS === 'true'; // Se 'false' ou não definido sem certs, usa HTTP
const CERT_PATH = path.resolve(process.env.SERVER_CERT_PATH || 'certs/server-cert.pem');
const KEY_PATH = path.resolve(process.env.SERVER_KEY_PATH || 'certs/server-key.pem');

let server;

if (USE_HTTPS && fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
  const options = {
    key: fs.readFileSync(KEY_PATH),
    cert: fs.readFileSync(CERT_PATH)
  };
  server = https.createServer(options, app);
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[HTTPS] Servidor de Licenciamento rodando em https://0.0.0.0:${PORT}`);
    console.log(`[API] Endpoint de Validação Externa por UUID: POST https://0.0.0.0:${PORT}/api/validate`);
    console.log(`[Painel Admin] Acesso Administrativo: https://0.0.0.0:${PORT}/admin`);
  });
} else {
  server = http.createServer(app);
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[HTTP] Servidor de Licenciamento rodando em http://0.0.0.0:${PORT} (Ideal para uso atrás do HAProxy/pfSense)`);
    console.log(`[API] Endpoint de Validação Externa por UUID: POST http://0.0.0.0:${PORT}/api/validate`);
    console.log(`[Painel Admin] Acesso Administrativo: http://0.0.0.0:${PORT}/admin`);
  });
}
