const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DATABASE_PATH || './data/leads.db';

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'v4123';

const sessions = new Map();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Schema atualizado com mais campos
// Criar tabelas básicas primeiro
db.exec(`
  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id TEXT NOT NULL,
    form_name TEXT,
    data TEXT NOT NULL,
    ip_address TEXT,
    webhook_sent INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS forms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    fields TEXT NOT NULL,
    webhook_url TEXT,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    form_id TEXT,
    url TEXT NOT NULL,
    is_global INTEGER DEFAULT 0,
    active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);

// Migração: adicionar novas colunas se não existirem
const leadColumns = ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id', 'referrer', 'page_url', 'user_agent', 'device_type', 'browser', 'os', 'country', 'city', 'webhook_response'];
leadColumns.forEach(col => {
  try { db.exec(`ALTER TABLE leads ADD COLUMN ${col} TEXT`); } catch (e) {}
});

const formColumns = ['styles', 'settings', 'updated_at'];
formColumns.forEach(col => {
  try { db.exec(`ALTER TABLE forms ADD COLUMN ${col} TEXT`); } catch (e) {}
});

const webhookColumns = ['last_triggered', 'success_count', 'fail_count'];
webhookColumns.forEach(col => {
  try { 
    if (col.includes('count')) {
      db.exec(`ALTER TABLE webhooks ADD COLUMN ${col} INTEGER DEFAULT 0`);
    } else {
      db.exec(`ALTER TABLE webhooks ADD COLUMN ${col} TEXT`);
    }
  } catch (e) {}
});

// Criar índices após colunas existirem
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_leads_form_id ON leads(form_id)`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at)`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_leads_utm_source ON leads(utm_source)`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_leads_utm_campaign ON leads(utm_campaign)`); } catch (e) {}

// Funções auxiliares
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function parseUserAgent(ua) {
  if (!ua) return { device: 'unknown', browser: 'unknown', os: 'unknown' };
  
  let device = 'desktop';
  if (/mobile/i.test(ua)) device = 'mobile';
  else if (/tablet|ipad/i.test(ua)) device = 'tablet';
  
  let browser = 'other';
  if (/chrome/i.test(ua) && !/edge|opr/i.test(ua)) browser = 'Chrome';
  else if (/firefox/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = 'Safari';
  else if (/edge/i.test(ua)) browser = 'Edge';
  else if (/opr|opera/i.test(ua)) browser = 'Opera';
  
  let os = 'other';
  if (/windows/i.test(ua)) os = 'Windows';
  else if (/macintosh|mac os/i.test(ua)) os = 'MacOS';
  else if (/linux/i.test(ua)) os = 'Linux';
  else if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
  
  return { device, browser, os };
}

function requireAuth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ success: false, error: 'Não autorizado' });
  }
  sessions.set(token, Date.now());
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [token, timestamp] of sessions) {
    if (now - timestamp > 24 * 60 * 60 * 1000) {
      sessions.delete(token);
    }
  }
}, 60 * 60 * 1000);

// ==================== ROTAS PÚBLICAS ====================

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = generateToken();
    sessions.set(token, Date.now());
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, error: 'Usuário ou senha inválidos' });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (token) sessions.delete(token);
  res.json({ success: true });
});

app.get('/api/session', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (token && sessions.has(token)) {
    sessions.set(token, Date.now());
    res.json({ success: true, authenticated: true });
  } else {
    res.json({ success: true, authenticated: false });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Receber lead (público) - ATUALIZADO com mais dados
app.post('/api/leads', async (req, res) => {
  try {
    const { formId, formName, data, meta } = req.body;
    if (!formId || !data) {
      return res.status(400).json({ success: false, error: 'formId e data obrigatórios' });
    }

    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.headers['x-real-ip'] || req.socket.remoteAddress;
    const ua = req.headers['user-agent'] || '';
    const { device, browser, os } = parseUserAgent(ua);
    
    // Extrair UTMs do meta ou do data
    const utmSource = meta?.utm_source || data.utm_source || null;
    const utmMedium = meta?.utm_medium || data.utm_medium || null;
    const utmCampaign = meta?.utm_campaign || data.utm_campaign || null;
    const utmTerm = meta?.utm_term || data.utm_term || null;
    const utmContent = meta?.utm_content || data.utm_content || null;
    const utmId = meta?.utm_id || data.utm_id || null;
    const referrer = meta?.referrer || data.referrer || null;
    const pageUrl = meta?.page_url || data.page_url || null;
    
    // Remover UTMs do data para não duplicar
    const cleanData = { ...data };
    ['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id', 'referrer', 'page_url'].forEach(k => delete cleanData[k]);

    const stmt = db.prepare(`
      INSERT INTO leads (form_id, form_name, data, utm_source, utm_medium, utm_campaign, utm_term, utm_content, utm_id, referrer, page_url, ip_address, user_agent, device_type, browser, os)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(
      formId, formName || '', JSON.stringify(cleanData),
      utmSource, utmMedium, utmCampaign, utmTerm, utmContent, utmId,
      referrer, pageUrl, ip, ua, device, browser, os
    );
    const leadId = result.lastInsertRowid;

    // Enviar para webhooks
    const webhooks = db.prepare('SELECT * FROM webhooks WHERE (form_id = ? OR is_global = 1) AND active = 1').all(formId);
    let webhookSent = false;
    let webhookResponse = null;

    const webhookPayload = {
      leadId,
      formId,
      formName,
      data: cleanData,
      utm: { source: utmSource, medium: utmMedium, campaign: utmCampaign, term: utmTerm, content: utmContent, id: utmId },
      meta: { ip, referrer, pageUrl, device, browser, os },
      receivedAt: new Date().toISOString()
    };

    for (const wh of webhooks) {
      try {
        const response = await fetch(wh.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(webhookPayload)
        });
        if (response.ok) {
          webhookSent = true;
          webhookResponse = `${wh.url}: OK`;
          db.prepare('UPDATE webhooks SET last_triggered = CURRENT_TIMESTAMP, success_count = success_count + 1 WHERE id = ?').run(wh.id);
        } else {
          db.prepare('UPDATE webhooks SET last_triggered = CURRENT_TIMESTAMP, fail_count = fail_count + 1 WHERE id = ?').run(wh.id);
        }
      } catch (e) {
        console.error('Webhook error:', e.message);
        db.prepare('UPDATE webhooks SET fail_count = fail_count + 1 WHERE id = ?').run(wh.id);
      }
    }

    if (webhookSent) {
      db.prepare('UPDATE leads SET webhook_sent = 1, webhook_response = ? WHERE id = ?').run(webhookResponse, leadId);
    }

    res.json({ success: true, leadId, webhookSent });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// ==================== ROTAS PROTEGIDAS ====================

// Listar leads com filtros
app.get('/api/leads', requireAuth, (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const formId = req.query.form_id;
    const search = req.query.search;
    const utmSource = req.query.utm_source;
    const utmCampaign = req.query.utm_campaign;
    const dateFrom = req.query.date_from;
    const dateTo = req.query.date_to;

    let where = '1=1';
    const params = [];

    if (formId) { where += ' AND form_id = ?'; params.push(formId); }
    if (utmSource) { where += ' AND utm_source = ?'; params.push(utmSource); }
    if (utmCampaign) { where += ' AND utm_campaign = ?'; params.push(utmCampaign); }
    if (dateFrom) { where += ' AND created_at >= ?'; params.push(dateFrom); }
    if (dateTo) { where += ' AND created_at <= ?'; params.push(dateTo + ' 23:59:59'); }
    if (search) { where += ' AND (data LIKE ? OR form_name LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

    const leads = db.prepare(`SELECT * FROM leads WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
    const { total } = db.prepare(`SELECT COUNT(*) as total FROM leads WHERE ${where}`).get(...params);

    res.json({
      success: true,
      leads: leads.map(l => ({
        ...l,
        data: JSON.parse(l.data || '{}')
      })),
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Detalhes de um lead
app.get('/api/leads/:id', requireAuth, (req, res) => {
  try {
    const lead = db.prepare('SELECT * FROM leads WHERE id = ?').get(req.params.id);
    if (!lead) return res.status(404).json({ success: false, error: 'Lead não encontrado' });
    
    res.json({
      success: true,
      lead: { ...lead, data: JSON.parse(lead.data || '{}') }
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Exportar CSV
app.get('/api/leads/export/csv', requireAuth, (req, res) => {
  try {
    const formId = req.query.form_id;
    let sql = 'SELECT * FROM leads';
    if (formId) sql += ' WHERE form_id = ?';
    sql += ' ORDER BY created_at DESC';
    
    const leads = formId ? db.prepare(sql).all(formId) : db.prepare(sql).all();
    if (!leads.length) return res.status(404).json({ error: 'Nenhum lead' });

    const allKeys = new Set();
    leads.forEach(l => Object.keys(JSON.parse(l.data || '{}')).forEach(k => allKeys.add(k)));

    const headers = ['id', 'form_name', 'created_at', ...allKeys, 'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'referrer', 'page_url', 'ip_address', 'device_type', 'browser', 'os'];
    let csv = headers.join(',') + '\n';
    
    leads.forEach(l => {
      const d = JSON.parse(l.data || '{}');
      csv += [
        l.id,
        '"' + (l.form_name || '').replace(/"/g, '""') + '"',
        l.created_at,
        ...Array.from(allKeys).map(k => '"' + (d[k] || '').toString().replace(/"/g, '""') + '"'),
        '"' + (l.utm_source || '') + '"',
        '"' + (l.utm_medium || '') + '"',
        '"' + (l.utm_campaign || '') + '"',
        '"' + (l.utm_term || '') + '"',
        '"' + (l.utm_content || '') + '"',
        '"' + (l.referrer || '') + '"',
        '"' + (l.page_url || '') + '"',
        '"' + (l.ip_address || '') + '"',
        '"' + (l.device_type || '') + '"',
        '"' + (l.browser || '') + '"',
        '"' + (l.os || '') + '"'
      ].join(',') + '\n';
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=leads-' + new Date().toISOString().slice(0,10) + '.csv');
    res.send('\uFEFF' + csv);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erro' });
  }
});

app.delete('/api/leads/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM leads WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Criar formulário com estilos
app.post('/api/forms', requireAuth, (req, res) => {
  try {
    const { name, fields, styles, settings, webhookUrl } = req.body;
    if (!name || !fields) {
      return res.status(400).json({ success: false, error: 'Nome e campos obrigatórios' });
    }

    const id = 'form_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    db.prepare('INSERT INTO forms (id, name, fields, styles, settings, webhook_url) VALUES (?, ?, ?, ?, ?, ?)').run(
      id, name, JSON.stringify(fields), JSON.stringify(styles || {}), JSON.stringify(settings || {}), webhookUrl || null
    );

    res.json({ success: true, formId: id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Atualizar formulário
app.put('/api/forms/:id', requireAuth, (req, res) => {
  try {
    const { name, fields, styles, settings, webhookUrl } = req.body;
    db.prepare('UPDATE forms SET name = ?, fields = ?, styles = ?, settings = ?, webhook_url = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(
      name, JSON.stringify(fields), JSON.stringify(styles || {}), JSON.stringify(settings || {}), webhookUrl || null, req.params.id
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

app.get('/api/forms', requireAuth, (req, res) => {
  try {
    const forms = db.prepare(`
      SELECT f.*, (SELECT COUNT(*) FROM leads WHERE form_id = f.id) as leads_count 
      FROM forms f WHERE f.active = 1 ORDER BY f.created_at DESC
    `).all();

    res.json({
      success: true,
      forms: forms.map(f => ({
        ...f,
        fields: JSON.parse(f.fields || '[]'),
        styles: JSON.parse(f.styles || '{}'),
        settings: JSON.parse(f.settings || '{}')
      }))
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

app.get('/api/forms/:id', requireAuth, (req, res) => {
  try {
    const form = db.prepare('SELECT * FROM forms WHERE id = ? AND active = 1').get(req.params.id);
    if (!form) return res.status(404).json({ success: false, error: 'Formulário não encontrado' });
    
    res.json({
      success: true,
      form: {
        ...form,
        fields: JSON.parse(form.fields || '[]'),
        styles: JSON.parse(form.styles || '{}'),
        settings: JSON.parse(form.settings || '{}')
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

app.delete('/api/forms/:id', requireAuth, (req, res) => {
  db.prepare('UPDATE forms SET active = 0 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Webhooks
app.post('/api/webhooks', requireAuth, (req, res) => {
  try {
    const { formId, url, isGlobal } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'URL obrigatória' });

    const result = db.prepare('INSERT INTO webhooks (form_id, url, is_global) VALUES (?, ?, ?)').run(formId || null, url, isGlobal ? 1 : 0);
    res.json({ success: true, webhookId: result.lastInsertRowid });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

app.get('/api/webhooks', requireAuth, (req, res) => {
  res.json({ success: true, webhooks: db.prepare('SELECT * FROM webhooks WHERE active = 1').all() });
});

app.delete('/api/webhooks/:id', requireAuth, (req, res) => {
  db.prepare('UPDATE webhooks SET active = 0 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Settings
app.get('/api/settings', requireAuth, (req, res) => {
  const settings = {};
  db.prepare('SELECT * FROM settings').all().forEach(s => settings[s.key] = s.value);
  res.json({ success: true, settings });
});

app.put('/api/settings', requireAuth, (req, res) => {
  const stmt = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  Object.entries(req.body).forEach(([k, v]) => stmt.run(k, v));
  res.json({ success: true });
});

// Stats avançados
app.get('/api/stats', requireAuth, (req, res) => {
  try {
    const totalLeads = db.prepare('SELECT COUNT(*) as c FROM leads').get().c;
    const totalForms = db.prepare('SELECT COUNT(*) as c FROM forms WHERE active = 1').get().c;
    const totalWebhooks = db.prepare('SELECT COUNT(*) as c FROM webhooks WHERE active = 1').get().c;
    const webhooksSent = db.prepare('SELECT COUNT(*) as c FROM leads WHERE webhook_sent = 1').get().c;
    
    // Leads por dia (últimos 7 dias)
    const leadsPerDay = db.prepare(`
      SELECT DATE(created_at) as date, COUNT(*) as count 
      FROM leads 
      WHERE created_at >= DATE('now', '-7 days')
      GROUP BY DATE(created_at)
      ORDER BY date
    `).all();
    
    // Top UTM sources
    const topSources = db.prepare(`
      SELECT utm_source, COUNT(*) as count 
      FROM leads 
      WHERE utm_source IS NOT NULL AND utm_source != ''
      GROUP BY utm_source 
      ORDER BY count DESC 
      LIMIT 5
    `).all();
    
    // Top campanhas
    const topCampaigns = db.prepare(`
      SELECT utm_campaign, COUNT(*) as count 
      FROM leads 
      WHERE utm_campaign IS NOT NULL AND utm_campaign != ''
      GROUP BY utm_campaign 
      ORDER BY count DESC 
      LIMIT 5
    `).all();
    
    // Dispositivos
    const devices = db.prepare(`
      SELECT device_type, COUNT(*) as count 
      FROM leads 
      WHERE device_type IS NOT NULL
      GROUP BY device_type
    `).all();

    res.json({
      success: true,
      stats: {
        totalLeads,
        totalForms,
        totalWebhooks,
        webhooksSent,
        leadsPerDay,
        topSources,
        topCampaigns,
        devices
      }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log('  v4 Forms rodando na porta ' + PORT);
  console.log('========================================');
  console.log('  Usuario: ' + ADMIN_USER);
  console.log('  Senha: ' + ADMIN_PASS);
  console.log('========================================');
});
