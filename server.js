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

app.use(cors({ origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.use(express.json({ limit: '10mb' }));
app.use((req, res, next) => { res.setHeader('Content-Type', 'application/json; charset=utf-8'); next(); });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS companies (id TEXT PRIMARY KEY, name TEXT NOT NULL, logo TEXT, color TEXT DEFAULT '#ef4444', webhook_url TEXT, active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS leads (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT, form_id TEXT NOT NULL, form_name TEXT, data TEXT NOT NULL, ip_address TEXT, webhook_sent INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS forms (id TEXT PRIMARY KEY, company_id TEXT, name TEXT NOT NULL, fields TEXT NOT NULL, webhook_url TEXT, active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS webhooks (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id TEXT, form_id TEXT, url TEXT NOT NULL, is_global INTEGER DEFAULT 0, active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
`);

// Migrations
const addCol = (t, c, type = 'TEXT') => { try { db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${type}`); } catch (e) {} };
['utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content', 'utm_id', 'referrer', 'page_url', 'user_agent', 'device_type', 'browser', 'os', 'webhook_response', 'company_id'].forEach(c => addCol('leads', c));
['styles', 'settings', 'updated_at', 'company_id', 'form_type', 'custom_html'].forEach(c => addCol('forms', c));
addCol('webhooks', 'last_triggered'); addCol('webhooks', 'success_count', 'INTEGER DEFAULT 0'); addCol('webhooks', 'fail_count', 'INTEGER DEFAULT 0'); addCol('webhooks', 'company_id');
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_leads_company ON leads(company_id)`); } catch (e) {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_forms_company ON forms(company_id)`); } catch (e) {}

// Helpers
function parseUA(ua) {
  if (!ua) return { device: 'unknown', browser: 'unknown', os: 'unknown' };
  let device = /mobile/i.test(ua) ? 'mobile' : /tablet|ipad/i.test(ua) ? 'tablet' : 'desktop';
  let browser = /chrome/i.test(ua) && !/edge/i.test(ua) ? 'Chrome' : /firefox/i.test(ua) ? 'Firefox' : /safari/i.test(ua) && !/chrome/i.test(ua) ? 'Safari' : /edge/i.test(ua) ? 'Edge' : 'other';
  let os = /windows/i.test(ua) ? 'Windows' : /macintosh/i.test(ua) ? 'MacOS' : /linux/i.test(ua) ? 'Linux' : /android/i.test(ua) ? 'Android' : /iphone|ipad/i.test(ua) ? 'iOS' : 'other';
  return { device, browser, os };
}
async function sendWebhook(url, data) {
  try {
    const c = new AbortController(); const t = setTimeout(() => c.abort(), 10000);
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data), signal: c.signal });
    clearTimeout(t); return { success: r.ok, status: r.status };
  } catch (e) { return { success: false, error: e.message }; }
}
const genId = () => 'f_' + crypto.randomBytes(8).toString('hex');
const genCompanyId = () => 'c_' + crypto.randomBytes(6).toString('hex');

// Auth
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  const tokenFromQuery = req.query.token;
  let token = null;
  if (auth && auth.startsWith('Bearer ')) token = auth.slice(7);
  else if (tokenFromQuery) token = tokenFromQuery;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  if (!sessions.has(token)) return res.status(401).json({ error: 'Invalid session' });
  req.session = sessions.get(token); next();
}
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { user: username, created: Date.now() });
    res.json({ success: true, token });
  } else res.status(401).json({ success: false });
});
app.post('/api/logout', requireAuth, (req, res) => { sessions.delete(req.headers.authorization.slice(7)); res.json({ success: true }); });
app.get('/api/session', requireAuth, (req, res) => { res.json({ authenticated: true, user: req.session.user }); });

// Companies
app.get('/api/companies', requireAuth, (req, res) => {
  try {
    const companies = db.prepare(`SELECT c.*, (SELECT COUNT(*) FROM forms WHERE company_id = c.id AND active=1) as forms_count, (SELECT COUNT(*) FROM leads WHERE company_id = c.id) as leads_count FROM companies c WHERE c.active = 1 ORDER BY c.name`).all();
    res.json({ companies });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/companies', requireAuth, (req, res) => {
  try {
    const { name, logo, color, webhook_url } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const id = genCompanyId();
    db.prepare('INSERT INTO companies (id, name, logo, color, webhook_url) VALUES (?, ?, ?, ?, ?)').run(id, name, logo || null, color || '#ef4444', webhook_url || null);
    res.json({ success: true, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/companies/:id', requireAuth, (req, res) => {
  try {
    const { name, logo, color, webhook_url } = req.body;
    db.prepare('UPDATE companies SET name = ?, logo = ?, color = ?, webhook_url = ? WHERE id = ?').run(name, logo, color, webhook_url, req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/companies/:id', requireAuth, (req, res) => {
  try { db.prepare('UPDATE companies SET active = 0 WHERE id = ?').run(req.params.id); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/companies/:id/stats', requireAuth, (req, res) => {
  try {
    const cid = req.params.id;
    const stats = {
      totalLeads: db.prepare('SELECT COUNT(*) as c FROM leads WHERE company_id = ?').get(cid)?.c || 0,
      totalForms: db.prepare('SELECT COUNT(*) as c FROM forms WHERE company_id = ? AND active = 1').get(cid)?.c || 0,
      leadsToday: db.prepare("SELECT COUNT(*) as c FROM leads WHERE company_id = ? AND date(created_at) = date('now')").get(cid)?.c || 0,
      leadsWeek: db.prepare("SELECT COUNT(*) as c FROM leads WHERE company_id = ? AND created_at >= date('now', '-7 days')").get(cid)?.c || 0,
      leadsPerDay: db.prepare(`SELECT date(created_at) as date, COUNT(*) as count FROM leads WHERE company_id = ? AND created_at >= date('now', '-7 days') GROUP BY date(created_at) ORDER BY date`).all(cid),
      topSources: db.prepare(`SELECT utm_source as source, COUNT(*) as count FROM leads WHERE company_id = ? AND utm_source IS NOT NULL GROUP BY utm_source ORDER BY count DESC LIMIT 5`).all(cid),
    };
    res.json({ stats });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Forms
app.get('/api/forms', requireAuth, (req, res) => {
  try {
    const { company_id } = req.query;
    let q = `SELECT f.*, (SELECT COUNT(*) FROM leads WHERE form_id = f.id) as leads_count FROM forms f WHERE f.active = 1`;
    const p = [];
    if (company_id) { q += ' AND f.company_id = ?'; p.push(company_id); }
    q += ' ORDER BY f.created_at DESC';
    const forms = db.prepare(q).all(...p);
    forms.forEach(f => {
      try { f.fields = JSON.parse(f.fields); } catch (e) { f.fields = []; }
      try { f.styles = JSON.parse(f.styles); } catch (e) { f.styles = {}; }
      try { f.settings = JSON.parse(f.settings); } catch (e) { f.settings = {}; }
    });
    res.json({ forms });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/forms', requireAuth, (req, res) => {
  try {
    const { name, fields, styles, settings, webhookUrl, company_id, form_type, custom_html } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const id = genId();
    db.prepare(`INSERT INTO forms (id, company_id, name, fields, styles, settings, webhook_url, form_type, custom_html) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, company_id || null, name, JSON.stringify(fields || []), JSON.stringify(styles || {}), JSON.stringify(settings || {}), webhookUrl || null, form_type || 'builder', custom_html || null);
    res.json({ success: true, id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/forms/:id', requireAuth, (req, res) => {
  try {
    const { name, fields, styles, settings, webhookUrl, company_id, custom_html } = req.body;
    db.prepare(`UPDATE forms SET name = ?, fields = ?, styles = ?, settings = ?, webhook_url = ?, company_id = ?, custom_html = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`).run(name, JSON.stringify(fields || []), JSON.stringify(styles || {}), JSON.stringify(settings || {}), webhookUrl || null, company_id || null, custom_html || null, req.params.id);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/forms/:id', requireAuth, (req, res) => {
  try { db.prepare('UPDATE forms SET active = 0 WHERE id = ?').run(req.params.id); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Leads
app.get('/api/leads', requireAuth, (req, res) => {
  try {
    const { company_id, form_id, utm_source, limit = 100, offset = 0 } = req.query;
    let q = 'SELECT * FROM leads WHERE 1=1'; const p = [];
    if (company_id) { q += ' AND company_id = ?'; p.push(company_id); }
    if (form_id) { q += ' AND form_id = ?'; p.push(form_id); }
    if (utm_source) { q += ' AND utm_source = ?'; p.push(utm_source); }
    q += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'; p.push(parseInt(limit), parseInt(offset));
    const leads = db.prepare(q).all(...p);
    leads.forEach(l => { try { l.data = JSON.parse(l.data); } catch (e) { l.data = {}; } });
    res.json({ leads });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/leads', (req, res) => {
  try {
    const { formId, formName, data, meta = {} } = req.body;
    if (!formId || !data) return res.status(400).json({ error: 'formId and data required' });
    const form = db.prepare('SELECT * FROM forms WHERE id = ?').get(formId);
    const ua = parseUA(req.headers['user-agent']);
    const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket?.remoteAddress || null;
    const result = db.prepare(`INSERT INTO leads (company_id, form_id, form_name, data, utm_source, utm_medium, utm_campaign, utm_term, utm_content, utm_id, referrer, page_url, ip_address, user_agent, device_type, browser, os) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(form?.company_id || null, formId, formName || form?.name || 'Form', JSON.stringify(data), meta.utm_source || null, meta.utm_medium || null, meta.utm_campaign || null, meta.utm_term || null, meta.utm_content || null, meta.utm_id || null, meta.referrer || null, meta.page_url || null, ip, req.headers['user-agent'] || null, ua.device, ua.browser, ua.os);
    const leadId = result.lastInsertRowid;
    const whData = { event: 'new_lead', lead_id: leadId, form_id: formId, form_name: formName || form?.name, company_id: form?.company_id, data, meta: { ...meta, ip, ...ua }, timestamp: new Date().toISOString() };
    if (form?.webhook_url) sendWebhook(form.webhook_url, whData).then(r => db.prepare('UPDATE leads SET webhook_sent = ?, webhook_response = ? WHERE id = ?').run(r.success ? 1 : 0, JSON.stringify(r), leadId));
    if (form?.company_id) { const co = db.prepare('SELECT webhook_url FROM companies WHERE id = ?').get(form.company_id); if (co?.webhook_url) sendWebhook(co.webhook_url, whData); }
    db.prepare('SELECT * FROM webhooks WHERE is_global = 1 AND active = 1').all().forEach(h => sendWebhook(h.url, whData).then(r => db.prepare(r.success ? 'UPDATE webhooks SET success_count = success_count + 1, last_triggered = CURRENT_TIMESTAMP WHERE id = ?' : 'UPDATE webhooks SET fail_count = fail_count + 1 WHERE id = ?').run(h.id)));
    res.json({ success: true, id: leadId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/leads/all', requireAuth, (req, res) => {
  try {
    const { company_id } = req.query;
    let result;
    if (company_id) {
      result = db.prepare('DELETE FROM leads WHERE company_id = ?').run(company_id);
    } else {
      result = db.prepare('DELETE FROM leads').run();
    }
    res.json({ success: true, deleted: result.changes });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/leads/delete-batch', requireAuth, (req, res) => {
  try {
    const { ids } = req.body;
    if (!ids || !ids.length) return res.status(400).json({ error: 'No IDs provided' });
    const placeholders = ids.map(() => '?').join(',');
    const result = db.prepare(`DELETE FROM leads WHERE id IN (${placeholders})`).run(...ids);
    res.json({ success: true, deleted: result.changes });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/leads/:id', requireAuth, (req, res) => {
  try { db.prepare('DELETE FROM leads WHERE id = ?').run(req.params.id); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/leads/export/csv', requireAuth, (req, res) => {
  try {
    const { company_id } = req.query;
    let q = 'SELECT * FROM leads'; const p = [];
    if (company_id) { q += ' WHERE company_id = ?'; p.push(company_id); }
    q += ' ORDER BY created_at DESC';
    const leads = db.prepare(q).all(...p);
    const h = ['ID', 'Empresa', 'Formulário', 'Nome', 'Email', 'Telefone', 'UTM Source', 'UTM Medium', 'UTM Campaign', 'IP', 'Device', 'Browser', 'OS', 'Data'];
    let csv = '\uFEFF' + h.join(';') + '\n';
    leads.forEach(l => { let d = {}; try { d = JSON.parse(l.data); } catch (e) {} csv += [l.id, l.company_id || '', l.form_name || '', d.nome || d.name || '', d.email || '', d.telefone || d.phone || '', l.utm_source || '', l.utm_medium || '', l.utm_campaign || '', l.ip_address || '', l.device_type || '', l.browser || '', l.os || '', l.created_at].map(v => `"${String(v).replace(/"/g, '""')}"`).join(';') + '\n'; });
    res.setHeader('Content-Type', 'text/csv; charset=utf-8'); res.setHeader('Content-Disposition', 'attachment; filename=leads.csv'); res.send(csv);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Webhooks
app.get('/api/webhooks', requireAuth, (req, res) => {
  try {
    const { company_id } = req.query;
    let q = 'SELECT * FROM webhooks WHERE active = 1'; const p = [];
    if (company_id) { q += ' AND (company_id = ? OR is_global = 1)'; p.push(company_id); }
    res.json({ webhooks: db.prepare(q).all(...p) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/webhooks', requireAuth, (req, res) => {
  try {
    const { url, formId, isGlobal, company_id } = req.body;
    if (!url) return res.status(400).json({ error: 'URL required' });
    db.prepare('INSERT INTO webhooks (url, form_id, is_global, company_id) VALUES (?, ?, ?, ?)').run(url, formId || null, isGlobal ? 1 : 0, company_id || null);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/webhooks/:id', requireAuth, (req, res) => {
  try { db.prepare('UPDATE webhooks SET active = 0 WHERE id = ?').run(req.params.id); res.json({ success: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Stats
app.get('/api/stats', requireAuth, (req, res) => {
  try {
    const { company_id } = req.query;
    let lq = 'SELECT COUNT(*) as c FROM leads', fq = 'SELECT COUNT(*) as c FROM forms WHERE active = 1';
    if (company_id) { lq += ' WHERE company_id = ?'; fq += ' AND company_id = ?'; }
    const stats = {
      totalLeads: db.prepare(lq).get(...(company_id ? [company_id] : []))?.c || 0,
      totalForms: db.prepare(fq).get(...(company_id ? [company_id] : []))?.c || 0,
      totalWebhooks: db.prepare('SELECT COUNT(*) as c FROM webhooks WHERE active = 1').get()?.c || 0,
      totalCompanies: db.prepare('SELECT COUNT(*) as c FROM companies WHERE active = 1').get()?.c || 0,
      webhooksSent: db.prepare('SELECT COUNT(*) as c FROM leads WHERE webhook_sent = 1').get()?.c || 0,
    };
    res.json({ stats });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Static
app.use(express.static(path.join(__dirname, 'public'), { setHeaders: (res, filePath) => { if (filePath.endsWith('.html')) res.setHeader('Content-Type', 'text/html; charset=utf-8'); } }));
app.get('*', (req, res) => { if (!req.path.startsWith('/api')) res.sendFile(path.join(__dirname, 'public', 'index.html')); });

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n========================================\n  v4 Forms rodando na porta ${PORT}\n  Usuario: ${ADMIN_USER}\n  Senha: ${ADMIN_PASS}\n========================================\n`);
});
