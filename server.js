const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DATABASE_PATH || './data/leads.db';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

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
  CREATE INDEX IF NOT EXISTS idx_leads_form_id ON leads(form_id);
  CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at);
`);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Receber lead
app.post('/api/leads', async (req, res) => {
  try {
    const { formId, formName, data } = req.body;
    if (!formId || !data) {
      return res.status(400).json({ success: false, error: 'formId e data obrigatórios' });
    }

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const stmt = db.prepare('INSERT INTO leads (form_id, form_name, data, ip_address) VALUES (?, ?, ?, ?)');
    const result = stmt.run(formId, formName || '', JSON.stringify(data), ip);
    const leadId = result.lastInsertRowid;

    // Enviar para webhooks
    const webhooks = db.prepare('SELECT url FROM webhooks WHERE (form_id = ? OR is_global = 1) AND active = 1').all(formId);
    let webhookSent = false;

    for (const wh of webhooks) {
      try {
        const response = await fetch(wh.url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            leadId,
            formId,
            formName,
            data,
            receivedAt: new Date().toISOString()
          })
        });
        if (response.ok) webhookSent = true;
      } catch (e) {
        console.error('Webhook error:', e.message);
      }
    }

    if (webhookSent) {
      db.prepare('UPDATE leads SET webhook_sent = 1 WHERE id = ?').run(leadId);
    }

    res.json({ success: true, leadId, webhookSent });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Listar leads
app.get('/api/leads', (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    const leads = db.prepare('SELECT * FROM leads ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset);
    const { total } = db.prepare('SELECT COUNT(*) as total FROM leads').get();

    res.json({
      success: true,
      leads: leads.map(l => ({ ...l, data: JSON.parse(l.data) })),
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Exportar CSV
app.get('/api/leads/export/csv', (req, res) => {
  try {
    const leads = db.prepare('SELECT * FROM leads ORDER BY created_at DESC').all();
    if (!leads.length) return res.status(404).json({ error: 'Nenhum lead' });

    const allKeys = new Set();
    leads.forEach(l => Object.keys(JSON.parse(l.data)).forEach(k => allKeys.add(k)));

    let csv = ['id', 'form_id', 'form_name', 'created_at', ...allKeys].join(',') + '\n';
    leads.forEach(l => {
      const d = JSON.parse(l.data);
      csv += [
        l.id,
        l.form_id,
        '"' + (l.form_name || '') + '"',
        l.created_at,
        ...Array.from(allKeys).map(k => '"' + (d[k] || '').toString().replace(/"/g, '""') + '"')
      ].join(',') + '\n';
    });

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename=leads.csv');
    res.send('\uFEFF' + csv);
  } catch (e) {
    res.status(500).json({ error: 'Erro' });
  }
});

// Deletar lead
app.delete('/api/leads/:id', (req, res) => {
  db.prepare('DELETE FROM leads WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Criar formulário
app.post('/api/forms', (req, res) => {
  try {
    const { name, fields, webhookUrl } = req.body;
    if (!name || !fields) {
      return res.status(400).json({ success: false, error: 'Nome e campos obrigatórios' });
    }

    const id = 'form_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    db.prepare('INSERT INTO forms (id, name, fields, webhook_url) VALUES (?, ?, ?, ?)').run(id, name, JSON.stringify(fields), webhookUrl || null);

    res.json({ success: true, formId: id });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Listar formulários
app.get('/api/forms', (req, res) => {
  try {
    const forms = db.prepare(`
      SELECT f.*, (SELECT COUNT(*) FROM leads WHERE form_id = f.id) as leads_count 
      FROM forms f WHERE f.active = 1 ORDER BY f.created_at DESC
    `).all();

    res.json({
      success: true,
      forms: forms.map(f => ({ ...f, fields: JSON.parse(f.fields) }))
    });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Deletar formulário
app.delete('/api/forms/:id', (req, res) => {
  db.prepare('UPDATE forms SET active = 0 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Criar webhook
app.post('/api/webhooks', (req, res) => {
  try {
    const { formId, url, isGlobal } = req.body;
    if (!url) return res.status(400).json({ success: false, error: 'URL obrigatória' });

    const result = db.prepare('INSERT INTO webhooks (form_id, url, is_global) VALUES (?, ?, ?)').run(formId || null, url, isGlobal ? 1 : 0);
    res.json({ success: true, webhookId: result.lastInsertRowid });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Erro interno' });
  }
});

// Listar webhooks
app.get('/api/webhooks', (req, res) => {
  res.json({ success: true, webhooks: db.prepare('SELECT * FROM webhooks WHERE active = 1').all() });
});

// Deletar webhook
app.delete('/api/webhooks/:id', (req, res) => {
  db.prepare('UPDATE webhooks SET active = 0 WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Settings
app.get('/api/settings', (req, res) => {
  const settings = {};
  db.prepare('SELECT * FROM settings').all().forEach(s => settings[s.key] = s.value);
  res.json({ success: true, settings });
});

app.put('/api/settings', (req, res) => {
  const stmt = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  Object.entries(req.body).forEach(([k, v]) => stmt.run(k, v));
  res.json({ success: true });
});

// Stats
app.get('/api/stats', (req, res) => {
  try {
    res.json({
      success: true,
      stats: {
        totalLeads: db.prepare('SELECT COUNT(*) as c FROM leads').get().c,
        totalForms: db.prepare('SELECT COUNT(*) as c FROM forms WHERE active = 1').get().c,
        totalWebhooks: db.prepare('SELECT COUNT(*) as c FROM webhooks WHERE active = 1').get().c,
        webhooksSent: db.prepare('SELECT COUNT(*) as c FROM leads WHERE webhook_sent = 1').get().c
      }
    });
  } catch (e) {
    res.status(500).json({ success: false });
  }
});

// Fallback para SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('========================================');
  console.log('  Barosac Forms rodando na porta ' + PORT);
  console.log('========================================');
});
