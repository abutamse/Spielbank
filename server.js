// Spielbank & Marktplatz — backend server
// Talks to Neon Postgres, exposes ONE generic, whitelisted query endpoint
// that the frontend's `db` shim (in the HTML file) calls into.
//
// SECURITY NOTE: like the original Supabase-anon-key setup this replaces,
// this API has no per-user auth check on top of it — anyone with the URL
// can read/write these 5 tables (that mirrors how the app already worked,
// including plaintext passwords used as pairing codes). Fine for a private
// game/party app among friends; do NOT reuse this pattern for anything
// handling real money or sensitive data.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json({ limit: '8mb' })); // product images are base64, can be a few hundred KB

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Neon requires SSL
});

// ── Whitelist: table -> allowed columns, and which ones are jsonb ──────────
const TABLES = {
  accounts: {
    columns: ['id', 'name', 'password', 'balance', 'connections', 'created_at'],
    jsonb: ['connections']
  },
  transactions: {
    columns: ['id', 'from_user', 'to_user', 'amount', 'note', 'created_at'],
    jsonb: []
  },
  products: {
    columns: ['id', 'seller', 'name', 'category', 'price', 'stock', 'description', 'image_data', 'active', 'created_at'],
    jsonb: []
  },
  inventory: {
    columns: ['id', 'owner', 'name', 'category', 'product_id', 'price_paid', 'image_data', 'uses_left', 'max_uses', 'active', 'created_at'],
    jsonb: []
  },
  payment_requests: {
    columns: ['id', 'from_user', 'to_user', 'amount', 'items', 'status', 'created_at'],
    jsonb: ['items']
  }
};

function qid(name) {
  // Safe identifier quoting for a name we've already checked is in our whitelist
  return '"' + name.replace(/"/g, '') + '"';
}

// Builds "col1 = $1 AND col2 = ANY($2) ..." from filters + an optional
// PostgREST-style or-string like "col.eq.val,col2.eq.val2"
function buildWhere(tableDef, filters, orFilter, params) {
  const clauses = [];
  for (const f of filters || []) {
    if (!tableDef.columns.includes(f.col)) throw badRequest('Ungültige Spalte: ' + f.col);
    if (f.op === 'eq') {
      params.push(f.val);
      clauses.push(`${qid(f.col)} = $${params.length}`);
    } else if (f.op === 'in') {
      params.push(Array.isArray(f.val) ? f.val : [f.val]);
      clauses.push(`${qid(f.col)} = ANY($${params.length})`);
    } else {
      throw badRequest('Nicht unterstützter Operator: ' + f.op);
    }
  }
  let sql = clauses.length ? clauses.join(' AND ') : null;

  if (orFilter) {
    const orClauses = [];
    for (const part of String(orFilter).split(',')) {
      const m = part.match(/^([a-zA-Z0-9_]+)\.eq\.(.*)$/);
      if (!m) continue;
      const [, col, val] = m;
      if (!tableDef.columns.includes(col)) throw badRequest('Ungültige Spalte: ' + col);
      params.push(val);
      orClauses.push(`${qid(col)} = $${params.length}`);
    }
    if (orClauses.length) {
      const orSql = '(' + orClauses.join(' OR ') + ')';
      sql = sql ? `${sql} AND ${orSql}` : orSql;
    }
  }
  return sql;
}

function badRequest(message) {
  const err = new Error(message);
  err.status = 400;
  return err;
}

app.post('/api/query', async (req, res) => {
  const { table, action, filters, orFilter, order, limit, single, values } = req.body || {};
  const tableDef = TABLES[table];
  if (!tableDef) return res.status(400).json({ error: { message: 'Unbekannte Tabelle: ' + table } });

  try {
    if (action === 'select' || !action) {
      const params = [];
      const where = buildWhere(tableDef, filters, orFilter, params);
      let sql = `SELECT * FROM ${qid(table)}`;
      if (where) sql += ` WHERE ${where}`;
      if (order && tableDef.columns.includes(order.col)) {
        sql += ` ORDER BY ${qid(order.col)} ${order.ascending ? 'ASC' : 'DESC'}`;
      }
      if (limit && Number.isFinite(Number(limit))) {
        sql += ` LIMIT ${Math.max(0, Math.min(1000, parseInt(limit, 10)))}`;
      }
      const result = await pool.query(sql, params);
      if (single) return res.json({ data: result.rows[0] || null });
      return res.json({ data: result.rows });
    }

    if (action === 'insert') {
      let rows = Array.isArray(values) ? values : [values];
      if (!rows.length) return res.json({ data: [] });
      // Union of columns actually used across all rows in this batch
      const colSet = new Set();
      rows.forEach(r => Object.keys(r || {}).forEach(k => { if (tableDef.columns.includes(k)) colSet.add(k); }));
      const cols = Array.from(colSet);
      if (!cols.length) throw badRequest('Keine gültigen Spalten zum Einfügen.');

      const params = [];
      const valueTuples = rows.map(row => {
        const placeholders = cols.map(c => {
          params.push(row[c] === undefined ? null : row[c]);
          const ph = `$${params.length}`;
          return tableDef.jsonb.includes(c) ? `${ph}::jsonb` : ph;
        });
        return `(${placeholders.join(', ')})`;
      });

      const sql = `INSERT INTO ${qid(table)} (${cols.map(qid).join(', ')}) VALUES ${valueTuples.join(', ')} RETURNING *`;
      const result = await pool.query(sql, params);
      if (single) return res.json({ data: result.rows[0] || null });
      return res.json({ data: result.rows });
    }

    if (action === 'update') {
      if (!values || typeof values !== 'object') throw badRequest('Keine Werte zum Aktualisieren.');
      const params = [];
      const setClauses = Object.keys(values)
        .filter(k => tableDef.columns.includes(k))
        .map(k => {
          params.push(values[k]);
          const ph = `$${params.length}`;
          return `${qid(k)} = ${tableDef.jsonb.includes(k) ? `${ph}::jsonb` : ph}`;
        });
      if (!setClauses.length) throw badRequest('Keine gültigen Spalten zum Aktualisieren.');

      const where = buildWhere(tableDef, filters, orFilter, params);
      if (!where) throw badRequest('Update ohne Filter ist nicht erlaubt.');

      const sql = `UPDATE ${qid(table)} SET ${setClauses.join(', ')} WHERE ${where} RETURNING *`;
      const result = await pool.query(sql, params);
      if (single) return res.json({ data: result.rows[0] || null });
      return res.json({ data: result.rows });
    }

    if (action === 'delete') {
      const params = [];
      const where = buildWhere(tableDef, filters, orFilter, params);
      if (!where) throw badRequest('Delete ohne Filter ist nicht erlaubt.');
      const sql = `DELETE FROM ${qid(table)} WHERE ${where} RETURNING *`;
      const result = await pool.query(sql, params);
      return res.json({ data: result.rows });
    }

    return res.status(400).json({ error: { message: 'Unbekannte Aktion: ' + action } });
  } catch (e) {
    const status = e.status || 500;
    // Pass through Postgres error codes (e.g. 23505 = unique_violation) so the
    // frontend's existing `if (error.code === '23505')` checks keep working.
    return res.status(status).json({ error: { message: e.message, code: e.code } });
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Spielbank server listening on port ' + PORT));
