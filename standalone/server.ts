// Vetor — servidor standalone da loja fictícia de eletrônicos.
//
// Roda FORA do runtime do Muse: basta Bun (bun:sqlite + node:crypto,
// zero dependências de npm). Serve o cliente pré-compilado em ./public e
// responde às mesmas chamadas RPC que a versão do Muse usa:
//
//   POST /actions   { "action": "<nome>", "args": { ... } }
//     sucesso → 200 { "data": ... }
//     erro    → 400 { "error": { "message": "..." } }
//
// Segurança idêntica à versão do Muse: senhas com PBKDF2 (120 mil
// iterações, SHA-256, sal aleatório), token de sessão aleatório guardado
// como SHA-256, bloqueio de 15 min após 5 logins errados, erro de login
// genérico (não revela se a conta existe), log de auditoria e todas as
// consultas parametrizadas.
//
// Banco: SQLite local. No plano grátis do Render o disco é apagado quando
// o serviço dorme, então a cada boot o servidor confere o banco e, se ele
// estiver vazio, recria tudo: catálogo, conta admin (mesmo hash da seed
// original — a senha em texto puro não existe em nenhum arquivo) e os
// compradores/pedidos simulados.

import { Database } from "bun:sqlite";
import { createHash, pbkdf2Sync, randomBytes, timingSafeEqual } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, extname, join, normalize } from "node:path";

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------

const PORT = Number(process.env.PORT ?? 3000);
const HOST = process.env.HOST ?? "0.0.0.0";
const DB_PATH = process.env.DATABASE_PATH ?? join(import.meta.dir, "data", "vetor.db");
const PUBLIC_DIR = join(import.meta.dir, "public");

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_MINUTES = 15;
const SESSION_HOURS = 12;
const PBKDF2_ITERATIONS = 120_000;
const MAX_BODY_BYTES = 1_000_000;

// ---------------------------------------------------------------------------
// Cripto — parâmetros idênticos aos da versão do Muse (privileged.ts)
// ---------------------------------------------------------------------------

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const hash = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256").toString("hex");
  return `${salt}$${hash}`;
}

function verifyPassword(password: string, stored: string): boolean {
  const [salt, expected] = stored.split("$");
  if (!salt || !expected) return false;
  const actual = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, 32, "sha256");
  const expectedBuf = Buffer.from(expected, "hex");
  return actual.length === expectedBuf.length && timingSafeEqual(actual, expectedBuf);
}

function newSessionToken(): { token: string; tokenHash: string } {
  const token = randomBytes(32).toString("hex");
  return { token, tokenHash: createHash("sha256").update(token).digest("hex") };
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

// ---------------------------------------------------------------------------
// Banco de dados + seed (re-semeadura a cada boot em banco vazio)
// ---------------------------------------------------------------------------

mkdirSync(dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH, { create: true });
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer',
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash TEXT NOT NULL UNIQUE,
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  price_cents INTEGER NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0,
  hue INTEGER NOT NULL DEFAULT 160,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cart_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  qty INTEGER NOT NULL DEFAULT 1,
  UNIQUE(user_id, product_id)
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  total_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pago',
  payment TEXT NOT NULL,
  address TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL REFERENCES orders(id),
  product_id INTEGER NOT NULL REFERENCES products(id),
  product_name TEXT NOT NULL,
  unit_price_cents INTEGER NOT NULL,
  qty INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS pentest_progress (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  step_key TEXT NOT NULL,
  done INTEGER NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  UNIQUE(user_id, step_key)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  step_key TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL
);
`;

// Catálogo e conta admin: EXATAMENTE os mesmos dados da seed original do
// Muse (drizzle/0002), incluindo o hash da senha do admin. A senha em
// texto puro não aparece aqui nem em nenhum outro lugar — por design do
// cenário black-box, ela é secreta.
const SEED_EPOCH = 1795200000000;

const CATALOG: Array<[string, string, string, number, number, number]> = [
  ['Notebook Vetor Pro 14"', "Computadores", "Intel Core i7, 16 GB de RAM, SSD de 512 GB e tela IPS Full HD. Chassi de alumínio, 1,4 kg.", 429900, 12, 160],
  ["Smartphone Vetor X2 256 GB", "Celulares", 'Tela AMOLED de 6,5", câmera de 108 MP, 5G e bateria de 5.000 mAh com carga rápida.', 219900, 30, 200],
  ["Fone Bluetooth com cancelamento de ruído", "Áudio", "Até 38 h de bateria, Bluetooth 5.3, microfones para chamadas e modo ambiente.", 34990, 58, 265],
  ['Monitor 27" 4K IPS', "Computadores", "Painel IPS 4K, 99% sRGB, HDR400, HDMI 2.1 e DisplayPort. Ajuste de altura e rotação.", 189900, 9, 210],
  ["Teclado mecânico RGB ABNT2", "Acessórios", "Switches hot-swap, keycaps PBT, conexão USB-C removível e layout ABNT2 completo.", 28990, 44, 330],
  ["Mouse sem fio ergonômico", "Acessórios", "Sensor de 4.000 DPI, bateria para 70 dias e formato anatômico para destros.", 15990, 73, 25],
  ["Console portátil retrô 512 GB", "Games", 'Tela de 7", saída HDMI, Wi-Fi e bateria de 6 h. Acompanha estojo de transporte.', 89900, 15, 285],
  ["Smartwatch Série 5 GPS", "Vestíveis", "GPS integrado, monitor de sono e oxigênio no sangue, resistente a 5 ATM.", 109900, 21, 350],
  ["Caixa de som inteligente 360°", "Áudio", "Som omnidirecional, assistente de voz, Wi-Fi e Bluetooth, entrada auxiliar.", 44900, 36, 180],
  ["SSD NVMe 1 TB Gen4", "Computadores", "Leitura de até 7.300 MB/s, escrita de 6.000 MB/s, formato M.2 2280.", 54990, 27, 230],
  ["Câmera de ação 4K à prova d'água", "Fotografia", "4K a 60 fps, estabilização eletrônica, submersível até 10 m sem case.", 129900, 8, 45],
  ["Carregador rápido USB-C 65 W", "Acessórios", "GaN, duas portas USB-C e uma USB-A, cabo trançado de 1,5 m incluso.", 12990, 120, 140],
];

// Compradores simulados (clientes fictícios da loja, com pedidos abaixo).
// As senhas deles são senhas de demonstração de contas fictícias e ficam
// documentadas no README.md deste pacote — diferente da senha do admin,
// que continua secreta.
const DEMO_CUSTOMERS = [
  { name: "Marina Duarte", email: "marina.duarte@exemplo.com", password: "marina2026", address: "Rua das Flores, 123 - Centro, Rio de Janeiro/RJ, CEP 20040-020" },
  { name: "Paulo Henrique Santos", email: "paulo.santos@exemplo.com", password: "paulo2026", address: "Av. Paulista, 1500 - Bela Vista, São Paulo/SP, CEP 01310-100" },
  { name: "Juliana Castro", email: "juliana.castro@exemplo.com", password: "juliana2026", address: "Rua Pernambuco, 480 - Savassi, Belo Horizonte/MG, CEP 30130-151" },
  { name: "Roberto Almeida", email: "roberto.almeida@exemplo.com", password: "roberto2026", address: "Av. Sete de Setembro, 2100 - Centro, Curitiba/PR, CEP 80060-010" },
];

function seedIfEmpty() {
  db.exec(SCHEMA_SQL);
  const row = db.query("SELECT COUNT(*) AS n FROM users").get() as { n: number };
  if (row.n > 0) return;

  const now = Date.now();
  const insertUser = db.query(
    "INSERT INTO users (name, email, password_hash, role, failed_attempts, locked_until, created_at) VALUES (?, ?, ?, ?, 0, NULL, ?) RETURNING id",
  );
  const insertProduct = db.query(
    "INSERT INTO products (name, category, description, price_cents, stock, hue, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  );
  const insertAudit = db.query(
    "INSERT INTO audit_log (user_id, email, event, detail, created_at) VALUES (?, ?, ?, ?, ?)",
  );
  const insertOrder = db.query(
    "INSERT INTO orders (user_id, total_cents, status, payment, address, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
  );
  const insertItem = db.query(
    "INSERT INTO order_items (order_id, product_id, product_name, unit_price_cents, qty) VALUES (?, ?, ?, ?, ?)",
  );
  const decStock = db.query("UPDATE products SET stock = stock - ? WHERE id = ?");

  db.transaction(() => {
    // Conta admin — mesmo hash da seed original (a senha NÃO está aqui).
    insertUser.get(
      "Administração Vetor",
      "admin@vetorloja.com.br",
      "e7095e7e77d5df7d73f157860fff6ed1$4cd74560e6face726eb8cb5fefaa3b797e490c017e38fdbc644320e78a995d6e",
      "admin",
      SEED_EPOCH,
    );

    const productIds: number[] = [];
    for (const [name, category, description, priceCents, stock, hue] of CATALOG) {
      const info = insertProduct.run(name, category, description, priceCents, stock, hue, SEED_EPOCH);
      productIds.push(Number(info.lastInsertRowid));
    }
    const priceOf = (idx: number) => CATALOG[idx]![3];
    const nameOf = (idx: number) => CATALOG[idx]![0];

    // Compradores simulados + pedidos simulados (datas relativas ao boot,
    // para o painel admin sempre mostrar movimento recente).
    const DAY = 86_400_000;
    const demoOrders: Array<{
      customer: number;
      items: Array<[number, number]>;
      status: string;
      payment: string;
      daysAgo: number;
    }> = [
      { customer: 0, items: [[0, 1]], status: "entregue", payment: "Pix", daysAgo: 6 },
      { customer: 0, items: [[2, 1], [11, 1]], status: "pago", payment: "Cartão de crédito", daysAgo: 1 },
      { customer: 1, items: [[9, 1]], status: "enviado", payment: "Boleto", daysAgo: 3 },
      { customer: 2, items: [[7, 1], [5, 1]], status: "entregue", payment: "Pix", daysAgo: 9 },
      { customer: 3, items: [[6, 1]], status: "pago", payment: "Cartão de crédito", daysAgo: 2 },
    ];

    const customerIds: number[] = [];
    DEMO_CUSTOMERS.forEach((c, i) => {
      const created = now - (12 - i * 2) * DAY;
      const u = insertUser.get(c.name, c.email, hashPassword(c.password), "customer", created) as { id: number };
      customerIds.push(u.id);
      insertAudit.run(u.id, c.email, "cadastro", "Conta de cliente criada", created);
    });

    for (const o of demoOrders) {
      const customer = DEMO_CUSTOMERS[o.customer]!;
      const userId = customerIds[o.customer]!;
      const total = o.items.reduce((sum, [idx, qty]) => sum + priceOf(idx) * qty, 0);
      const created = now - o.daysAgo * DAY;
      const order = insertOrder.get(userId, total, o.status, o.payment, customer.address, created) as { id: number };
      for (const [idx, qty] of o.items) {
        insertItem.run(order.id, productIds[idx]!, nameOf(idx), priceOf(idx), qty);
        decStock.run(qty, productIds[idx]!);
      }
      insertAudit.run(userId, customer.email, "compra", `Pedido #${order.id} — R$ ${(total / 100).toFixed(2)} via ${o.payment}`, created);
    }
  })();
  console.log("[vetor] banco semeado: catálogo, admin e compradores/pedidos simulados.");
}

seedIfEmpty();

// ---------------------------------------------------------------------------
// Validação de entrada — mesmos limites das actions originais (zod)
// ---------------------------------------------------------------------------

class ActionError extends Error {}

function fail(message: string): never {
  throw new ActionError(message);
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function reqStr(args: Record<string, unknown>, field: string, opts: { min?: number; max: number; trim?: boolean; def?: string }): string {
  let v = args[field];
  if (v === undefined && opts.def !== undefined) v = opts.def;
  if (typeof v !== "string") fail(`Campo "${field}" inválido.`);
  const s = opts.trim ? (v as string).trim() : (v as string);
  if (opts.min !== undefined && s.length < opts.min) fail(`Campo "${field}" muito curto.`);
  if (s.length > opts.max) fail(`Campo "${field}" muito longo.`);
  return s;
}

function reqEmail(args: Record<string, unknown>, field = "email"): string {
  const s = reqStr(args, field, { max: 120, trim: true }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s)) fail("E-mail inválido.");
  return s;
}

function reqInt(args: Record<string, unknown>, field: string, opts: { min: number; max: number; def?: number }): number {
  let v = args[field];
  if (v === undefined && opts.def !== undefined) v = opts.def;
  if (typeof v !== "number" || !Number.isInteger(v) || v < opts.min || v > opts.max) {
    fail(`Campo "${field}" inválido.`);
  }
  return v as number;
}

function reqBool(args: Record<string, unknown>, field: string): boolean {
  const v = args[field];
  if (typeof v !== "boolean") fail(`Campo "${field}" inválido.`);
  return v;
}

function reqEnum<T extends string>(args: Record<string, unknown>, field: string, values: readonly T[]): T {
  const v = args[field];
  if (typeof v !== "string" || !(values as readonly string[]).includes(v)) fail(`Campo "${field}" inválido.`);
  return v as T;
}

function tokenOf(args: Record<string, unknown>): string {
  return reqStr(args, "token", { min: 10, max: 200 });
}

// ---------------------------------------------------------------------------
// Linhas do banco
// ---------------------------------------------------------------------------

interface UserRow {
  id: number;
  name: string;
  email: string;
  password_hash: string;
  role: string;
  failed_attempts: number;
  locked_until: number | null;
  created_at: number;
}

interface ProductRow {
  id: number;
  name: string;
  category: string;
  description: string;
  price_cents: number;
  stock: number;
  hue: number;
}

interface OrderRow {
  id: number;
  user_id: number;
  total_cents: number;
  status: string;
  payment: string;
  address: string;
  created_at: number;
}

function audit(userId: number | null, email: string, event: string, detail = "") {
  db.query("INSERT INTO audit_log (user_id, email, event, detail, created_at) VALUES (?, ?, ?, ?, ?)").run(
    userId,
    email,
    event,
    detail,
    Date.now(),
  );
  // Registro também no stdout: o Railway guarda o log do container, então
  // o histórico de auditoria pode ser conferido depois mesmo que o banco
  // (SQLite local, apagado a cada restart no plano grátis) seja recriado.
  // Nunca registra senhas, tokens ou dados de sessão — só evento e e-mail.
  console.log(`[vetor:audit] ${new Date().toISOString()} ${event} ${email}${detail ? ` — ${detail}` : ""}`);
}

function requireUser(token: string): UserRow {
  const row = db
    .query(
      `SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = ? AND s.expires_at > ? LIMIT 1`,
    )
    .get(hashToken(token), Date.now()) as UserRow | null;
  if (!row) fail("Sessão inválida ou expirada. Faça login novamente.");
  return row;
}

function requireAdmin(token: string): UserRow {
  const user = requireUser(token);
  if (user.role !== "admin") fail("Acesso restrito à administração.");
  return user;
}

function publicUser(u: UserRow) {
  return { id: u.id, name: u.name, email: u.email, role: u.role };
}

function publicProduct(p: ProductRow) {
  return {
    id: p.id,
    name: p.name,
    category: p.category,
    description: p.description,
    priceCents: p.price_cents,
    stock: p.stock,
    hue: p.hue,
  };
}

function cartCount(userId: number): number {
  const rows = db.query("SELECT qty FROM cart_items WHERE user_id = ?").all(userId) as Array<{ qty: number }>;
  return rows.reduce((sum, r) => sum + r.qty, 0);
}

function startSession(userId: number): string {
  const { token, tokenHash } = newSessionToken();
  db.query("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)").run(
    tokenHash,
    userId,
    Date.now(),
    Date.now() + SESSION_HOURS * 3600_000,
  );
  return token;
}

// ---------------------------------------------------------------------------
// Actions — mesma lógica e mesmas mensagens da versão do Muse
// ---------------------------------------------------------------------------

type Handler = (args: Record<string, unknown>) => unknown;

const actions: Record<string, Handler> = {
  register(args) {
    const name = reqStr(args, "name", { min: 2, max: 80, trim: true });
    const email = reqEmail(args);
    const password = reqStr(args, "password", { min: 8, max: 72 });
    const existing = db.query("SELECT id FROM users WHERE email = ? LIMIT 1").get(email);
    if (existing) fail("Não foi possível concluir o cadastro. Verifique os dados e tente novamente.");
    const user = db
      .query(
        "INSERT INTO users (name, email, password_hash, role, failed_attempts, locked_until, created_at) VALUES (?, ?, ?, 'customer', 0, NULL, ?) RETURNING *",
      )
      .get(name, email, hashPassword(password), Date.now()) as UserRow;
    audit(user.id, email, "cadastro", "Conta de cliente criada");
    return { token: startSession(user.id), user: publicUser(user) };
  },

  login(args) {
    const email = reqEmail(args);
    const password = reqStr(args, "password", { min: 1, max: 72 });
    const user = db.query("SELECT * FROM users WHERE email = ? LIMIT 1").get(email) as UserRow | null;
    const now = Date.now();
    if (user?.locked_until && user.locked_until > now) {
      const mins = Math.max(1, Math.ceil((user.locked_until - now) / 60_000));
      audit(user.id, email, "login_bloqueado", `Tentativa durante bloqueio (${mins} min restantes)`);
      fail(`Conta temporariamente bloqueada. Tente novamente em ${mins} min.`);
    }
    if (!user || !verifyPassword(password, user.password_hash)) {
      if (user) {
        const attempts = user.failed_attempts + 1;
        const lock = attempts >= MAX_FAILED_ATTEMPTS;
        db.query("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?").run(
          lock ? 0 : attempts,
          lock ? now + LOCK_MINUTES * 60_000 : user.locked_until,
          user.id,
        );
        audit(
          user.id,
          email,
          lock ? "conta_bloqueada" : "login_falhou",
          lock
            ? `Bloqueada por ${LOCK_MINUTES} min após ${MAX_FAILED_ATTEMPTS} falhas`
            : `Senha incorreta (tentativa ${attempts})`,
        );
      } else {
        audit(null, email, "login_falhou", "Conta inexistente");
      }
      // Erro genérico: nunca revela se a conta existe.
      fail("E-mail ou senha incorretos.");
    }
    db.query("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?").run(user.id);
    audit(user.id, email, "login_ok", `Papel: ${user.role}`);
    return { token: startSession(user.id), user: publicUser(user) };
  },

  logout(args) {
    const token = tokenOf(args);
    db.query("DELETE FROM sessions WHERE token_hash = ?").run(hashToken(token));
    return { ok: true as const };
  },

  me(args) {
    const user = requireUser(tokenOf(args));
    return { user: publicUser(user), cartCount: cartCount(user.id) };
  },

  listProducts(args) {
    const query = reqStr(args, "query", { max: 80, def: "" });
    const category = reqStr(args, "category", { max: 40, def: "" });
    const all = db.query("SELECT * FROM products ORDER BY category, name").all() as ProductRow[];
    const categories = [...new Set(all.map((p) => p.category))];
    let filtered = all;
    if (category) filtered = filtered.filter((p) => p.category === category);
    const q = query.trim().toLowerCase();
    if (q) {
      filtered = filtered.filter(
        (p) =>
          p.name.toLowerCase().includes(q) ||
          p.description.toLowerCase().includes(q) ||
          p.category.toLowerCase().includes(q),
      );
    }
    return { products: filtered.map(publicProduct), categories };
  },

  getCart(args) {
    const user = requireUser(tokenOf(args));
    const rows = db
      .query(
        `SELECT c.qty AS qty, p.* FROM cart_items c JOIN products p ON p.id = c.product_id
         WHERE c.user_id = ? ORDER BY p.name`,
      )
      .all(user.id) as Array<ProductRow & { qty: number }>;
    const items = rows.map((r) => ({ product: publicProduct(r), qty: r.qty }));
    return { items, totalCents: items.reduce((sum, i) => sum + i.product.priceCents * i.qty, 0) };
  },

  addToCart(args) {
    const user = requireUser(tokenOf(args));
    const productId = reqInt(args, "productId", { min: 1, max: Number.MAX_SAFE_INTEGER });
    const qty = reqInt(args, "qty", { min: 1, max: 20, def: 1 });
    const product = db.query("SELECT * FROM products WHERE id = ? LIMIT 1").get(productId) as ProductRow | null;
    if (!product) fail("Produto não encontrado.");
    const current = db
      .query("SELECT id, qty FROM cart_items WHERE user_id = ? AND product_id = ? LIMIT 1")
      .get(user.id, product.id) as { id: number; qty: number } | null;
    const newQty = (current?.qty ?? 0) + qty;
    if (newQty > product.stock) fail(`Estoque insuficiente: restam ${product.stock} unidade(s).`);
    if (current) {
      db.query("UPDATE cart_items SET qty = ? WHERE id = ?").run(newQty, current.id);
    } else {
      db.query("INSERT INTO cart_items (user_id, product_id, qty) VALUES (?, ?, ?)").run(user.id, product.id, qty);
    }
    return { ok: true as const, cartCount: cartCount(user.id) };
  },

  setCartQty(args) {
    const user = requireUser(tokenOf(args));
    const productId = reqInt(args, "productId", { min: 1, max: Number.MAX_SAFE_INTEGER });
    const qty = reqInt(args, "qty", { min: 0, max: 99 });
    const current = db
      .query("SELECT id FROM cart_items WHERE user_id = ? AND product_id = ? LIMIT 1")
      .get(user.id, productId) as { id: number } | null;
    if (!current) fail("Item não está no carrinho.");
    if (qty === 0) {
      db.query("DELETE FROM cart_items WHERE id = ?").run(current.id);
    } else {
      const product = db.query("SELECT * FROM products WHERE id = ? LIMIT 1").get(productId) as ProductRow | null;
      if (product && qty > product.stock) fail(`Estoque insuficiente: restam ${product.stock} unidade(s).`);
      db.query("UPDATE cart_items SET qty = ? WHERE id = ?").run(qty, current.id);
    }
    return { ok: true as const };
  },

  checkout(args) {
    const user = requireUser(tokenOf(args));
    const payment = reqEnum(args, "payment", ["Pix", "Cartão de crédito", "Boleto"] as const);
    const address = reqStr(args, "address", { min: 10, max: 300, trim: true });
    const rows = db
      .query(
        `SELECT c.qty AS qty, p.* FROM cart_items c JOIN products p ON p.id = c.product_id
         WHERE c.user_id = ?`,
      )
      .all(user.id) as Array<ProductRow & { qty: number }>;
    if (rows.length === 0) fail("Seu carrinho está vazio.");
    for (const r of rows) {
      if (r.qty > r.stock) fail(`Estoque insuficiente para "${r.name}".`);
    }
    const total = rows.reduce((sum, r) => sum + r.price_cents * r.qty, 0);
    let orderId = 0;
    db.transaction(() => {
      const order = db
        .query("INSERT INTO orders (user_id, total_cents, status, payment, address, created_at) VALUES (?, ?, 'pago', ?, ?, ?) RETURNING id")
        .get(user.id, total, payment, address, Date.now()) as { id: number };
      orderId = order.id;
      for (const r of rows) {
        db.query("INSERT INTO order_items (order_id, product_id, product_name, unit_price_cents, qty) VALUES (?, ?, ?, ?, ?)").run(
          order.id,
          r.id,
          r.name,
          r.price_cents,
          r.qty,
        );
        db.query("UPDATE products SET stock = stock - ? WHERE id = ?").run(r.qty, r.id);
      }
      db.query("DELETE FROM cart_items WHERE user_id = ?").run(user.id);
    })();
    audit(user.id, user.email, "compra", `Pedido #${orderId} — R$ ${(total / 100).toFixed(2)} via ${payment}`);
    return { orderId, totalCents: total };
  },

  listOrders(args) {
    const user = requireUser(tokenOf(args));
    const orderRows = db.query("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC").all(user.id) as OrderRow[];
    const orders = orderRows.map((o) => {
      const items = db
        .query("SELECT product_name, qty, unit_price_cents FROM order_items WHERE order_id = ?")
        .all(o.id) as Array<{ product_name: string; qty: number; unit_price_cents: number }>;
      return {
        id: o.id,
        totalCents: o.total_cents,
        status: o.status,
        payment: o.payment,
        address: o.address,
        createdAt: new Date(o.created_at).toISOString(),
        items: items.map((i) => ({ name: i.product_name, qty: i.qty, unitPriceCents: i.unit_price_cents })),
      };
    });
    return { orders };
  },

  getProgress(args) {
    const user = requireUser(tokenOf(args));
    const rows = db
      .query("SELECT step_key, done, note FROM pentest_progress WHERE user_id = ?")
      .all(user.id) as Array<{ step_key: string; done: number; note: string }>;
    return { progress: rows.map((r) => ({ stepKey: r.step_key, done: r.done === 1, note: r.note })) };
  },

  setStep(args) {
    const user = requireUser(tokenOf(args));
    const stepKey = reqStr(args, "stepKey", { min: 1, max: 40 });
    const done = reqBool(args, "done");
    const note = reqStr(args, "note", { max: 2000, def: "" });
    const existing = db
      .query("SELECT id FROM pentest_progress WHERE user_id = ? AND step_key = ? LIMIT 1")
      .get(user.id, stepKey) as { id: number } | null;
    if (existing) {
      db.query("UPDATE pentest_progress SET done = ?, note = ?, updated_at = ? WHERE id = ?").run(
        done ? 1 : 0,
        note,
        Date.now(),
        existing.id,
      );
    } else {
      db.query("INSERT INTO pentest_progress (user_id, step_key, done, note, updated_at) VALUES (?, ?, ?, ?, ?)").run(
        user.id,
        stepKey,
        done ? 1 : 0,
        note,
        Date.now(),
      );
    }
    return { ok: true as const };
  },

  listFindings(args) {
    const user = requireUser(tokenOf(args));
    const rows = db.query("SELECT * FROM findings WHERE user_id = ? ORDER BY id DESC").all(user.id) as Array<{
      id: number;
      title: string;
      severity: string;
      step_key: string;
      description: string;
      created_at: number;
    }>;
    return {
      findings: rows.map((r) => ({
        id: r.id,
        title: r.title,
        severity: r.severity,
        stepKey: r.step_key,
        description: r.description,
        createdAt: new Date(r.created_at).toISOString(),
      })),
    };
  },

  addFinding(args) {
    const user = requireUser(tokenOf(args));
    const title = reqStr(args, "title", { min: 3, max: 140, trim: true });
    const severity = reqEnum(args, "severity", ["info", "baixa", "media", "alta", "critica"] as const);
    const stepKey = reqStr(args, "stepKey", { max: 40, def: "" });
    const description = reqStr(args, "description", { max: 3000, def: "" });
    const row = db
      .query("INSERT INTO findings (user_id, title, severity, step_key, description, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id")
      .get(user.id, title, severity, stepKey, description, Date.now()) as { id: number };
    return { id: row.id };
  },

  deleteFinding(args) {
    const user = requireUser(tokenOf(args));
    const id = reqInt(args, "id", { min: 1, max: Number.MAX_SAFE_INTEGER });
    db.query("DELETE FROM findings WHERE id = ? AND user_id = ?").run(id, user.id);
    return { ok: true as const };
  },

  adminOverview(args) {
    requireAdmin(tokenOf(args));
    const allUsers = db.query("SELECT * FROM users ORDER BY id DESC").all() as UserRow[];
    const allOrders = db.query("SELECT * FROM orders").all() as OrderRow[];
    const allProducts = db.query("SELECT * FROM products").all() as ProductRow[];
    const recentAudit = db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 60").all() as Array<{
      id: number;
      email: string;
      event: string;
      detail: string;
      created_at: number;
    }>;
    const recentOrders = db
      .query(
        `SELECT o.*, u.email AS email FROM orders o JOIN users u ON u.id = o.user_id
         ORDER BY o.id DESC LIMIT 30`,
      )
      .all() as Array<OrderRow & { email: string }>;
    const now = Date.now();
    return {
      totals: {
        users: allUsers.length,
        orders: allOrders.length,
        revenueCents: allOrders.filter((o) => o.status !== "cancelado").reduce((sum, o) => sum + o.total_cents, 0),
        products: allProducts.length,
        lowStock: allProducts.filter((p) => p.stock <= 10).length,
        failedLogins: recentAudit.filter((a) => a.event === "login_falhou" || a.event === "conta_bloqueada").length,
      },
      users: allUsers.map((u) => ({
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        locked: !!u.locked_until && u.locked_until > now,
        createdAt: new Date(u.created_at).toISOString(),
      })),
      recentOrders: recentOrders.map((o) => ({
        id: o.id,
        email: o.email,
        totalCents: o.total_cents,
        status: o.status,
        createdAt: new Date(o.created_at).toISOString(),
      })),
      audit: recentAudit.map((a) => ({
        id: a.id,
        email: a.email,
        event: a.event,
        detail: a.detail,
        createdAt: new Date(a.created_at).toISOString(),
      })),
    };
  },

  adminSetOrderStatus(args) {
    const admin = requireAdmin(tokenOf(args));
    const orderId = reqInt(args, "orderId", { min: 1, max: Number.MAX_SAFE_INTEGER });
    const status = reqEnum(args, "status", ["pago", "enviado", "entregue", "cancelado"] as const);
    db.query("UPDATE orders SET status = ? WHERE id = ?").run(status, orderId);
    audit(admin.id, admin.email, "admin_pedido", `Pedido #${orderId} → ${status}`);
    return { ok: true as const };
  },

  adminSetStock(args) {
    const admin = requireAdmin(tokenOf(args));
    const productId = reqInt(args, "productId", { min: 1, max: Number.MAX_SAFE_INTEGER });
    const stock = reqInt(args, "stock", { min: 0, max: 100_000 });
    db.query("UPDATE products SET stock = ? WHERE id = ?").run(stock, productId);
    audit(admin.id, admin.email, "admin_estoque", `Produto ${productId} estoque → ${stock}`);
    return { ok: true as const };
  },

  adminUnlock(args) {
    const admin = requireAdmin(tokenOf(args));
    const userId = reqInt(args, "userId", { min: 1, max: Number.MAX_SAFE_INTEGER });
    db.query("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?").run(userId);
    audit(admin.id, admin.email, "admin_desbloqueio", `Conta ${userId} desbloqueada`);
    return { ok: true as const };
  },
};

// ---------------------------------------------------------------------------
// HTTP — arquivos estáticos (./public) + POST /actions
// ---------------------------------------------------------------------------

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
};

const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "content-security-policy":
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'",
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...SECURITY_HEADERS },
  });
}

async function handleActions(req: Request): Promise<Response> {
  const raw = await req.text();
  if (raw.length > MAX_BODY_BYTES) {
    return jsonResponse(413, { error: { message: "Requisição muito grande." } });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return jsonResponse(400, { error: { message: "Corpo da requisição inválido." } });
  }
  if (!isRecord(parsed) || typeof parsed.action !== "string") {
    return jsonResponse(400, { error: { message: "Requisição inválida." } });
  }
  const handler = actions[parsed.action];
  if (!handler) {
    return jsonResponse(404, { error: { message: `Ação desconhecida: ${parsed.action}` } });
  }
  const args = isRecord(parsed.args) ? parsed.args : {};
  try {
    const data = handler(args);
    return jsonResponse(200, { data });
  } catch (e) {
    if (e instanceof ActionError) {
      return jsonResponse(400, { error: { message: e.message } });
    }
    console.error(`[vetor] erro na ação ${parsed.action}:`, e);
    return jsonResponse(500, { error: { message: "Erro interno. Tente novamente." } });
  }
}

async function serveStatic(pathname: string): Promise<Response> {
  const rel = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, "");
  const filePath = join(PUBLIC_DIR, rel);
  if (filePath.startsWith(PUBLIC_DIR)) {
    const file = Bun.file(filePath);
    if (await file.exists()) {
      return new Response(file, {
        headers: {
          "content-type": MIME[extname(filePath).toLowerCase()] ?? "application/octet-stream",
          ...SECURITY_HEADERS,
        },
      });
    }
  }
  // SPA: qualquer rota desconhecida devolve o index.html.
  const index = Bun.file(join(PUBLIC_DIR, "index.html"));
  return new Response(index, {
    headers: { "content-type": "text/html; charset=utf-8", ...SECURITY_HEADERS },
  });
}

const server = Bun.serve({
  port: PORT,
  hostname: HOST,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/healthz") {
      return new Response("ok", { status: 200, headers: { "content-type": "text/plain; charset=utf-8" } });
    }
    // Log de acesso, como um servidor de verdade: IP, método, caminho e
    // user-agent de cada requisição. O IP vem do X-Forwarded-For que o
    // Railway repassa (primeiro da lista); sem ele, usa o IP direto da
    // conexão. Nunca registra corpo, senha ou token.
    const fwd = req.headers.get("x-forwarded-for");
    const ip = fwd ? fwd.split(",")[0].trim() : (server.requestIP(req)?.address ?? "?");
    const ua = req.headers.get("user-agent") ?? "-";
    console.log(`[vetor:req] ${new Date().toISOString()} ${ip} ${req.method} ${url.pathname}${url.search} "${ua}"`);
    if (url.pathname === "/actions") {
      if (req.method !== "POST") {
        return jsonResponse(405, { error: { message: "Método não permitido." } });
      }
      return handleActions(req);
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      return jsonResponse(405, { error: { message: "Método não permitido." } });
    }
    return serveStatic(url.pathname);
  },
});

console.log(`[vetor] Loja Vetor no ar em http://${HOST}:${server.port} (banco: ${DB_PATH})`);
