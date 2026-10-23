import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), 'oficina.db')
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()


def is_postgres():
    return bool(DATABASE_URL)


def _adapt(sql):
    if is_postgres():
        sql = sql.replace("?", "%s")
        if sql.strip().upper().startswith("INSERT INTO") and "ON CONFLICT" not in sql.upper() and "RETURNING" not in sql.upper():
            sql = sql.rstrip(";") + " ON CONFLICT DO NOTHING;"
        return sql
    return sql


class RowProxy:
    """Linha que permite acesso por nome e por índice, e conversao via dict()."""
    __slots__ = ('_data', '_keys')

    def __init__(self, data, keys):
        self._data = data
        self._keys = keys

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._data[key]
        return self._data[self._keys.index(key)]

    def __getattr__(self, name):
        if name in self._keys:
            return self._data[self._keys.index(name)]
        raise AttributeError(name)

    def keys(self):
        return list(self._keys)

    def values(self):
        return list(self._data)

    def items(self):
        return [(k, self._data[i]) for i, k in enumerate(self._keys)]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __repr__(self):
        return repr(dict(zip(self._keys, self._data)))


class Cursor:
    def __init__(self, cur, backend):
        self.cur = cur
        self.backend = backend

    def _row(self, r):
        if r is None:
            return None
        if self.backend == 'postgres':
            keys = [d[0] for d in self.cur.description]
            return RowProxy(list(r), keys)
        return r

    def fetchone(self):
        return self._row(self.cur.fetchone())

    def fetchall(self):
        rows = self.cur.fetchall()
        if self.backend == 'postgres':
            return [self._row(r) for r in rows]
        return rows

    def execute(self, sql, params=None):
        sql = _adapt(sql)
        if params:
            return self.cur.execute(sql, params)
        return self.cur.execute(sql)

    def __getattr__(self, name):
        return getattr(self.cur, name)


class Connection:
    def __init__(self, conn, backend):
        self.conn = conn
        self.backend = backend

    def execute(self, sql, params=None):
        sql = _adapt(sql)
        cur = self.conn.cursor()
        if params is not None and len(params) > 0:
            cur.execute(sql, params)
        else:
            cur.execute(sql)
        if self.backend == 'sqlite':
            return Cursor(cur, 'sqlite')
        return Cursor(cur, 'postgres')

    def executescript(self, sql):
        if self.backend == 'postgres':
            cur = self.conn.cursor()
            cur.execute(_adapt(sql))
            return cur
        return self.conn.executescript(sql)

    def commit(self):
        return self.conn.commit()

    def rollback(self):
        return self.conn.rollback()

    def close(self):
        return self.conn.close()


def get_connection():
    if is_postgres():
        import psycopg2
        return Connection(
            psycopg2.connect(DATABASE_URL),
            "postgres",
        )
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return Connection(conn, "sqlite")


def insert_id(conn, sql, params=None):
    """Executa um INSERT e retorna o id da nova linha (compatível SQLite/PostgreSQL)."""
    if is_postgres():
        sql2 = _adapt(sql).rstrip(";")
        if "RETURNING" not in sql2.upper():
            sql2 += " RETURNING id"
        cur = conn.conn.cursor()
        if params is not None and len(params) > 0:
            cur.execute(sql2, params)
        else:
            cur.execute(sql2)
        row = cur.fetchone()
        return row[0] if row else None
    cur = conn.execute(sql, params or ())
    return cur.lastrowid


def _table_exists(conn, tabela):
    if is_postgres():
        return conn.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name=?",
            (tabela,)
        ).fetchone() is not None
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (tabela,)
    ).fetchone() is not None


def _column_exists(conn, tabela, coluna):
    if is_postgres():
        return conn.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_name=? AND column_name=?",
            (tabela, coluna)
        ).fetchone() is not None
    cols = [r['name'] for r in conn.execute(f"PRAGMA table_info({tabela})").fetchall()]
    return coluna in cols


def _insert_ignore(conn, tabela, colunas, valores):
    cols = ", ".join(colunas)
    ph = ", ".join(["?"] * len(colunas))
    sql = f"INSERT INTO {tabela} ({cols}) VALUES ({ph})"
    if is_postgres():
        sql += " ON CONFLICT DO NOTHING"
    else:
        sql = "INSERT OR IGNORE INTO " + sql[len("INSERT INTO "):]
    conn.execute(sql, valores)


def init_db():
    ddl = """
        CREATE TABLE IF NOT EXISTS usuarios (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            nome          TEXT NOT NULL,
            username      TEXT NOT NULL UNIQUE,
            email         TEXT,
            senha_hash    TEXT NOT NULL,
            ativo         INTEGER DEFAULT 1,
            admin         INTEGER DEFAULT 0,
            senha_trocada INTEGER DEFAULT 0,
            criado_em     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS clientes (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            nome           TEXT NOT NULL,
            telefone       TEXT,
            email          TEXT,
            cpf_cnpj       TEXT,
            cep            TEXT,
            endereco       TEXT,
            bairro         TEXT,
            cidade         TEXT,
            uf             TEXT,
            observacao     TEXT,
            ultimo_servico TIMESTAMP,
            criado_em      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            token          TEXT
        );
        CREATE TABLE IF NOT EXISTS marcas (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS modelos (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            marca_id INTEGER NOT NULL REFERENCES marcas(id),
            nome     TEXT NOT NULL,
            UNIQUE(marca_id, nome)
        );
        CREATE TABLE IF NOT EXISTS cores (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS categorias_veiculo (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS veiculos (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id   INTEGER NOT NULL REFERENCES clientes(id),
            placa        TEXT NOT NULL,
            marca_id     INTEGER REFERENCES marcas(id),
            modelo_id    INTEGER REFERENCES modelos(id),
            ano          INTEGER,
            chassi       TEXT,
            cor_id       INTEGER REFERENCES cores(id),
            categoria_id INTEGER REFERENCES categorias_veiculo(id),
            observacao   TEXT
        );
        CREATE TABLE IF NOT EXISTS categorias_servico (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS servicos (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            categoria_id INTEGER REFERENCES categorias_servico(id),
            nome         TEXT NOT NULL,
            descricao    TEXT,
            valor_base   REAL
        );
        CREATE TABLE IF NOT EXISTS categorias_peca (
            id   INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS pecas (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            codigo         TEXT UNIQUE,
            nome           TEXT NOT NULL,
            descricao      TEXT,
            categoria_id   INTEGER REFERENCES categorias_peca(id),
            fornecedor     TEXT,
            preco_custo    REAL,
            preco_venda    REAL,
            estoque_atual  INTEGER DEFAULT 0,
            estoque_minimo INTEGER DEFAULT 0,
            foto           TEXT
        );
        CREATE TABLE IF NOT EXISTS fornecedores (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            nome       TEXT NOT NULL,
            contato    TEXT,
            telefone   TEXT,
            email      TEXT,
            endereco   TEXT,
            observacao TEXT
        );
        CREATE TABLE IF NOT EXISTS ordens_servico (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id      INTEGER NOT NULL REFERENCES clientes(id),
            veiculo_id      INTEGER REFERENCES veiculos(id),
            data_abertura   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_fechamento TIMESTAMP,
            status          TEXT DEFAULT 'aberta',
            km_entrada      INTEGER,
            km_saida        INTEGER,
            observacao      TEXT,
            total_servicos  REAL DEFAULT 0,
            total_pecas     REAL DEFAULT 0,
            total_geral     REAL DEFAULT 0,
            desconto        REAL DEFAULT 0,
            valor_pago      REAL DEFAULT 0,
            forma_pagamento TEXT
        );
        CREATE TABLE IF NOT EXISTS os_servicos (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            os_id          INTEGER NOT NULL REFERENCES ordens_servico(id),
            servico_id     INTEGER NOT NULL REFERENCES servicos(id),
            quantidade     INTEGER DEFAULT 1,
            valor_unitario REAL,
            subtotal       REAL
        );
        CREATE TABLE IF NOT EXISTS os_pecas (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            os_id          INTEGER NOT NULL REFERENCES ordens_servico(id),
            peca_id        INTEGER NOT NULL REFERENCES pecas(id),
            quantidade     INTEGER DEFAULT 1,
            valor_unitario REAL,
            subtotal       REAL
        );
        CREATE TABLE IF NOT EXISTS vendas (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_id      INTEGER REFERENCES clientes(id),
            data            TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total           REAL DEFAULT 0,
            desconto        REAL DEFAULT 0,
            valor_pago      REAL DEFAULT 0,
            forma_pagamento TEXT
        );
        CREATE TABLE IF NOT EXISTS venda_itens (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            venda_id       INTEGER NOT NULL REFERENCES vendas(id),
            peca_id        INTEGER NOT NULL REFERENCES pecas(id),
            quantidade     INTEGER DEFAULT 1,
            valor_unitario REAL,
            subtotal       REAL
        );
        CREATE TABLE IF NOT EXISTS empresa (
            id            INTEGER PRIMARY KEY CHECK (id = 1),
            razao_social  TEXT,
            nome_fantasia TEXT,
            cnpj          TEXT,
            ie            TEXT,
            telefone      TEXT,
            celular       TEXT,
            email         TEXT,
            website       TEXT,
            cep           TEXT,
            endereco      TEXT,
            bairro        TEXT,
            cidade        TEXT,
            uf            TEXT,
            slogan        TEXT,
            observacao    TEXT,
            logo_path     TEXT
        );
        CREATE TABLE IF NOT EXISTS log_acoes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id   INTEGER,
            usuario_nome TEXT,
            acao         TEXT NOT NULL,
            entidade     TEXT NOT NULL,
            entidade_id  INTEGER,
            descricao    TEXT,
            criado_em    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """

    if is_postgres():
        ddl = ddl.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
        ddl = ddl.replace(" REAL ", " DOUBLE PRECISION ")
        ddl = ddl.replace("CHECK (id = 1)", "")

    conn = get_connection()
    conn.executescript(ddl)
    conn.commit()
    conn.close()


def ensure_empresa():
    conn = get_connection()
    _insert_ignore(conn, "empresa", ["id"], [1])
    conn.commit()
    conn.close()
