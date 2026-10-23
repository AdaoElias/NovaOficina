import os
import time
import uuid
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from database import get_connection, init_db, ensure_empresa, is_postgres, insert_id

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

TABELAS_PERMITIDAS = {'marcas', 'modelos', 'cores', 'categorias_veiculo',
                      'categorias_servico', 'categorias_peca'}


@app.before_request
def make_session_permanent():
    session.permanent = True


@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    return resp

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

MARCAS = [
    "Toyota", "Volkswagen", "Fiat", "Chevrolet", "Ford", "Honda", "Hyundai",
    "Nissan", "Renault", "Peugeot", "Citroën", "Jeep", "Mitsubishi", "Suzuki",
    "BMW", "Mercedes-Benz", "Audi", "Volvo", "Kia", "Subaru", "Land Rover",
    "Jaguar", "Porsche", "Tesla", "BYD", "Caoa Chery", "Jac Motors", "Changan",
    "Geely", "MG", "Lexus", "Maserati", "Mini", "Outros",
]
CORES = [
    "Branco", "Preto", "Prata", "Cinza", "Vermelho", "Azul", "Verde",
    "Amarelo", "Laranja", "Marrom", "Bege", "Dourado", "Bordô", "Roxo",
    "Rosa", "Vinho", "Bronze", "Fantasia", "Outros",
]
CAT_VEICULO = ["Hatch", "Sedã", "SUV", "Pickup", "Caminhonete", "Caminhão", "Moto", "Outros"]
CAT_SERVICO = ["Elétrica", "Hidráulica", "Motor", "Teste de Gás", "Suspensão", "Freios", "Ar Condicionado", "Funilaria", "Pintura", "Outros"]
CAT_PECA = ["Motor", "Freios", "Suspensão", "Elétrica", "Filtros", "Óleos", "Pneus", "Outros"]

SERVICOS_PADRAO = [
    ("Troca de Óleo", "Troca de óleo do motor com filtro", 89.90, "Motor"),
    ("Alinhamento", "Alinhamento da direção", 79.90, "Suspensão"),
    ("Balanceamento", "Balanceamento das rodas", 59.90, "Suspensão"),
    ("Revisão Elétrica", "Verificação geral do sistema elétrico", 99.90, "Elétrica"),
    ("Troca de Pastilhas de Freio", "Substituição das pastilhas", 149.90, "Freios"),
    ("Troca de Discos de Freio", "Substituição dos discos", 199.90, "Freios"),
    ("Teste de Gás", "Teste anual obrigatório de emissão de gases", 119.90, "Teste de Gás"),
    ("Troca de Correia Dentada", "Substituição da correia dentada", 349.90, "Motor"),
    ("Troca de Amortecedores", "Substituição dos amortecedores (par)", 499.90, "Suspensão"),
    ("Scanner Automotivo", "Diagnóstico eletrônico completo", 89.90, "Elétrica"),
    ("Revisão Geral", "Revisão completa de 40 itens", 249.90, "Motor"),
    ("Troca de Bateria", "Substituição da bateria", 49.90, "Elétrica"),
]

FORNECEDORES_PADRAO = [
    ("Auto Peças Brasil Ltda", "(11)3123-4567", "vendas@autopecasbrasil.com.br"),
    ("Peças & Cia", "(11)3987-6543", "contato@pecasecia.com.br"),
    ("Distribuidora de Peças ABC", "(21)2543-2100", "abc@distribuidora.com.br"),
]

def date_br(val):
    if not val:
        return '-'
    s = str(val).replace('T', ' ').strip()
    if ' ' in s:
        d, t = s.split(' ', 1)
        t = t[:5]
    else:
        d, t = s, ''
    partes = d.split('-')
    if len(partes) == 3:
        d = f"{partes[2]}/{partes[1]}/{partes[0]}"
    return f"{d} {t}".strip() if t else d

app.jinja_env.filters['date_br'] = date_br

def hash_senha(s):
    return generate_password_hash(s)

def log_acao(usuario_id, usuario_nome, acao, entidade, entidade_id=None, descricao=""):
    conn = get_connection()
    conn.execute(
        "INSERT INTO log_acoes (usuario_id,usuario_nome,acao,entidade,entidade_id,descricao) VALUES (?,?,?,?,?,?)",
        (usuario_id, usuario_nome, acao, entidade, entidade_id, descricao)
    )
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'usuario_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('admin'):
            flash("Acesso restrito a administradores", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

@app.context_processor
def inject_globals():
    emp = {}
    try:
        conn = get_connection()
        row = conn.execute("SELECT * FROM empresa WHERE id=1").fetchone()
        if row:
            emp = dict(row)
        conn.close()
    except Exception:
        pass
    return {'now': datetime.now(), 'emp': emp}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        senha = request.form.get('senha', '')
        conn = get_connection()
        user = conn.execute(
            "SELECT * FROM usuarios WHERE username=? AND ativo=1", (username,)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user['senha_hash'], senha):
            session['usuario_id'] = user['id']
            session['usuario_nome'] = user['nome']
            session['username'] = user['username']
            session['admin'] = user['admin']
            session['senha_trocada'] = user['senha_trocada']
            log_acao(user['id'], user['nome'], 'login', 'sistema')
            if not user['senha_trocada']:
                flash("Você deve alterar sua senha padrão no primeiro acesso", "warning")
                return redirect(url_for('perfil'))
            flash("Login realizado com sucesso", "success")
            return redirect(url_for('index'))
        flash("Usuário ou senha inválidos", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Sessão encerrada", "success")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    conn = get_connection()
    agora = datetime.now()
    inicio_mes = agora.replace(day=1).strftime('%Y-%m-%d')
    proximo_mes = (datetime(agora.year + (1 if agora.month == 12 else 0),
                           1 if agora.month == 12 else agora.month + 1, 1)).strftime('%Y-%m-%d')
    stats = {
        'clientes': conn.execute("SELECT COUNT(*) FROM clientes").fetchone()[0],
        'veiculos': conn.execute("SELECT COUNT(*) FROM veiculos").fetchone()[0],
        'os_abertas': conn.execute("SELECT COUNT(*) FROM ordens_servico WHERE status IN ('aberta','em_andamento')").fetchone()[0],
        'os_fechadas_mes': conn.execute("SELECT COUNT(*) FROM ordens_servico WHERE status='fechada' AND data_fechamento >= ? AND data_fechamento < ?", (inicio_mes, proximo_mes)).fetchone()[0],
        'pecas': conn.execute("SELECT COUNT(*) FROM pecas").fetchone()[0],
        'pecas_baixa': conn.execute("SELECT COUNT(*) FROM pecas WHERE estoque_atual <= estoque_minimo AND estoque_minimo > 0").fetchone()[0],
        'vendas_mes': conn.execute("SELECT COALESCE(SUM(total),0) FROM vendas WHERE data >= ? AND data < ?", (inicio_mes, proximo_mes)).fetchone()[0],
        'faturamento_mes': conn.execute("SELECT COALESCE(SUM(total_geral),0) FROM ordens_servico WHERE status='fechada' AND data_fechamento >= ? AND data_fechamento < ?", (inicio_mes, proximo_mes)).fetchone()[0],
    }
    os_recentes = conn.execute(
        "SELECT o.*, c.nome as cliente_nome FROM ordens_servico o LEFT JOIN clientes c ON o.cliente_id=c.id ORDER BY o.id DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return render_template('index.html', stats=stats, os_recentes=[dict(r) for r in os_recentes])

@app.route('/clientes')
@login_required
def listar_clientes():
    busca = request.args.get('busca', '')
    conn = get_connection()
    if busca:
        rows = conn.execute(
            "SELECT * FROM clientes WHERE nome LIKE ? ORDER BY nome LIMIT 500",
            (f"%{busca}%",)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM clientes ORDER BY nome LIMIT 500").fetchall()
    conn.close()
    return render_template('clientes/listar.html', clientes=[dict(r) for r in rows], busca=busca)

@app.route('/clientes/novo', methods=['GET', 'POST'])
@login_required
def criar_cliente():
    if request.method == 'POST':
        dados = {k: request.form.get(k, '') for k in ['nome','telefone','email','cpf_cnpj','cep','endereco','bairro','cidade','uf','observacao']}
        if not dados['nome']:
            flash("Nome é obrigatório", "danger")
            return render_template('clientes/form.html', cliente=dados, editando=False)
        conn = get_connection()
        token = uuid.uuid4().hex
        novo_id = insert_id(
            conn,
            """INSERT INTO clientes (nome,telefone,email,cpf_cnpj,cep,endereco,bairro,cidade,uf,observacao,token)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (dados['nome'], dados['telefone'], dados['email'], dados['cpf_cnpj'], dados['cep'],
             dados['endereco'], dados['bairro'], dados['cidade'], dados['uf'], dados['observacao'], token)
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'criar', 'cliente', novo_id, dados['nome'])
        flash("Cliente criado com sucesso", "success")
        return redirect(url_for('listar_clientes'))
    return render_template('clientes/form.html', cliente={}, editando=False)

@app.route('/clientes/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_cliente(id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id=?", (id,)).fetchone()
    if not row:
        conn.close()
        flash("Cliente não encontrado", "danger")
        return redirect(url_for('listar_clientes'))
    if request.method == 'POST':
        dados = {k: request.form.get(k, '') for k in ['nome','telefone','email','cpf_cnpj','cep','endereco','bairro','cidade','uf','observacao']}
        if not dados['nome']:
            flash("Nome é obrigatório", "danger")
            return render_template('clientes/form.html', cliente=dict(row)|dados, editando=True)
        conn.execute(
            """UPDATE clientes SET nome=?,telefone=?,email=?,cpf_cnpj=?,cep=?,endereco=?,bairro=?,cidade=?,uf=?,observacao=?
               WHERE id=?""",
            (dados['nome'], dados['telefone'], dados['email'], dados['cpf_cnpj'], dados['cep'],
             dados['endereco'], dados['bairro'], dados['cidade'], dados['uf'], dados['observacao'], id)
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'cliente', id, dados['nome'])
        flash("Cliente atualizado com sucesso", "success")
        return redirect(url_for('listar_clientes'))
    conn.close()
    return render_template('clientes/form.html', cliente=dict(row), editando=True)

@app.route('/clientes/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_cliente(id):
    conn = get_connection()
    row = conn.execute("SELECT nome FROM clientes WHERE id=?", (id,)).fetchone()
    if row:
        conn.execute("DELETE FROM clientes WHERE id=?", (id,))
        conn.commit()
        log_acao(session['usuario_id'], session['usuario_nome'], 'excluir', 'cliente', id, row['nome'])
        flash("Cliente excluído", "success")
    conn.close()
    return redirect(url_for('listar_clientes'))

@app.route('/clientes/<int:id>/qrcode')
@login_required
def qrcode_cliente(id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id=?", (id,)).fetchone()
    if not row:
        conn.close()
        flash("Cliente não encontrado", "danger")
        return redirect(url_for('listar_clientes'))
    emp = conn.execute("SELECT * FROM empresa WHERE id=1").fetchone()
    conn.close()
    return render_template('clientes/qrcode.html', cliente=dict(row), emp=dict(emp) if emp else {})

@app.route('/c/<token>')
def cliente_publico(token):
    conn = get_connection()
    cli = conn.execute("SELECT * FROM clientes WHERE token=?", (token,)).fetchone()
    if not cli:
        conn.close()
        return render_template('cliente_publico/erro.html'), 404
    veiculos = conn.execute(
        """SELECT v.*, m.nome as marca_nome, mo.nome as modelo_nome, co.nome as cor_nome
           FROM veiculos v
           LEFT JOIN marcas m ON v.marca_id = m.id
           LEFT JOIN modelos mo ON v.modelo_id = mo.id
           LEFT JOIN cores co ON v.cor_id = co.id
           WHERE v.cliente_id=?
           ORDER BY v.id DESC""", (cli['id'],)
    ).fetchall()
    ordens = conn.execute(
        """SELECT o.*, v.placa
           FROM ordens_servico o
           LEFT JOIN veiculos v ON o.veiculo_id = v.id
           WHERE o.cliente_id=?
           ORDER BY o.id DESC LIMIT 20""", (cli['id'],)
    ).fetchall()
    emp = conn.execute("SELECT * FROM empresa WHERE id=1").fetchone()
    conn.close()
    return render_template('cliente_publico/dados.html', cliente=dict(cli),
                           veiculos=[dict(r) for r in veiculos],
                           ordens=[dict(r) for r in ordens],
                           emp=dict(emp) if emp else {})

@app.route('/veiculos')
@login_required
def listar_veiculos():
    busca = request.args.get('busca', '')
    conn = get_connection()
    sql = """SELECT v.*, c.nome as cliente_nome, m.nome as marca_nome, mo.nome as modelo_nome,
                    co.nome as cor_nome, cat.nome as categoria_nome
             FROM veiculos v
             LEFT JOIN clientes c ON v.cliente_id = c.id
             LEFT JOIN marcas m ON v.marca_id = m.id
             LEFT JOIN modelos mo ON v.modelo_id = mo.id
             LEFT JOIN cores co ON v.cor_id = co.id
             LEFT JOIN categorias_veiculo cat ON v.categoria_id = cat.id"""
    if busca:
        rows = conn.execute(sql + " WHERE v.placa LIKE ? ORDER BY v.id DESC LIMIT 200", (f"%{busca}%",)).fetchall()
    else:
        rows = conn.execute(sql + " ORDER BY v.id DESC LIMIT 500").fetchall()
    conn.close()
    return render_template('veiculos/listar.html', veiculos=[dict(r) for r in rows], busca=busca)

@app.route('/veiculos/novo', methods=['GET', 'POST'])
@login_required
def criar_veiculo():
    conn = get_connection()
    clientes = conn.execute("SELECT id, nome FROM clientes ORDER BY nome").fetchall()
    marcas = conn.execute("SELECT id, nome FROM marcas ORDER BY nome").fetchall()
    cores = conn.execute("SELECT id, nome FROM cores ORDER BY nome").fetchall()
    categorias = conn.execute("SELECT id, nome FROM categorias_veiculo ORDER BY nome").fetchall()
    modelos = conn.execute("SELECT id, nome FROM modelos ORDER BY nome").fetchall()
    if request.method == 'POST':
        placa = request.form.get('placa', '').strip().upper()
        if not placa:
            flash("Placa é obrigatória", "danger")
            return render_template('veiculos/form.html', veiculo={}, clientes=clientes, marcas=marcas, cores=cores, categorias=categorias, modelos=modelos)
        modelo_id = request.form.get('modelo_id')
        if modelo_id == '__outro__':
            modelo_nome = request.form.get('modelo_novo', '').strip()
            marca_id = request.form.get('marca_id')
            if modelo_nome and marca_id:
                modelo_id = insert_id(conn, "INSERT INTO modelos (marca_id, nome) VALUES (?,?)", (marca_id, modelo_nome))
            else:
                modelo_id = None
        vid = insert_id(
            conn,
            """INSERT INTO veiculos (cliente_id,placa,marca_id,modelo_id,ano,chassi,cor_id,categoria_id,observacao)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (request.form.get('cliente_id') or None, placa, request.form.get('marca_id') or None,
             modelo_id, request.form.get('ano') or None,
             request.form.get('chassi'), request.form.get('cor_id') or None,
             request.form.get('categoria_id') or None, request.form.get('observacao'))
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'criar', 'veiculo', vid, placa)
        flash("Veículo criado", "success")
        return redirect(url_for('listar_veiculos'))
    conn.close()
    return render_template('veiculos/form.html', veiculo={}, clientes=clientes, marcas=marcas, cores=cores, categorias=categorias, modelos=modelos)

@app.route('/veiculos/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_veiculo(id):
    conn = get_connection()
    row = conn.execute(
        """SELECT v.*, c.nome as cliente_nome, m.nome as marca_nome, mo.nome as modelo_nome,
                  co.nome as cor_nome, cat.nome as categoria_nome
           FROM veiculos v
           LEFT JOIN clientes c ON v.cliente_id = c.id
           LEFT JOIN marcas m ON v.marca_id = m.id
           LEFT JOIN modelos mo ON v.modelo_id = mo.id
           LEFT JOIN cores co ON v.cor_id = co.id
           LEFT JOIN categorias_veiculo cat ON v.categoria_id = cat.id
           WHERE v.id=?""", (id,)
    ).fetchone()
    if not row:
        conn.close()
        flash("Veículo não encontrado", "danger")
        return redirect(url_for('listar_veiculos'))
    clientes = conn.execute("SELECT id, nome FROM clientes ORDER BY nome").fetchall()
    marcas = conn.execute("SELECT id, nome FROM marcas ORDER BY nome").fetchall()
    cores = conn.execute("SELECT id, nome FROM cores ORDER BY nome").fetchall()
    categorias = conn.execute("SELECT id, nome FROM categorias_veiculo ORDER BY nome").fetchall()
    modelos = conn.execute("SELECT id, nome FROM modelos ORDER BY nome").fetchall()
    if request.method == 'POST':
        modelo_id = request.form.get('modelo_id')
        if modelo_id == '__outro__':
            modelo_nome = request.form.get('modelo_novo', '').strip()
            marca_id = request.form.get('marca_id')
            if modelo_nome and marca_id:
                modelo_id = insert_id(conn, "INSERT INTO modelos (marca_id, nome) VALUES (?,?)", (marca_id, modelo_nome))
            else:
                modelo_id = None
            conn.execute(
                """UPDATE veiculos SET cliente_id=?,placa=?,marca_id=?,modelo_id=?,ano=?,chassi=?,cor_id=?,categoria_id=?,observacao=?
                   WHERE id=?""",
            (request.form.get('cliente_id') or None, request.form.get('placa','').strip().upper(),
             request.form.get('marca_id') or None, modelo_id,
             request.form.get('ano') or None, request.form.get('chassi'),
             request.form.get('cor_id') or None, request.form.get('categoria_id') or None,
             request.form.get('observacao'), id)
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'veiculo', id, row['placa'])
        flash("Veículo atualizado", "success")
        return redirect(url_for('listar_veiculos'))
    conn.close()
    return render_template('veiculos/form.html', veiculo=dict(row), clientes=clientes, marcas=marcas, cores=cores, categorias=categorias, modelos=modelos)

@app.route('/veiculos/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_veiculo(id):
    conn = get_connection()
    row = conn.execute("SELECT placa FROM veiculos WHERE id=?", (id,)).fetchone()
    if row:
        conn.execute("DELETE FROM veiculos WHERE id=?", (id,))
        conn.commit()
        log_acao(session['usuario_id'], session['usuario_nome'], 'excluir', 'veiculo', id, row['placa'])
        flash("Veículo excluído", "success")
    conn.close()
    return redirect(url_for('listar_veiculos'))

@app.route('/modelos_por_marca')
@login_required
def modelos_por_marca():
    marca_id = request.args.get('marca_id')
    conn = get_connection()
    rows = conn.execute("SELECT id, nome FROM modelos WHERE marca_id=? ORDER BY nome", (marca_id,)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/os')
@login_required
def listar_os():
    status_filtro = request.args.get('status', '')
    busca = request.args.get('busca', '')
    conn = get_connection()
    params = []
    where = []
    if status_filtro:
        where.append("o.status=?")
        params.append(status_filtro)
    if busca:
        where.append("(c.nome LIKE ? OR v.placa LIKE ?)")
        params.extend([f"%{busca}%", f"%{busca}%"])
    sql_where = f"WHERE {' AND '.join(where)}" if where else ""
    rows = conn.execute(
        f"""SELECT o.*, c.nome as cliente_nome, v.placa
            FROM ordens_servico o
            LEFT JOIN clientes c ON o.cliente_id = c.id
            LEFT JOIN veiculos v ON o.veiculo_id = v.id
            {sql_where}
            ORDER BY o.id DESC LIMIT 500""", params
    ).fetchall()
    conn.close()
    return render_template('os/listar.html', ordens=[dict(r) for r in rows], status_filtro=status_filtro, busca=busca)

@app.route('/os/novo', methods=['GET', 'POST'])
@login_required
def criar_os():
    conn = get_connection()
    clientes = conn.execute("SELECT id, nome FROM clientes ORDER BY nome").fetchall()
    servicos = conn.execute("SELECT s.*, cs.nome as categoria_nome FROM servicos s LEFT JOIN categorias_servico cs ON s.categoria_id=cs.id ORDER BY s.nome").fetchall()
    pecas = conn.execute("SELECT p.*, cp.nome as categoria_nome FROM pecas p LEFT JOIN categorias_peca cp ON p.categoria_id=cp.id ORDER BY p.nome").fetchall()
    veiculos = conn.execute("SELECT v.id, v.placa, m.nome as marca, mo.nome as modelo FROM veiculos v LEFT JOIN marcas m ON v.marca_id=m.id LEFT JOIN modelos mo ON v.modelo_id=mo.id ORDER BY v.placa").fetchall()
    if request.method == 'POST':
        cliente_id = request.form.get('cliente_id')
        veiculo_id = request.form.get('veiculo_id') or None
        km_entrada = request.form.get('km_entrada') or None
        observacao = request.form.get('observacao', '')
        status = request.form.get('status', 'aberta')
        desconto = float(request.form.get('desconto', 0) or 0)
        valor_pago = float(request.form.get('valor_pago', 0) or 0)
        forma_pagamento = request.form.get('forma_pagamento', '')

        servico_ids = request.form.getlist('servico_id[]')
        servico_qtds = request.form.getlist('servico_qtd[]')
        servico_vals = request.form.getlist('servico_val[]')
        peca_ids = request.form.getlist('peca_id[]')
        peca_qtds = request.form.getlist('peca_qtd[]')
        peca_vals = request.form.getlist('peca_val[]')

        total_serv = 0
        for q, v in zip(servico_qtds, servico_vals):
            total_serv += int(q or 1) * float(v or 0)
        total_pec = 0
        for q, v in zip(peca_qtds, peca_vals):
            total_pec += int(q or 1) * float(v or 0)
        total_geral = total_serv + total_pec - desconto

        os_id = insert_id(
            conn,
            """INSERT INTO ordens_servico (cliente_id,veiculo_id,km_entrada,observacao,status,
               total_servicos,total_pecas,total_geral,desconto,valor_pago,forma_pagamento)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (cliente_id, veiculo_id, km_entrada, observacao, status,
             total_serv, total_pec, total_geral, desconto, valor_pago, forma_pagamento)
        )

        for sid, sq, sv in zip(servico_ids, servico_qtds, servico_vals):
            if sid:
                qtd = int(sq or 1)
                val = float(sv or 0)
                conn.execute(
                    "INSERT INTO os_servicos (os_id,servico_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)",
                    (os_id, sid, qtd, val, qtd * val)
                )

        for pid, pq, pv in zip(peca_ids, peca_qtds, peca_vals):
            if pid:
                qtd = int(pq or 1)
                val = float(pv or 0)
                conn.execute(
                    "INSERT INTO os_pecas (os_id,peca_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)",
                    (os_id, pid, qtd, val, qtd * val)
                )
                if status == 'fechada':
                    conn.execute("UPDATE pecas SET estoque_atual = estoque_atual - ? WHERE id=?", (qtd, pid))

        if cliente_id:
            conn.execute("UPDATE clientes SET ultimo_servico=CURRENT_TIMESTAMP WHERE id=?", (cliente_id,))

        if status == 'fechada':
            conn.execute("UPDATE ordens_servico SET data_fechamento=CURRENT_TIMESTAMP WHERE id=?", (os_id,))

        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'criar', 'os', os_id, f"OS #{os_id}")
        flash("Ordem de serviço criada", "success")
        return redirect(url_for('listar_os'))
    conn.close()
    return render_template('os/form.html', os={}, editando=False, clientes=clientes, servicos=servicos, pecas=pecas, veiculos=veiculos)

@app.route('/os/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_os(id):
    conn = get_connection()
    row = conn.execute(
        """SELECT o.*, c.nome as cliente_nome, v.placa
           FROM ordens_servico o
           LEFT JOIN clientes c ON o.cliente_id = c.id
           LEFT JOIN veiculos v ON o.veiculo_id = v.id
           WHERE o.id=?""", (id,)
    ).fetchone()
    if not row:
        conn.close()
        flash("OS não encontrada", "danger")
        return redirect(url_for('listar_os'))
    clientes = conn.execute("SELECT id, nome FROM clientes ORDER BY nome").fetchall()
    servicos = conn.execute("SELECT s.*, cs.nome as categoria_nome FROM servicos s LEFT JOIN categorias_servico cs ON s.categoria_id=cs.id ORDER BY s.nome").fetchall()
    pecas = conn.execute("SELECT p.*, cp.nome as categoria_nome FROM pecas p LEFT JOIN categorias_peca cp ON p.categoria_id=cp.id ORDER BY p.nome").fetchall()
    veiculos = conn.execute("SELECT v.id, v.placa, m.nome as marca, mo.nome as modelo FROM veiculos v LEFT JOIN marcas m ON v.marca_id=m.id LEFT JOIN modelos mo ON v.modelo_id=mo.id ORDER BY v.placa").fetchall()
    os_servicos = conn.execute(
        "SELECT s.*, sv.nome as servico_nome FROM os_servicos s LEFT JOIN servicos sv ON s.servico_id=sv.id WHERE s.os_id=?",
        (id,)
    ).fetchall()
    os_pecas = conn.execute(
        "SELECT p.*, pe.nome as peca_nome FROM os_pecas p LEFT JOIN pecas pe ON p.peca_id=pe.id WHERE p.os_id=?",
        (id,)
    ).fetchall()

    if request.method == 'POST':
        cliente_id = request.form.get('cliente_id')
        veiculo_id = request.form.get('veiculo_id') or None
        km_entrada = request.form.get('km_entrada') or None
        km_saida = request.form.get('km_saida') or None
        observacao = request.form.get('observacao', '')
        status = request.form.get('status', 'aberta')
        desconto = float(request.form.get('desconto', 0) or 0)
        valor_pago = float(request.form.get('valor_pago', 0) or 0)
        forma_pagamento = request.form.get('forma_pagamento', '')

        servico_ids = request.form.getlist('servico_id[]')
        peca_ids = request.form.getlist('peca_id[]')

        if servico_ids or peca_ids:
            conn.execute("DELETE FROM os_servicos WHERE os_id=?", (id,))
            conn.execute("DELETE FROM os_pecas WHERE os_id=?", (id,))
            servico_qtds = request.form.getlist('servico_qtd[]')
            servico_vals = request.form.getlist('servico_val[]')
            peca_qtds = request.form.getlist('peca_qtd[]')
            peca_vals = request.form.getlist('peca_val[]')
            total_serv = 0
            for q, v in zip(servico_qtds, servico_vals):
                total_serv += int(q or 1) * float(v or 0)
            total_pec = 0
            for q, v in zip(peca_qtds, peca_vals):
                total_pec += int(q or 1) * float(v or 0)
            for sid, sq, sv in zip(servico_ids, servico_qtds, servico_vals):
                if sid:
                    qtd = int(sq or 1); val = float(sv or 0)
                    conn.execute("INSERT INTO os_servicos (os_id,servico_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)", (id, sid, qtd, val, qtd * val))
            for pid, pq, pv in zip(peca_ids, peca_qtds, peca_vals):
                if pid:
                    qtd = int(pq or 1); val = float(pv or 0)
                    conn.execute("INSERT INTO os_pecas (os_id,peca_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)", (id, pid, qtd, val, qtd * val))
                    if status == 'fechada':
                        conn.execute("UPDATE pecas SET estoque_atual = estoque_atual - ? WHERE id=?", (qtd, pid))
        else:
            total_serv = conn.execute("SELECT COALESCE(SUM(subtotal),0) FROM os_servicos WHERE os_id=?", (id,)).fetchone()[0]
            total_pec = conn.execute("SELECT COALESCE(SUM(subtotal),0) FROM os_pecas WHERE os_id=?", (id,)).fetchone()[0]

        total_geral = total_serv + total_pec - desconto
        data_fechamento = None
        if status == 'fechada':
            data_fechamento = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn.execute(
            """UPDATE ordens_servico SET cliente_id=?,veiculo_id=?,km_entrada=?,km_saida=?,observacao=?,
               status=?,total_servicos=?,total_pecas=?,total_geral=?,desconto=?,valor_pago=?,
               forma_pagamento=?,data_fechamento=COALESCE(?,data_fechamento) WHERE id=?""",
            (cliente_id, veiculo_id, km_entrada, km_saida, observacao, status,
             total_serv, total_pec, total_geral, desconto, valor_pago, forma_pagamento,
             data_fechamento, id)
        )

        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'os', id, f"OS #{id}")
        flash("OS atualizada", "success")
        return redirect(url_for('listar_os'))
    conn.close()
    data = dict(row)
    return render_template('os/form.html', os=data, editando=True, clientes=clientes, servicos=servicos, pecas=pecas, veiculos=veiculos,
                           os_servicos=[dict(s) for s in os_servicos], os_pecas=[dict(p) for p in os_pecas])

@app.route('/os/<int:os_id>/servicos/add', methods=['POST'])
@login_required
def adicionar_servico_os(os_id):
    servico_id = request.form.get('servico_id')
    quantidade = int(request.form.get('quantidade', 1))
    valor = float(request.form.get('valor_unitario', 0))
    if servico_id:
        conn = get_connection()
        conn.execute("INSERT INTO os_servicos (os_id,servico_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)",
                     (os_id, servico_id, quantidade, valor, quantidade * valor))
        conn.commit()
        conn.close()
        flash("Serviço adicionado", "success")
    return redirect(url_for('editar_os', id=os_id))

@app.route('/os/<int:os_id>/servicos/<int:item_id>/remover', methods=['POST'])
@login_required
def remover_servico_os(os_id, item_id):
    conn = get_connection()
    conn.execute("DELETE FROM os_servicos WHERE id=? AND os_id=?", (item_id, os_id))
    conn.commit()
    conn.close()
    flash("Serviço removido", "success")
    return redirect(url_for('editar_os', id=os_id))

@app.route('/os/<int:os_id>/pecas/add', methods=['POST'])
@login_required
def adicionar_peca_os(os_id):
    peca_id = request.form.get('peca_id')
    quantidade = int(request.form.get('quantidade', 1))
    valor = float(request.form.get('valor_unitario', 0))
    if peca_id:
        conn = get_connection()
        conn.execute("INSERT INTO os_pecas (os_id,peca_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)",
                     (os_id, peca_id, quantidade, valor, quantidade * valor))
        conn.commit()
        conn.close()
        flash("Peça adicionada", "success")
    return redirect(url_for('editar_os', id=os_id))

@app.route('/os/<int:os_id>/pecas/<int:item_id>/remover', methods=['POST'])
@login_required
def remover_peca_os(os_id, item_id):
    conn = get_connection()
    conn.execute("DELETE FROM os_pecas WHERE id=? AND os_id=?", (item_id, os_id))
    conn.commit()
    conn.close()
    flash("Peça removida", "success")
    return redirect(url_for('editar_os', id=os_id))

@app.route('/os/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_os(id):
    conn = get_connection()
    row = conn.execute("SELECT id FROM ordens_servico WHERE id=?", (id,)).fetchone()
    if row:
        conn.execute("DELETE FROM os_pecas WHERE os_id=?", (id,))
        conn.execute("DELETE FROM os_servicos WHERE os_id=?", (id,))
        conn.execute("DELETE FROM ordens_servico WHERE id=?", (id,))
        conn.commit()
        log_acao(session['usuario_id'], session['usuario_nome'], 'excluir', 'os', id, f"OS #{id}")
        flash("OS excluída", "success")
    conn.close()
    return redirect(url_for('listar_os'))

@app.route('/pecas')
@login_required
def listar_pecas():
    busca = request.args.get('busca', '')
    conn = get_connection()
    sql = """SELECT p.*, cp.nome as categoria_nome
             FROM pecas p LEFT JOIN categorias_peca cp ON p.categoria_id=cp.id"""
    if busca:
        rows = conn.execute(sql + " WHERE p.nome LIKE ? OR p.codigo LIKE ? ORDER BY p.nome LIMIT 500",
                          (f"%{busca}%", f"%{busca}%")).fetchall()
    else:
        rows = conn.execute(sql + " ORDER BY p.nome LIMIT 500").fetchall()
    conn.close()
    return render_template('pecas/listar.html', pecas=[dict(r) for r in rows], busca=busca)

@app.route('/pecas/novo', methods=['GET', 'POST'])
@login_required
def criar_peca():
    conn = get_connection()
    categorias = conn.execute("SELECT id, nome FROM categorias_peca ORDER BY nome").fetchall()
    fornecedores = conn.execute("SELECT id, nome FROM fornecedores ORDER BY nome").fetchall()
    if request.method == 'POST':
        dados = {
            'codigo': request.form.get('codigo', ''),
            'nome': request.form.get('nome', ''),
            'descricao': request.form.get('descricao', ''),
            'categoria_id': request.form.get('categoria_id') or None,
            'fornecedor': request.form.get('fornecedor', ''),
            'preco_custo': request.form.get('preco_custo', 0),
            'preco_venda': request.form.get('preco_venda', 0),
            'estoque_atual': request.form.get('estoque_atual', 0),
            'estoque_minimo': request.form.get('estoque_minimo', 0),
        }
        foto = request.files.get('foto')
        if foto and foto.filename:
            filename = secure_filename(foto.filename)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'jpg'
            if ext not in ALLOWED_EXTENSIONS:
                flash("Tipo de arquivo não permitido", "danger")
                return redirect(url_for('listar_pecas'))
            nome_foto = f"peca_{int(time.time())}.{ext}"
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], nome_foto))
            dados['foto'] = nome_foto
        if not dados['nome']:
            flash("Nome é obrigatório", "danger")
            return render_template('pecas/form.html', peca=dados, editando=False, categorias=categorias, fornecedores=fornecedores)
        if not dados['codigo']:
            last = conn.execute("SELECT codigo FROM pecas WHERE codigo LIKE 'PEC-%' ORDER BY id DESC LIMIT 1").fetchone()
            num = int(last['codigo'].split('-')[1]) + 1 if last and last['codigo'] else 1
            dados['codigo'] = f"PEC-{num:04d}"
        pid = insert_id(
            conn,
            """INSERT INTO pecas (codigo,nome,descricao,categoria_id,fornecedor,preco_custo,preco_venda,estoque_atual,estoque_minimo,foto)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (dados['codigo'], dados['nome'], dados['descricao'], dados['categoria_id'],
             dados['fornecedor'], dados['preco_custo'], dados['preco_venda'],
             dados['estoque_atual'], dados['estoque_minimo'], dados.get('foto'))
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'criar', 'peca', pid, dados['nome'])
        flash("Peça criada", "success")
        return redirect(url_for('listar_pecas'))
    conn.close()
    return render_template('pecas/form.html', peca={}, editando=False, categorias=categorias, fornecedores=fornecedores)

@app.route('/pecas/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_peca(id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM pecas WHERE id=?", (id,)).fetchone()
    if not row:
        conn.close()
        flash("Peça não encontrada", "danger")
        return redirect(url_for('listar_pecas'))
    categorias = conn.execute("SELECT id, nome FROM categorias_peca ORDER BY nome").fetchall()
    fornecedores = conn.execute("SELECT id, nome FROM fornecedores ORDER BY nome").fetchall()
    if request.method == 'POST':
        foto = request.files.get('foto')
        foto_nome = row['foto']
        if foto and foto.filename:
            filename = secure_filename(foto.filename)
            ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'jpg'
            if ext not in ALLOWED_EXTENSIONS:
                flash("Tipo de arquivo não permitido", "danger")
                return redirect(url_for('listar_pecas'))
            foto_nome = f"peca_{int(time.time())}.{ext}"
            foto.save(os.path.join(app.config['UPLOAD_FOLDER'], foto_nome))
        conn.execute(
            """UPDATE pecas SET codigo=?,nome=?,descricao=?,categoria_id=?,fornecedor=?,preco_custo=?,preco_venda=?,
               estoque_atual=?,estoque_minimo=?,foto=? WHERE id=?""",
            (request.form.get('codigo',''), request.form.get('nome',''), request.form.get('descricao',''),
             request.form.get('categoria_id') or None, request.form.get('fornecedor',''),
             request.form.get('preco_custo',0), request.form.get('preco_venda',0),
             request.form.get('estoque_atual',0), request.form.get('estoque_minimo',0), foto_nome, id)
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'peca', id, row['nome'])
        flash("Peça atualizada", "success")
        return redirect(url_for('listar_pecas'))
    conn.close()
    return render_template('pecas/form.html', peca=dict(row), editando=True, categorias=categorias, fornecedores=fornecedores)

@app.route('/pecas/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_peca(id):
    conn = get_connection()
    row = conn.execute("SELECT nome FROM pecas WHERE id=?", (id,)).fetchone()
    if row:
        conn.execute("DELETE FROM pecas WHERE id=?", (id,))
        conn.commit()
        log_acao(session['usuario_id'], session['usuario_nome'], 'excluir', 'peca', id, row['nome'])
        flash("Peça excluída", "success")
    conn.close()
    return redirect(url_for('listar_pecas'))

@app.route('/fornecedores')
@login_required
def listar_fornecedores():
    busca = request.args.get('busca', '')
    conn = get_connection()
    if busca:
        rows = conn.execute("SELECT * FROM fornecedores WHERE nome LIKE ? ORDER BY nome LIMIT 200", (f"%{busca}%",)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM fornecedores ORDER BY nome LIMIT 500").fetchall()
    conn.close()
    return render_template('fornecedores/listar.html', fornecedores=[dict(r) for r in rows], busca=busca)

@app.route('/fornecedores/novo', methods=['GET', 'POST'])
@login_required
def criar_fornecedor():
    if request.method == 'POST':
        dados = {k: request.form.get(k, '') for k in ['nome','contato','telefone','email','endereco','observacao']}
        if not dados['nome']:
            flash("Nome é obrigatório", "danger")
            return render_template('fornecedores/form.html', fornecedor=dados, editando=False)
        conn = get_connection()
        novo_id = insert_id(
            conn,
            "INSERT INTO fornecedores (nome,contato,telefone,email,endereco,observacao) VALUES (?,?,?,?,?,?)",
            (dados['nome'], dados['contato'], dados['telefone'], dados['email'], dados['endereco'], dados['observacao'])
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'criar', 'fornecedor', novo_id, dados['nome'])
        flash("Fornecedor criado", "success")
        return redirect(url_for('listar_fornecedores'))
    return render_template('fornecedores/form.html', fornecedor={}, editando=False)

@app.route('/fornecedores/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_fornecedor(id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM fornecedores WHERE id=?", (id,)).fetchone()
    if not row:
        conn.close()
        flash("Fornecedor não encontrado", "danger")
        return redirect(url_for('listar_fornecedores'))
    if request.method == 'POST':
        conn.execute(
            "UPDATE fornecedores SET nome=?,contato=?,telefone=?,email=?,endereco=?,observacao=? WHERE id=?",
            (request.form.get('nome',''), request.form.get('contato',''), request.form.get('telefone',''),
             request.form.get('email',''), request.form.get('endereco',''), request.form.get('observacao',''), id)
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'fornecedor', id, row['nome'])
        flash("Fornecedor atualizado", "success")
        return redirect(url_for('listar_fornecedores'))
    conn.close()
    return render_template('fornecedores/form.html', fornecedor=dict(row), editando=True)

@app.route('/fornecedores/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_fornecedor(id):
    conn = get_connection()
    row = conn.execute("SELECT nome FROM fornecedores WHERE id=?", (id,)).fetchone()
    if row:
        conn.execute("DELETE FROM fornecedores WHERE id=?", (id,))
        conn.commit()
        log_acao(session['usuario_id'], session['usuario_nome'], 'excluir', 'fornecedor', id, row['nome'])
        flash("Fornecedor excluído", "success")
    conn.close()
    return redirect(url_for('listar_fornecedores'))

@app.route('/vendas')
@login_required
def listar_vendas():
    busca = request.args.get('busca', '')
    conn = get_connection()
    sql = """SELECT v.*, c.nome as cliente_nome
             FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id"""
    if busca:
        rows = conn.execute(sql + " WHERE c.nome LIKE ? ORDER BY v.id DESC LIMIT 500", (f"%{busca}%",)).fetchall()
    else:
        rows = conn.execute(sql + " ORDER BY v.id DESC LIMIT 500").fetchall()
    conn.close()
    return render_template('vendas/listar.html', vendas=[dict(r) for r in rows], busca=busca)

@app.route('/vendas/novo', methods=['GET', 'POST'])
@login_required
def criar_venda():
    conn = get_connection()
    clientes = conn.execute("SELECT id, nome FROM clientes ORDER BY nome").fetchall()
    pecas = conn.execute("SELECT * FROM pecas ORDER BY nome").fetchall()
    if request.method == 'POST':
        cliente_id = request.form.get('cliente_id') or None
        desconto = float(request.form.get('desconto', 0) or 0)
        valor_pago = float(request.form.get('valor_pago', 0) or 0)
        forma_pagamento = request.form.get('forma_pagamento', '')

        peca_ids = request.form.getlist('peca_id[]')
        peca_qtds = request.form.getlist('peca_qtd[]')
        peca_vals = request.form.getlist('peca_val[]')

        total = 0
        for q, v in zip(peca_qtds, peca_vals):
            total += int(q or 1) * float(v or 0)
        total_geral = total - desconto

        venda_id = insert_id(
            conn,
            "INSERT INTO vendas (cliente_id,total,desconto,valor_pago,forma_pagamento) VALUES (?,?,?,?,?)",
            (cliente_id, total_geral, desconto, valor_pago, forma_pagamento)
        )

        for pid, pq, pv in zip(peca_ids, peca_qtds, peca_vals):
            if pid:
                qtd = int(pq or 1)
                val = float(pv or 0)
                conn.execute(
                    "INSERT INTO venda_itens (venda_id,peca_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)",
                    (venda_id, pid, qtd, val, qtd * val)
                )
                conn.execute("UPDATE pecas SET estoque_atual = estoque_atual - ? WHERE id=?", (qtd, pid))

        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'criar', 'venda', venda_id, f"Venda #{venda_id}")
        flash("Venda criada", "success")
        return redirect(url_for('listar_vendas'))
    conn.close()
    return render_template('vendas/form.html', venda={}, editando=False, clientes=clientes, pecas=pecas)

@app.route('/vendas/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_venda(id):
    conn = get_connection()
    row = conn.execute(
        "SELECT v.*, c.nome as cliente_nome FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.id=?",
        (id,)
    ).fetchone()
    if not row:
        conn.close()
        flash("Venda não encontrada", "danger")
        return redirect(url_for('listar_vendas'))
    clientes = conn.execute("SELECT id, nome FROM clientes ORDER BY nome").fetchall()
    pecas = conn.execute("SELECT * FROM pecas ORDER BY nome").fetchall()
    itens = conn.execute(
        "SELECT vi.*, p.nome FROM venda_itens vi LEFT JOIN pecas p ON vi.peca_id=p.id WHERE vi.venda_id=?",
        (id,)
    ).fetchall()
    if request.method == 'POST':
        conn.execute("DELETE FROM venda_itens WHERE venda_id=?", (id,))
        cliente_id = request.form.get('cliente_id') or None
        desconto = float(request.form.get('desconto', 0) or 0)
        valor_pago = float(request.form.get('valor_pago', 0) or 0)
        forma_pagamento = request.form.get('forma_pagamento', '')

        peca_ids = request.form.getlist('peca_id[]')
        peca_qtds = request.form.getlist('peca_qtd[]')
        peca_vals = request.form.getlist('peca_val[]')

        total = 0
        for q, v in zip(peca_qtds, peca_vals):
            total += int(q or 1) * float(v or 0)
        total_geral = total - desconto

        conn.execute(
            "UPDATE vendas SET cliente_id=?,total=?,desconto=?,valor_pago=?,forma_pagamento=? WHERE id=?",
            (cliente_id, total_geral, desconto, valor_pago, forma_pagamento, id)
        )
        for pid, pq, pv in zip(peca_ids, peca_qtds, peca_vals):
            if pid:
                qtd = int(pq or 1)
                val = float(pv or 0)
                conn.execute(
                    "INSERT INTO venda_itens (venda_id,peca_id,quantidade,valor_unitario,subtotal) VALUES (?,?,?,?,?)",
                    (id, pid, qtd, val, qtd * val)
                )
                conn.execute("UPDATE pecas SET estoque_atual = estoque_atual - ? WHERE id=?", (qtd, pid))
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'venda', id, f"Venda #{id}")
        flash("Venda atualizada", "success")
        return redirect(url_for('listar_vendas'))
    conn.close()
    data = dict(row)
    return render_template('vendas/form.html', venda=data, editando=True, clientes=clientes, pecas=pecas,
                           itens=[dict(i) for i in itens])

@app.route('/vendas/<int:id>/cupom')
@login_required
def cupom_venda(id):
    conn = get_connection()
    venda = conn.execute(
        "SELECT v.*, c.nome as cliente_nome, c.cpf_cnpj, c.endereco, c.cidade, c.uf, c.telefone FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.id=?", (id,)
    ).fetchone()
    if not venda:
        conn.close()
        flash("Venda não encontrada", "danger")
        return redirect(url_for('listar_vendas'))
    itens = conn.execute(
        "SELECT vi.*, p.nome FROM venda_itens vi LEFT JOIN pecas p ON vi.peca_id=p.id WHERE vi.venda_id=?",
        (id,)
    ).fetchall()
    emp = conn.execute("SELECT * FROM empresa WHERE id=1").fetchone()
    conn.close()
    return render_template('vendas/cupom.html', venda=dict(venda), itens=[dict(i) for i in itens], emp=dict(emp) if emp else {})

@app.route('/vendas/<int:id>/recibo')
@login_required
def recibo_venda(id):
    conn = get_connection()
    venda = conn.execute(
        "SELECT v.*, c.nome as cliente_nome, c.cpf_cnpj, c.endereco, c.cidade, c.uf, c.telefone FROM vendas v LEFT JOIN clientes c ON v.cliente_id=c.id WHERE v.id=?", (id,)
    ).fetchone()
    if not venda:
        conn.close()
        flash("Venda não encontrada", "danger")
        return redirect(url_for('listar_vendas'))
    itens = conn.execute(
        "SELECT vi.*, p.nome FROM venda_itens vi LEFT JOIN pecas p ON vi.peca_id=p.id WHERE vi.venda_id=?",
        (id,)
    ).fetchall()
    emp = conn.execute("SELECT * FROM empresa WHERE id=1").fetchone()
    conn.close()
    return render_template('vendas/recibo.html', venda=dict(venda), itens=[dict(i) for i in itens], emp=dict(emp) if emp else {})

@app.route('/vendas/<int:id>/excluir', methods=['POST'])
@login_required
def excluir_venda(id):
    conn = get_connection()
    row = conn.execute("SELECT id FROM vendas WHERE id=?", (id,)).fetchone()
    if row:
        conn.execute("DELETE FROM venda_itens WHERE venda_id=?", (id,))
        conn.execute("DELETE FROM vendas WHERE id=?", (id,))
        conn.commit()
        log_acao(session['usuario_id'], session['usuario_nome'], 'excluir', 'venda', id, f"Venda #{id}")
        flash("Venda excluída", "success")
    conn.close()
    return redirect(url_for('listar_vendas'))

@app.route('/usuarios')
@login_required
def listar_usuarios():
    busca = request.args.get('busca', '')
    conn = get_connection()
    if busca:
        rows = conn.execute(
            "SELECT id, nome, username, email, admin, ativo FROM usuarios WHERE nome LIKE ? OR username LIKE ? ORDER BY nome",
            (f"%{busca}%", f"%{busca}%")
        ).fetchall()
    else:
        rows = conn.execute("SELECT id, nome, username, email, admin, ativo FROM usuarios ORDER BY nome").fetchall()
    conn.close()
    return render_template('usuarios/listar.html', usuarios=[dict(r) for r in rows], busca=busca)

@app.route('/usuarios/novo', methods=['GET', 'POST'])
@login_required
@admin_required
def criar_usuario():
    if request.method == 'POST':
        nome = request.form.get('nome', '')
        username = request.form.get('username', '').strip().lower()
        senha = request.form.get('senha', '')
        email = request.form.get('email', '')
        admin = 1 if request.form.get('admin') else 0
        ativo = 1 if request.form.get('ativo') else 1
        if not nome or not username or not senha:
            flash("Nome, usuário e senha são obrigatórios", "danger")
            return render_template('usuarios/form.html', usuario={}, editando=False)
        conn = get_connection()
        existente = conn.execute("SELECT id FROM usuarios WHERE username=?", (username,)).fetchone()
        if existente:
            conn.close()
            flash("Nome de usuário já existe", "danger")
            return render_template('usuarios/form.html', usuario={}, editando=False)
        conn.execute(
            "INSERT INTO usuarios (nome,username,email,senha_hash,admin,ativo) VALUES (?,?,?,?,?,?)",
            (nome, username, email, hash_senha(senha), admin, ativo)
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'criar', 'usuario', None, nome)
        flash("Usuário criado", "success")
        return redirect(url_for('listar_usuarios'))
    return render_template('usuarios/form.html', usuario={}, editando=False)

@app.route('/usuarios/<int:id>/editar', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM usuarios WHERE id=?", (id,)).fetchone()
    if not row:
        conn.close()
        flash("Usuário não encontrado", "danger")
        return redirect(url_for('listar_usuarios'))
    if request.method == 'POST':
        nome = request.form.get('nome', '')
        email = request.form.get('email', '')
        senha = request.form.get('senha', '')
        admin = 1 if request.form.get('admin') else 0
        ativo = 1 if request.form.get('ativo') else 1
        if senha:
            conn.execute("UPDATE usuarios SET nome=?,email=?,senha_hash=?,admin=?,ativo=? WHERE id=?",
                       (nome, email, hash_senha(senha), admin, ativo, id))
        else:
            conn.execute("UPDATE usuarios SET nome=?,email=?,admin=?,ativo=? WHERE id=?",
                       (nome, email, admin, ativo, id))
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'usuario', id, nome)
        flash("Usuário atualizado", "success")
        return redirect(url_for('listar_usuarios'))
    conn.close()
    return render_template('usuarios/form.html', usuario=dict(row), editando=True)

@app.route('/usuarios/<int:id>/excluir', methods=['POST'])
@login_required
@admin_required
def excluir_usuario(id):
    if id == session['usuario_id']:
        flash("Você não pode excluir seu próprio usuário", "danger")
        return redirect(url_for('listar_usuarios'))
    conn = get_connection()
    row = conn.execute("SELECT nome FROM usuarios WHERE id=?", (id,)).fetchone()
    if row:
        conn.execute("DELETE FROM usuarios WHERE id=?", (id,))
        conn.commit()
        log_acao(session['usuario_id'], session['usuario_nome'], 'excluir', 'usuario', id, row['nome'])
        flash("Usuário excluído", "success")
    conn.close()
    return redirect(url_for('listar_usuarios'))

@app.route('/relatorios')
@login_required
def relatorios():
    import datetime
    hoje = datetime.date.today()
    ini = request.args.get('inicio', hoje.replace(day=1).isoformat())
    fim = request.args.get('fim', hoje.isoformat())
    conn = get_connection()
    os_periodo = conn.execute(
        "SELECT COUNT(*) as total, COALESCE(SUM(total_geral),0) as faturamento FROM ordens_servico WHERE DATE(data_abertura) BETWEEN ? AND ?",
        (ini, fim)).fetchone()
    os_status = conn.execute(
        "SELECT status, COUNT(*) as qtd FROM ordens_servico WHERE DATE(data_abertura) BETWEEN ? AND ? GROUP BY status", (ini, fim)).fetchall()
    vendas_periodo = conn.execute(
        "SELECT COUNT(*) as total, COALESCE(SUM(total),0) as valor FROM vendas WHERE DATE(data) BETWEEN ? AND ?", (ini, fim)).fetchone()
    pecas_baixa = conn.execute(
        "SELECT COUNT(*) FROM pecas WHERE estoque_atual <= estoque_minimo AND estoque_minimo > 0").fetchone()[0]
    top_servicos = conn.execute(
        """SELECT sv.nome, COUNT(*) as qtd, COALESCE(SUM(s.subtotal),0) as total
           FROM os_servicos s JOIN servicos sv ON s.servico_id=sv.id
           WHERE s.id IN (SELECT id FROM os_servicos WHERE os_id IN (SELECT id FROM ordens_servico WHERE DATE(data_abertura) BETWEEN ? AND ?))
           GROUP BY sv.nome ORDER BY qtd DESC LIMIT 10""", (ini, fim)).fetchall()
    conn.close()
    return render_template('relatorios/index.html', ini=ini, fim=fim, os_periodo=dict(os_periodo),
                           os_status=[dict(r) for r in os_status], vendas_periodo=dict(vendas_periodo),
                           pecas_baixa=pecas_baixa, top_servicos=[dict(r) for r in top_servicos])

@app.route('/configuracoes', methods=['GET', 'POST'])
@login_required
@admin_required
def configuracoes():
    conn = get_connection()
    if request.method == 'POST':
        acao = request.form.get('acao')
        tabela = request.form.get('tabela')
        nome = request.form.get('nome', '').strip()
        marca_id = request.form.get('marca_id')
        if tabela not in TABELAS_PERMITIDAS:
            flash("Operação inválida", "danger")
        elif acao == 'add' and nome:
            if tabela == 'modelos' and marca_id:
                conn.execute("INSERT OR IGNORE INTO modelos (marca_id, nome) VALUES (?,?)", (marca_id, nome))
            else:
                conn.execute(f"INSERT OR IGNORE INTO {tabela} (nome) VALUES (?)", (nome,))
            flash(f"Adicionado a {tabela}", "success")
        elif acao == 'del':
            item_id = request.form.get('item_id')
            if item_id:
                conn.execute(f"DELETE FROM {tabela} WHERE id=?", (item_id,))
                flash(f"Removido de {tabela}", "success")
        conn.commit()
        return redirect(url_for('configuracoes'))
    marcas = conn.execute("SELECT * FROM marcas ORDER BY nome").fetchall()
    modelos = conn.execute("SELECT mo.*, ma.nome as marca_nome FROM modelos mo JOIN marcas ma ON mo.marca_id=ma.id ORDER BY ma.nome, mo.nome").fetchall()
    cores = conn.execute("SELECT * FROM cores ORDER BY nome").fetchall()
    cat_veic = conn.execute("SELECT * FROM categorias_veiculo ORDER BY nome").fetchall()
    cat_serv = conn.execute("SELECT * FROM categorias_servico ORDER BY nome").fetchall()
    cat_peca = conn.execute("SELECT * FROM categorias_peca ORDER BY nome").fetchall()
    conn.close()
    return render_template('configuracoes/index.html', marcas=marcas, modelos=modelos, cores=cores,
                           cat_veic=cat_veic, cat_serv=cat_serv, cat_peca=cat_peca)

@app.route('/perfil', methods=['GET', 'POST'])
@login_required
def perfil():
    conn = get_connection()
    row = conn.execute("SELECT * FROM usuarios WHERE id=?", (session['usuario_id'],)).fetchone()
    if request.method == 'POST':
        nome = request.form.get('nome', '')
        email = request.form.get('email', '')
        senha_atual = request.form.get('senha_atual', '')
        senha_nova = request.form.get('senha_nova', '')
        if not nome:
            flash("Nome é obrigatório", "danger")
            return render_template('perfil/index.html', usuario=dict(row))
        if senha_nova:
            if not check_password_hash(row['senha_hash'], senha_atual):
                flash("Senha atual incorreta", "danger")
                return render_template('perfil/index.html', usuario=dict(row))
            conn.execute("UPDATE usuarios SET nome=?, email=?, senha_hash=?, senha_trocada=1 WHERE id=?",
                         (nome, email, hash_senha(senha_nova), session['usuario_id']))
        else:
            conn.execute("UPDATE usuarios SET nome=?, email=? WHERE id=?",
                         (nome, email, session['usuario_id']))
        conn.commit()
        conn.close()
        session['usuario_nome'] = nome
        session['senha_trocada'] = 1
        flash("Perfil atualizado", "success")
        return redirect(url_for('perfil'))
    conn.close()
    return render_template('perfil/index.html', usuario=dict(row))

@app.route('/empresa', methods=['GET', 'POST'])
@login_required
def empresa():
    conn = get_connection()
    row = conn.execute("SELECT * FROM empresa WHERE id=1").fetchone()
    if request.method == 'POST':
        campos = ['razao_social', 'nome_fantasia', 'cnpj', 'ie', 'telefone', 'celular',
                   'email', 'website', 'cep', 'endereco', 'bairro', 'cidade', 'uf',
                   'slogan', 'observacao']
        valores = {k: request.form.get(k, '').strip() for k in campos}

        logo_path = row['logo_path'] if row else None
        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename and allowed_file(file.filename):
                fname = secure_filename(file.filename)
                ext = fname.rsplit('.', 1)[1].lower()
                logo_fname = f'logo.{ext}'
                logo_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'logo')
                os.makedirs(logo_dir, exist_ok=True)
                file.save(os.path.join(logo_dir, logo_fname))
                logo_path = f'uploads/logo/{logo_fname}'

        conn.execute(
            """UPDATE empresa SET
               razao_social=?, nome_fantasia=?, cnpj=?, ie=?, telefone=?, celular=?,
               email=?, website=?, cep=?, endereco=?, bairro=?, cidade=?, uf=?,
               slogan=?, observacao=?, logo_path=?
               WHERE id=1""",
            (valores['razao_social'] or None, valores['nome_fantasia'] or None,
             valores['cnpj'] or None, valores['ie'] or None,
             valores['telefone'] or None, valores['celular'] or None,
             valores['email'] or None, valores['website'] or None,
             valores['cep'] or None, valores['endereco'] or None,
             valores['bairro'] or None, valores['cidade'] or None,
             valores['uf'] or None, valores['slogan'] or None,
             valores['observacao'] or None, logo_path)
        )
        conn.commit()
        conn.close()
        log_acao(session['usuario_id'], session['usuario_nome'], 'editar', 'empresa')
        flash("Empresa atualizada", "success")
        return redirect(url_for('empresa'))
    conn.close()
    return render_template('empresa/form.html', emp=dict(row) if row else {})

@app.route('/historico')
@login_required
def historico():
    busca = request.args.get('busca', '')
    conn = get_connection()
    if busca:
        rows = conn.execute(
            "SELECT * FROM log_acoes WHERE usuario_nome LIKE ? OR acao LIKE ? OR entidade LIKE ? OR descricao LIKE ? ORDER BY id DESC LIMIT 500",
            (f"%{busca}%", f"%{busca}%", f"%{busca}%", f"%{busca}%")
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM log_acoes ORDER BY id DESC LIMIT 500").fetchall()
    conn.close()
    return render_template('historico/listar.html', registros=[dict(r) for r in rows], busca=busca)

def seed_all():
    conn = get_connection()
    def insert_if_empty(table, column, values):
        count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        if count > 0:
            return
        for val in values:
            conn.execute(f"INSERT OR IGNORE INTO {table} ({column}) VALUES (?)", (val,))
    insert_if_empty("marcas", "nome", MARCAS)
    insert_if_empty("cores", "nome", CORES)
    insert_if_empty("categorias_veiculo", "nome", CAT_VEICULO)
    insert_if_empty("categorias_servico", "nome", CAT_SERVICO)
    insert_if_empty("categorias_peca", "nome", CAT_PECA)

    count = conn.execute("SELECT COUNT(*) FROM fornecedores").fetchone()[0]
    if count == 0:
        for nome, tel, email in FORNECEDORES_PADRAO:
            conn.execute(
                "INSERT INTO fornecedores (nome, contato, telefone, email) VALUES (?,?,?,?)",
                (nome, nome.split()[0], tel, email)
            )

    count = conn.execute("SELECT COUNT(*) FROM servicos").fetchone()[0]
    if count == 0:
        for nome, desc, valor, cat_nome in SERVICOS_PADRAO:
            cat = conn.execute("SELECT id FROM categorias_servico WHERE nome=?", (cat_nome,)).fetchone()
            cat_id = cat['id'] if cat else None
            conn.execute(
                "INSERT INTO servicos (categoria_id, nome, descricao, valor_base) VALUES (?,?,?,?)",
                (cat_id, nome, desc, valor)
            )

    count = conn.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0]
    if count == 0:
        conn.execute(
            "INSERT INTO usuarios (nome,username,email,senha_hash,admin,ativo,senha_trocada) VALUES (?,?,?,?,?,?,0)",
            ("Administrador", "admin", "admin@oficina.com", hash_senha("admin"), 1, 1)
        )
        print("  Usuário admin criado (admin/admin) - altere a senha no primeiro acesso")

    sem_token = conn.execute("SELECT id FROM clientes WHERE token IS NULL OR token=''").fetchall()
    for row in sem_token:
        tok = uuid.uuid4().hex
        conn.execute("UPDATE clientes SET token=? WHERE id=?", (tok, row['id']))
    if sem_token:
        print(f"  Tokens gerados para {len(sem_token)} cliente(s)")

    conn.commit()
    conn.close()


if __name__ == '__main__':
    print("Inicializando banco de dados...")
    init_db()
    print("Populando dados iniciais...")
    seed_all()
    if is_postgres():
        print("Usando PostgreSQL (DATABASE_URL) em modo produção")
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug, host='0.0.0.0', port=port)
