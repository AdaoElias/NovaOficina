from app import app, init_db, ensure_empresa, seed_all

init_db()
ensure_empresa()
seed_all()
