from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

# Configuração da aplicação
app = Flask(__name__)
app.config['SECRET_KEY'] = 'chave-secreta-do-projeto'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicialização do banco de dados
db = SQLAlchemy(app)

# Configuração do login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Modelos
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    escola = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    materials = db.relationship('Material', backref='owner', lazy=True)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)

class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    condition = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='disponível')
    image_url = db.Column(db.String(200))
    post_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requests = db.relationship('Request', backref='material', lazy=True)

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pendente')
    request_date = db.Column(db.DateTime, default=datetime.utcnow)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    requester = db.relationship('User', foreign_keys=[requester_id], backref='requests_made')
    owner = db.relationship('User', foreign_keys=[owner_id], backref='requests_received')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Rotas
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/how_it_works')
def how_it_works():
    return render_template('how_it_works.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        escola = request.form.get('escola')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('As senhas não coincidem!', 'danger')
            return render_template('register.html')
        
        user_exists = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        if user_exists:
            flash('Nome de usuário ou email já existe!', 'danger')
            return render_template('register.html')
        
        user = User(username=username, email=email, escola=escola)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Conta criada com sucesso! Agora você pode fazer login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Login falhou. Verifique seu nome de usuário e senha.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/materials')
def all_materials():
    try:
        materials = Material.query.filter_by(status='disponível').all()
        return render_template('materials.html', materials=materials)
    except Exception as e:
        app.logger.error(f'Erro na rota de materiais: {e}')
        flash('Erro ao carregar materiais. Tente novamente.', 'danger')
        return render_template('materials.html', materials=[])

@app.route('/materials/<int:id>')
def material_detail(id):
    material = Material.query.get_or_404(id)
    return render_template('material_detail.html', material=material)

@app.route('/materials/new', methods=['GET', 'POST'])
@login_required
def new_material():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        condition = request.form.get('condition')
        image_url = request.form.get('image_url')
        
        material = Material(
            name=name,
            description=description,
            category=category,
            condition=condition,
            image_url=image_url,
            user_id=current_user.id
        )
        
        db.session.add(material)
        db.session.commit()
        
        flash('Material cadastrado com sucesso!', 'success')
        return redirect(url_for('my_materials'))
    
    return render_template('material_form.html', title='Novo Material')

@app.route('/materials/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_material(id):
    material = Material.query.get_or_404(id)
    
    if material.owner != current_user:
        flash('Você não tem permissão para editar este material.', 'danger')
        return redirect(url_for('material_detail', id=id))
    
    if request.method == 'POST':
        material.name = request.form.get('name')
        material.description = request.form.get('description')
        material.category = request.form.get('category')
        material.condition = request.form.get('condition')
        material.image_url = request.form.get('image_url')
        
        db.session.commit()
        
        flash('Material atualizado com sucesso!', 'success')
        return redirect(url_for('material_detail', id=id))
    
    return render_template('material_form.html', title='Editar Material', material=material)

@app.route('/materials/<int:id>/request', methods=['GET', 'POST'])
@login_required
def request_material(id):
    material = Material.query.get_or_404(id)
    
    if material.owner == current_user:
        flash('Você não pode solicitar seu próprio material.', 'danger')
        return redirect(url_for('material_detail', id=id))
    
    if material.status != 'disponível':
        flash('Este material não está mais disponível.', 'danger')
        return redirect(url_for('material_detail', id=id))
    
    if request.method == 'POST':
        message = request.form.get('message')
        
        material_request = Request(
            message=message,
            material_id=material.id,
            requester_id=current_user.id,
            owner_id=material.user_id
        )
        
        db.session.add(material_request)
        db.session.commit()
        
        flash('Solicitação enviada com sucesso!', 'success')
        return redirect(url_for('my_requests'))
    
    return render_template('request_form.html', material=material)

@app.route('/my-materials')
@login_required
def my_materials():
    materials = Material.query.filter_by(user_id=current_user.id).all()
    return render_template('my_materials.html', materials=materials)

@app.route('/my-requests')
@login_required
def my_requests():
    requests_made = Request.query.filter_by(requester_id=current_user.id).all()
    requests_received = Request.query.filter_by(owner_id=current_user.id).all()
    return render_template('my_requests.html', requests_made=requests_made, requests_received=requests_received)

@app.route('/requests/<int:id>/approve', methods=['POST'])
@login_required
def approve_request(id):
    req = Request.query.get_or_404(id)
    
    if req.owner != current_user:
        flash('Você não tem permissão para aprovar esta solicitação.', 'danger')
        return redirect(url_for('my_requests'))
    
    req.status = 'aceita'
    req.material.status = 'reservado'
    
    db.session.commit()
    
    flash('Solicitação aprovada com sucesso!', 'success')
    return redirect(url_for('my_requests'))

@app.route('/requests/<int:id>/reject', methods=['POST'])
@login_required
def reject_request(id):
    req = Request.query.get_or_404(id)
    
    if req.owner != current_user:
        flash('Você não tem permissão para recusar esta solicitação.', 'danger')
        return redirect(url_for('my_requests'))
    
    req.status = 'recusada'
    
    db.session.commit()
    
    flash('Solicitação recusada.', 'info')
    return redirect(url_for('my_requests'))

@app.route('/requests/<int:id>/complete', methods=['POST'])
@login_required
def complete_request(id):
    req = Request.query.get_or_404(id)
    
    if req.owner != current_user and req.requester != current_user:
        flash('Você não tem permissão para concluir esta solicitação.', 'danger')
        return redirect(url_for('my_requests'))
    
    req.status = 'concluída'
    req.material.status = 'doado'
    
    db.session.commit()
    
    flash('Doação concluída com sucesso!', 'success')
    return redirect(url_for('my_requests'))

# Criar banco de dados
def create_tables():
    try:
        db.create_all()
        print("Banco de dados criado com sucesso!")
    except Exception as e:
        print(f"Erro ao criar banco de dados: {e}")

# Inicializar banco de dados no contexto da aplicação
with app.app_context():
    create_tables()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
