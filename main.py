# Importar las librerías necesarias de Flask
from flask import Flask, render_template, request, redirect, session, flash
# Importar la extensión para bases de datos SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
# Importar funciones para seguridad de contraseñas
from werkzeug.security import generate_password_hash, check_password_hash

# Crear la aplicación Flask
app = Flask(__name__)
# Clave secreta para sesiones y seguridad de la app
app.secret_key = 'super-secret-key'  # Cambia esto por una clave segura en producción
# Configurar la base de datos SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///diary.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Inicializar la base de datos con la app
# Esto permite usar db.Model para crear tablas
# y db.session para interactuar con la base de datos
# (agregar, consultar, modificar, eliminar datos)
db = SQLAlchemy(app)

# Definir la tabla Card para las entradas del diario
class Card(db.Model):
    # id: identificador único de cada tarjeta
    id = db.Column(db.Integer, primary_key=True)
    # title: título de la tarjeta
    title = db.Column(db.String(100), nullable=False)
    # subtitle: descripción corta
    subtitle = db.Column(db.String(300), nullable=False)
    # text: contenido principal de la tarjeta
    text = db.Column(db.Text, nullable=False)

    # Representación de la tarjeta (útil para depuración)
    def __repr__(self):
        return f'<Card {self.id}>'
    
#Asignación #2. Crear la tabla Usuario
# Definir la tabla User para los usuarios registrados
class User(db.Model):
    # id: identificador único de usuario
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # login: correo electrónico del usuario
    login = db.Column(db.String(100),  nullable=False)
    # password: contraseña del usuario (ahora se almacena como hash seguro)
    password = db.Column(db.String(128), nullable=False)  # Aumenta el tamaño para hash

# Ruta principal: login de usuario
@app.route('/', methods=['GET','POST'])
def login():
        error = ''
        if request.method == 'POST':
            # Obtener datos del formulario
            form_login = request.form['email']
            form_password = request.form['password']
            #Asignación #4. Aplicar la autorización
            # Buscar usuario por login y verificar contraseña usando hash seguro
            user = User.query.filter_by(login=form_login).first()
            if user and check_password_hash(user.password, form_password):
                # Guardar datos del usuario en la sesión para mantenerlo logueado
                session['user_id'] = user.id
                session['user_login'] = user.login
                return redirect('/index')
            else:
                error = 'Nombre de usuario o contraseña incorrectos'
                # Mostrar mensaje de error usando flash
                flash(error, 'danger')
            return render_template('login.html', error=error)
        else:
            # Si es GET, mostrar el formulario de login
            return render_template('login.html')

# Ruta para cerrar sesión
@app.route('/logout')
def logout():
    # Limpiar la sesión y mostrar mensaje
    session.clear()
    flash('Sesión cerrada correctamente.', 'info')
    return redirect('/')

# Ruta de registro de usuario
@app.route('/reg', methods=['GET','POST'])
def reg():
    if request.method == 'POST':
        # Obtener datos del formulario
        login= request.form['email']
        password = request.form['password']
        #Asignación #3. Hacer que los datos del usuario se registren en la base de datos.
        # Verificar si el usuario ya existe
        existing_user = User.query.filter_by(login=login).first()
        if existing_user:
            error = 'El usuario ya existe'
            flash(error, 'warning')
            return render_template('registration.html', error=error)
        # Guardar el usuario con la contraseña encriptada (hash)
        user = User()
        user.login = login
        user.password = generate_password_hash(password)
        db.session.add(user)
        db.session.commit()
        flash('Usuario registrado correctamente. Inicia sesión.', 'success')
        return redirect('/')
    else:
        # Si es GET, mostrar el formulario de registro
        return render_template('registration.html')

# Decorador para requerir login en rutas protegidas
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Si el usuario no está logueado, redirigir al login
        if 'user_id' not in session:
            flash('Debes iniciar sesión para acceder a esta página.', 'warning')
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

# Página principal después de iniciar sesión
@app.route('/index')
@login_required
def index():
    # Visualización de las entradas de la base de datos
    # Consulta todas las tarjetas ordenadas por id
    cards = Card.query.order_by(Card.id).all()
    return render_template('index.html', cards=cards)

# Página para ver una tarjeta específica
@app.route('/card/<int:id>')
@login_required
def card(id):
    # Buscar la tarjeta por id
    card = Card.query.get(id)
    return render_template('card.html', card=card)

# Página para mostrar el formulario de creación de tarjeta
@app.route('/create')
@login_required
def create():
    return render_template('create_card.html')

# El formulario de inscripción de nuevas tarjetas
@app.route('/form_create', methods=['GET','POST'])
@login_required
def form_create():
    if request.method == 'POST':
        # Obtener datos del formulario
        title =  request.form['title']
        subtitle = request.form['subtitle']
        text = request.form['text']

        # Creación de un objeto que se enviará a la base de datos
        card = Card()
        card.title = title
        card.subtitle = subtitle
        card.text = text

        db.session.add(card)
        db.session.commit()
        flash('Tarjeta creada correctamente.', 'success')
        # Redirigir a la página principal después de crear la tarjeta
        return redirect('/index')
    else:
        # Si es GET, mostrar el formulario de creación
        return render_template('create_card.html')

# Ejecutar la aplicación en modo debug
if __name__ == "__main__":
    app.run(debug=True)
