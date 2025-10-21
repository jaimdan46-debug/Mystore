import os
import sqlite3
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    current_user, login_required
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Importacion de la configuracion general y funciones en formato de estrategia 

DB_NAME = "database.db"
UPLOAD_FOLDER = os.path.join("static", "images")

app = Flask(__name__)
app.secret_key = "tu_clave_secreta"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Funciones de la base de datos en general y configuracion extra 

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Crea base de datos y tablas si no existen"""
    conn = get_db_connection()

    # Crear tablas
    conn.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT,
        price REAL NOT NULL,
        description TEXT,
        image TEXT
    )''')

    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0
    )''')

    conn.execute('''CREATE TABLE IF NOT EXISTS cart (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        quantity INTEGER
    )''')

    # 🔧 Asegurar columna reset_token
    try:
        conn.execute("ALTER TABLE users ADD COLUMN reset_token TEXT;")
    except sqlite3.OperationalError:
        pass  # ya existe

    # Productos de ejemplo
    existing = conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]
    if existing == 0:
        conn.executemany('INSERT INTO products (name, category, price, description, image) VALUES (?, ?, ?, ?, ?)', [
            ("Auriculares Gamer", "Electrónica", 1200, "Auriculares con sonido envolvente.", "headset.jpg"),
            ("Camiseta Moderna", "Ropa", 350, "Camiseta con estampado moderno.", "shirt.jpg"),
            ("Smartwatch", "Electrónica", 2500, "Reloj inteligente multifunción.", "watch.jpg"),
            ("Zapatos Deportivos", "Ropa", 1800, "Zapatos cómodos y modernos.", "shoes.jpg")
        ])

    # Configuracion especifica para el usuario "Admin"
    admin_exists = conn.execute("SELECT * FROM users WHERE email = 'admin@tienda.com'").fetchone()
    if not admin_exists:
        conn.execute(
            "INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)",
            ("admin@tienda.com", generate_password_hash("admin123"), 1)
        )

    conn.commit()
    conn.close()

# Modelo especifico para el usuario

class User(UserMixin):
    def __init__(self, id, email, password, is_admin):
        self.id = id
        self.email = email
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user["id"], user["email"], user["password"], user["is_admin"])
    return None

# =================== Rutas principales ===================

@app.route("/")
def home():
    conn = get_db_connection()
    products = conn.execute("SELECT * FROM products LIMIT 4").fetchall()
    conn.close()
    return render_template("home.html", products=products)

@app.route("/catalog")
def catalog():
    category = request.args.get("category")
    conn = get_db_connection()
    if category:
        products = conn.execute("SELECT * FROM products WHERE category = ?", (category,)).fetchall()
    else:
        products = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return render_template("catalog.html", products=products)

@app.route("/product/<int:product_id>")
def product(product_id):
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    conn.close()
    if product:
        return render_template("product.html", product=product)
    return redirect(url_for("catalog"))

# =================== Carrito de compras  ===================

@app.route("/cart")
def cart():
    conn = get_db_connection()
    items = conn.execute('''
        SELECT cart.id, cart.product_id, products.name, products.price, products.image, cart.quantity
        FROM cart
        JOIN products ON cart.product_id = products.id
    ''').fetchall()
    conn.close()
    total = sum(item["price"] * item["quantity"] for item in items)
    return render_template("cart.html", items=items, total=total)

@app.route("/add_to_cart/<int:product_id>")
def add_to_cart(product_id):
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM cart WHERE product_id = ?", (product_id,)).fetchone()
    if item:
        conn.execute("UPDATE cart SET quantity = quantity + 1 WHERE product_id = ?", (product_id,))
    else:
        conn.execute("INSERT INTO cart (product_id, quantity) VALUES (?, ?)", (product_id, 1))
    conn.commit()
    conn.close()
    flash("Producto agregado al carrito ✅")
    return redirect(url_for("catalog"))

@app.route("/remove_from_cart/<int:product_id>", methods=["POST"])
def remove_from_cart(product_id):
    conn = get_db_connection()
    item = conn.execute("SELECT * FROM cart WHERE product_id = ?", (product_id,)).fetchone()
    if item:
        if item["quantity"] > 1:
            conn.execute("UPDATE cart SET quantity = quantity - 1 WHERE product_id = ?", (product_id,))
        else:
            conn.execute("DELETE FROM cart WHERE product_id = ?", (product_id,))
        conn.commit()
    conn.close()
    flash("Producto eliminado del carrito 🗑️")
    return redirect(url_for("cart"))

# =================== Login / Registro ===================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            login_user(User(user["id"], user["email"], user["password"], user["is_admin"]))
            flash("Has iniciado sesión correctamente ✅")
            return redirect(url_for("admin_panel" if user["is_admin"] else "home"))
        else:
            flash("Correo o contraseña incorrectos ❌")
            return render_template("login.html", show_forgot=True)  # muestra enlace
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        exists = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if exists:
            flash("Este correo ya está registrado ⚠️")
        else:
            conn.execute("INSERT INTO users (email, password) VALUES (?, ?)",
                         (email, generate_password_hash(password)))
            conn.commit()
            flash("Cuenta creada exitosamente 🎉 Ahora inicia sesión.")
        conn.close()
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Has cerrado sesión 👋")
    return redirect(url_for("home"))

# =================== Metodo de recuperar contraseña  ===================

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(16)
            conn.execute("UPDATE users SET reset_token = ? WHERE email = ?", (token, email))
            conn.commit()
            flash(f"Enlace para restablecer: {url_for('reset_password', token=token, _external=True)}")
        else:
            flash("No se encontró una cuenta con ese correo ⚠️")
        conn.close()
    return render_template("forgot_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE reset_token = ?", (token,)).fetchone()
    if not user:
        conn.close()
        flash("Token inválido o expirado ❌")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form["password"]
        conn.execute("UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
                     (generate_password_hash(new_password), user["id"]))
        conn.commit()
        conn.close()
        flash("Contraseña actualizada correctamente ✅")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html", token=token)

# ===================== Panel de administrador =====================

@app.route("/admin", methods=["GET"])
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash("Acceso denegado ❌")
        return redirect(url_for("home"))

    conn = get_db_connection()
    products = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return render_template("admin.html", products=products)

@app.route("/admin/add_product", methods=["POST"])
@login_required
def add_product():
    if not current_user.is_admin:
        flash("No tienes permisos para esta acción 🚫")
        return redirect(url_for("home"))

    name = request.form["name"]
    category = request.form["category"]
    price = float(request.form["price"])
    description = request.form["description"]
    image_file = request.files.get("image_file")

    image_name = "placeholder.jpg"
    if image_file and image_file.filename != "":
        image_name = secure_filename(image_file.filename)
        image_path = os.path.join(app.config["UPLOAD_FOLDER"], image_name)
        image_file.save(image_path)

    conn = get_db_connection()
    conn.execute(
        "INSERT INTO products (name, category, price, description, image) VALUES (?, ?, ?, ?, ?)",
        (name, category, price, description, image_name)
    )
    conn.commit()
    conn.close()
    flash("Producto agregado correctamente ✅")
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete_product/<int:product_id>", methods=["POST"])
@login_required
def delete_product(product_id):
    if not current_user.is_admin:
        flash("No tienes permisos para esta acción 🚫")
        return redirect(url_for("home"))

    conn = get_db_connection()
    conn.execute("DELETE FROM products WHERE id = ?", (product_id,))
    conn.commit()
    conn.close()
    flash("🗑️ Producto eliminado correctamente")
    return redirect(url_for("admin_panel"))

# ====================================================

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
