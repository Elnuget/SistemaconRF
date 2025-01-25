from flask import Flask, render_template, request, session, redirect, url_for, flash, jsonify, send_from_directory
import config
from flask_mysqldb import MySQL
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import uuid
from flask_mail import Mail, Message
from random import randint
from werkzeug.security import generate_password_hash, check_password_hash
import cv2
import numpy as np
import base64
from PIL import Image
import io
import face_recognition
from functools import wraps

# Inicializar la aplicación Flask
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER

# Configuración de la base de datos y claves
app.config['SECRET_KEY'] = config.HEX_SEC_KEY
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB
app.config['EMAIL_PASSWORD'] = config.EMAIL_PASSWORD
app.config['EMAIL_ADMIN'] = config.EMAIL_ADMIN

# Inicialización de MySQL
mysql = MySQL(app)

@app.route('/')
def home():
    if 'email' not in session:
        return render_template('index.html')
    
    if not is_verified_user(session['email']):
        flash('Debes verificar tu correo electrónico antes de acceder', 'warning')
        return redirect(url_for('verify_email'))
    
    return render_template('home.html', title='Inicio')

@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    if user is not None and check_password_hash(user[4], password):
        # Si el usuario no está verificado
        if not user[7]:  # Asumiendo que verified es la columna 7
            session['email'] = email  # Guardamos el email en la sesión
            session['name'] = user[1]  # Guardamos el nombre en la sesión
            flash('Por favor verifica tu correo electrónico antes de continuar', 'warning')
            return redirect(url_for('verify_email'))
        
        # Si el usuario está verificado
        session['email'] = email
        session['name'] = user[1]
        session['surnames'] = user[2]
        session['is_admin'] = user[9]
        # Agregar notificación
        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO notifications (email, notification, status) VALUES (%s, %s, 'Activa')",
            (email, f"Nuevo inicio de sesión - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        )
        mysql.connection.commit()
        cur.close()
        ip_address = request.remote_addr
        subject = "Notificación de inicio de sesión"
        body = f"Se ha iniciado sesión el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} desde la IP {ip_address}."
        send_email(subject, body, email)
        return redirect(url_for('home'))
    else:
        flash('Las credenciales no son correctas', 'danger')
        return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        surnames = request.form['surnames']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        profile_photo = request.form.get('profile_photo')

        if not name or not surnames or not email or not password or not confirm_password:
            flash('Todos los campos son obligatorios', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Las contraseñas no coinciden', 'danger')
            return redirect(url_for('register'))

        cur = mysql.connection.cursor()
        # Verificar si el correo ya está registrado
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()
        if existing_user:
            cur.close()
            flash('El correo electrónico ya está registrado. Por favor, usa otro correo.', 'danger')
            return redirect(url_for('register'))

        # Encriptar la contraseña
        hashed_password = generate_password_hash(password)

        # Procesar la foto de perfil si existe
        filename = None
        if profile_photo and profile_photo.startswith('data:image'):
            # Extraer los datos base64 de la imagen
            import base64
            format, imgstr = profile_photo.split(';base64,')
            ext = format.split('/')[-1]
            
            # Generar nombre único para el archivo
            filename = f"{str(uuid.uuid4())}.{ext}"
            
            # Decodificar y guardar la imagen
            with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'wb') as f:
                f.write(base64.b64decode(imgstr))

        # Generar código de verificación
        verification_code = randint(100000, 999999)
        verification_sent_time = datetime.now()
        sql = """INSERT INTO users 
                (name, surnames, email, password, verification_code, verified, 
                 verification_sent_time, profile_image) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
        data = (name, surnames, email, hashed_password, verification_code, 
                False, verification_sent_time, filename)
        cur.execute(sql, data)
        mysql.connection.commit()
        cur.close()

        # Enviar correo de verificación
        subject = "Código de Verificación"
        body = f"Hola {name},\n\nTu código de verificación es: {verification_code}"
        send_email(subject, body, email)

        session['email'] = email
        session['name'] = name

        flash('Usuario registrado correctamente. Por favor, verifica tu correo electrónico.', 'success')
        return redirect(url_for('verify_email'))

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        verification_code = request.form['verification_code']

        if 'email' in session:
            email = session['email']
            cur = mysql.connection.cursor()
            cur.execute("SELECT name, verification_code, verification_sent_time FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

            if user:
                name, stored_code, verification_sent_time = user
                current_time = datetime.now()
                time_diff = current_time - verification_sent_time

                if time_diff > timedelta(minutes=10):
                    # Eliminar al usuario
                    cur.execute("DELETE FROM users WHERE email = %s", (email,))
                    mysql.connection.commit()
                    cur.close()
                    session.clear()
                    flash('El tiempo para verificar tu correo ha expirado. Tu cuenta ha sido eliminada. Por favor, regístrate nuevamente.', 'danger')
                    return redirect(url_for('register'))

                elif time_diff <= timedelta(minutes=5) and stored_code == int(verification_code):
                    cur.execute("UPDATE users SET verified = True WHERE email = %s", (email,))
                    mysql.connection.commit()
                    cur.close()

                    if 'name' not in session:
                        session['name'] = name

                    # Enviar correo de bienvenida
                    subject = "Bienvenido a Task Manager"
                    body = f"Hola {session['name']},\n\nTu cuenta ha sido verificada exitosamente."
                    send_email(subject, body, email)

                    flash('Correo verificado correctamente', 'success')
                    return redirect(url_for('home'))
                else:
                    flash('Código de verificación incorrecto o ha expirado. Por favor, intenta nuevamente.', 'danger')
                    cur.close()
            else:
                flash('No se ha encontrado un email en la sesión. Por favor, regístrate o inicia sesión nuevamente.', 'danger')
                return redirect(url_for('register'))

    return render_template('verify_email.html')

@app.route('/resend_verification', methods=['POST'])
def resend_verification():
    if 'email' in session:
        email = session['email']
        cur = mysql.connection.cursor()
        cur.execute("SELECT name FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if user:
            name = user[0]
            verification_code = randint(100000, 999999)
            verification_sent_time = datetime.now()
            cur.execute("UPDATE users SET verification_code = %s, verification_sent_time = %s WHERE email = %s",
                        (verification_code, verification_sent_time, email))
            mysql.connection.commit()
            cur.close()

            subject = "Nuevo Código de Verificación"
            body = f"Hola {name},\n\nTu nuevo código de verificación es: {verification_code}"
            send_email(subject, body, email)

            flash('Nuevo código de verificación reenviado. Por favor, revisa tu correo electrónico.', 'success')
        else:
            flash('No se ha encontrado el usuario. Por favor, regístrate o inicia sesión nuevamente.', 'danger')
            cur.close()
    else:
        flash('No se ha encontrado un email en la sesión. Por favor, regístrate o inicia sesión nuevamente.', 'danger')
        return redirect(url_for('register'))

    return redirect(url_for('verify_email'))

def is_verified_user(email):
    cur = mysql.connection.cursor()
    cur.execute("SELECT verified FROM users WHERE email = %s", [email])
    user = cur.fetchone()
    cur.close()
    return user and user[0]

# Configuración de Flask-Mail
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = 'ce1794111e38a8'
app.config['MAIL_PASSWORD'] = '8cd7f9996fd6e1'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

def send_email(subject, body, to_email):
    try:
        msg = Message(
            subject=subject,
            sender=app.config['MAIL_USERNAME'],
            recipients=[to_email],
            body=body
        )
        with app.app_context():
            mail.send(msg)
        print("Correo enviado exitosamente")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE_MB = 2

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload-profile-image', methods=['POST'])
def upload_profile_image():
    if 'email' not in session:
        return jsonify({'error': 'Debes iniciar sesión primero'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No se ha seleccionado ningún archivo'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No se ha seleccionado ningún archivo'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Formato de archivo no permitido.'}), 400
    
    if 'file' in request.files:
        file_size_mb = request.cookies.get('file_size_mb')
        if file_size_mb and float(file_size_mb) > MAX_FILE_SIZE_MB:
            return jsonify({'error': f'El tamaño máximo permitido es {MAX_FILE_SIZE_MB} MB'}), 400
    
    if request.method == 'POST':
        file = request.files['file']
        cur = mysql.connection.cursor()
        cur.execute("SELECT profile_image FROM users WHERE email = %s", (session['email'],))
        previous_profile_image = cur.fetchone()
        cur.close()

        if previous_profile_image:
            previous_filename = previous_profile_image[0]
            if previous_filename:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], previous_filename))
                except FileNotFoundError:
                    pass

        filename = str(uuid.uuid4()) + secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        cur = mysql.connection.cursor()
        cur.execute("UPDATE users SET profile_image = %s WHERE email = %s", (filename, session['email']))
        mysql.connection.commit()
        cur.close()

        return jsonify({'message': 'Imagen de perfil actualizada correctamente'}), 200
    else:
        return jsonify({'error': 'Método no permitido'}), 405

@app.route('/uploaded-profile-image/<filename>')
def uploaded_profile_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/get-profile-image-url-master')
def get_profile_image_url_master():
    try:
        email = session.get('email')
        if (email):
            user_id = get_user_id_by_email(email)
            if (user_id):
                cur = mysql.connection.cursor()
                cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))
                profile_image = cur.fetchone()
                cur.close()
                profile_image_name = profile_image[0]
                if profile_image_name is None or not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], profile_image_name)):
                    profile_image_name = "perfil-por-defecto.png"
                    profile_image_url = f"/uploaded-profile-image/{profile_image_name}"
                    return jsonify({'profile_image_url': profile_image_url})
                else:
                    profile_image_url = f"/uploaded-profile-image/{profile_image_name}"
                    return jsonify({'profile_image_url': profile_image_url})
            return jsonify({'profile_image_url': '/static/Profile_image/default_profile.jpg'})
        else:
            return jsonify({'error': 'Correo electrónico no encontrado en la sesión'})
    except Exception as e:
        return jsonify({'error': str(e)})

def get_user_id_by_email(email):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))
    user_id = cur.fetchone()
    cur.close()
    if user_id:
        return user_id[0]
    else:
        return None

# Rutas de API para notificaciones
@app.route('/api/notifications', methods=['GET'])
def api_notifications():
    """
    Obtiene las notificaciones del usuario actual.
    Se ejecuta una sola vez cuando se carga la página o cuando el usuario interactúa con el botón de notificaciones.
    """
    if 'email' not in session:
        return jsonify({'error': 'Usuario no autenticado'}), 401

    email = session['email']
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM `notifications` WHERE email = %s ORDER BY id DESC", [email])
    notifications = cur.fetchall()
    cur.close()

    notifications_list = [{'id': n[0], 'notification': n[2], 'status': n[3]} for n in notifications]
    return jsonify(notifications_list)

@app.route('/api/update-notifications', methods=['POST'])
def update_notifications():
    """
    Actualiza el estado de las notificaciones a 'Inactiva'.
    Se ejecuta solo cuando el usuario hace clic en el botón de notificaciones.
    """
    if 'email' not in session:
        return jsonify({'error': 'Usuario no autenticado'}), 401

    email = session['email']
    try:
        conn = mysql.connection
        cur = conn.cursor()
        cur.execute("UPDATE notifications SET status = 'Inactiva' WHERE email = %s AND status = 'Activa'", [email])
        conn.commit()
        cur.close()
        return jsonify({'message': 'Notificaciones actualizadas correctamente'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#######################################################
# 1) Enviar también el 'id' de cada usuario con su imagen
#######################################################
@app.route('/get-user-images', methods=['GET'])
def get_user_images():
    """
    Retorna una lista de diccionarios con {id, image} donde:
      - id: el ID del usuario en la BD
      - image: la imagen en base64
    """
    try:
        cur = mysql.connection.cursor()
        # Traemos id y filename de quienes tengan una imagen
        cur.execute("SELECT id, profile_image FROM users WHERE profile_image IS NOT NULL")
        rows = cur.fetchall()
        cur.close()

        user_images = []
        for row in rows:
            user_id = row[0]
            profile_image_name = row[1]
            profile_image_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_image_name)

            # Verificamos que el archivo exista
            if (os.path.exists(profile_image_path)):
                with open(profile_image_path, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                    user_images.append({
                        'id': user_id,
                        'image': encoded_string
                    })

        return jsonify(user_images)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

#######################################################
# 2) Detectar cara y devolver "closest match" usando face_recognition
#######################################################
@app.route('/detect-face', methods=['POST'])
def detect_face():
    try:
        data = request.json['image']
        user_images = request.json['user_images']

        # 2.1) Decodificar la imagen capturada de la webcam
        image_data = data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        pil_image = Image.open(io.BytesIO(image_bytes))
        
        # Convertir a formato numpy (RGB)
        rgb_image = np.array(pil_image.convert('RGB'))

        # 2.2) Usar face_recognition para detectar si hay rostros
        face_locations = face_recognition.face_locations(rgb_image)
        if len(face_locations) == 0:
            return jsonify({'face_detected': False})

        # Tomamos el primer rostro
        detected_face_encoding = face_recognition.face_encodings(rgb_image, face_locations)[0]

        # 2.3) Comparar con todas las imágenes de usuarios
        closest_match = None
        closest_distance = float('inf')

        for user_img in user_images:
            user_id = user_img['id']
            encoded_user_image = user_img['image']

            # Decodificar la imagen del usuario
            user_image_bytes = base64.b64decode(encoded_user_image)
            user_image_np = np.array(Image.open(io.BytesIO(user_image_bytes)).convert('RGB'))

            # Si no se detectan rostros en la imagen del usuario, continuamos
            encodings = face_recognition.face_encodings(user_image_np)
            if not encodings:
                continue

            # Obtenemos el primer encoding
            user_face_encoding = encodings[0]
            distance = face_recognition.face_distance([user_face_encoding], detected_face_encoding)[0]

            if distance < closest_distance:
                closest_distance = distance
                closest_match = {
                    'id': user_id,
                    'image': encoded_user_image
                }

        # 2.4) Si encontramos al menos un "closest match", lo devolvemos
        if closest_match:
            return jsonify({
                'face_detected': True,
                'closest_match': f"data:image/jpeg;base64,{closest_match['image']}"
            })
        else:
            return jsonify({'face_detected': True, 'closest_match': None})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

#######################################################
# 3) Login con rostro
#######################################################
@app.route('/login-face', methods=['POST'])
def login_face():
    try:
        data = request.json['image']
        user_images = request.json['user_images']

        # Decodificar la imagen de la webcam
        image_data = data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        pil_image = Image.open(io.BytesIO(image_bytes))
        rgb_image = np.array(pil_image.convert('RGB'))

        # Detección de rostros
        face_locations = face_recognition.face_locations(rgb_image)
        if len(face_locations) == 0:
            return jsonify({'success': False, 'message': 'No se detecta rostro'})

        # Tomamos solo el primer rostro
        detected_face_encoding = face_recognition.face_encodings(rgb_image, face_locations)[0]

        # Comparamos con las imágenes de la BD
        for user_img in user_images:
            user_id = user_img['id']
            encoded_user_image = user_img['image']

            # Decodificar la imagen del usuario
            user_image_bytes = base64.b64decode(encoded_user_image)
            user_image_np = np.array(Image.open(io.BytesIO(user_image_bytes)).convert('RGB'))

            user_face_encodings = face_recognition.face_encodings(user_image_np)
            if not user_face_encodings:
                continue

            user_face_encoding = user_face_encodings[0]
            matches = face_recognition.compare_faces([user_face_encoding], detected_face_encoding)

            if matches[0]:
                # Coincidencia encontrada, iniciamos sesión
                cur = mysql.connection.cursor()
                cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                user = cur.fetchone()
                cur.close()

                if user:
                    # user = (id, name, surnames, email, password, ..., verified, profile_image, etc.)
                    session['email'] = user[3]
                    session['name'] = user[1]
                    session['surnames'] = user[2]
                    session['is_admin'] = user[9]
                    # Agregar notificación
                    cur = mysql.connection.cursor()
                    cur.execute(
                        "INSERT INTO notifications (email, notification, status) VALUES (%s, %s, 'Activa')",
                        (user[3], f"Nuevo inicio de sesión (rostro) - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    )
                    mysql.connection.commit()
                    cur.close()
                    ip_address = request.remote_addr
                    subject = "Notificación de inicio de sesión (Rostro)"
                    body = f"Se ha iniciado sesión el {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} desde la IP {ip_address}."
                    send_email(subject, body, user[3])
                    return jsonify({'success': True})
                else:
                    return jsonify({'success': False, 'message': 'Usuario no encontrado'})

        return jsonify({'success': False, 'message': 'No se encontró una coincidencia'})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})
        
@app.route('/simple-detect-face', methods=['POST'])
def simple_detect_face():
    """
    Endpoint que solo se encarga de verificar si la imagen tiene un rostro,
    sin compararlo con usuarios en la base de datos.
    """
    try:
        # Obtener el JSON que envías desde JS
        data = request.json.get('image')
        if not data:
            return jsonify({'error': 'No image data sent'}), 400

        # Decodificar la imagen base64 (viene con el prefijo 'data:image/...') y convertir a RGB
        image_data = data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        pil_image = Image.open(io.BytesIO(image_bytes)).convert('RGB')
        rgb_image = np.array(pil_image)

        # Detectar si hay al menos un rostro
        face_locations = face_recognition.face_locations(rgb_image)
        if len(face_locations) == 0:
            return jsonify({'face_detected': False})
        else:
            return jsonify({'face_detected': True})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_admin' not in session or not session['is_admin']:
            flash('Acceso denegado. Se requieren privilegios de administrador.', 'danger')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/users')
@admin_required
def users():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    cur.close()
    return render_template('users.html', users=users)

@app.route('/api/users', methods=['POST'])
@admin_required
def create_user():
    data = request.json
    try:
        cur = mysql.connection.cursor()
        
        # Verificar si el email ya existe
        cur.execute("SELECT * FROM users WHERE email = %s", [data['email']])
        if cur.fetchone():
            return jsonify({'success': False, 'message': 'El email ya está registrado'})
        
        hashed_password = generate_password_hash(data['password'])
        cur.execute("""
            INSERT INTO users (name, surnames, email, password, verified, is_admin)
            VALUES (%s, %s, %s, %s, TRUE, %s)
        """, (data['name'], data['surnames'], data['email'], hashed_password, data['is_admin']))
        
        mysql.connection.commit()
        cur.close()
        return jsonify({'success': True, 'message': 'Usuario creado exitosamente'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def manage_user(user_id):
    cur = mysql.connection.cursor()
    
    if request.method == 'GET':
        cur.execute("SELECT * FROM users WHERE id = %s", [user_id])
        user = cur.fetchone()
        cur.close()
        if user:
            return jsonify({
                'id': user[0],
                'name': user[1],
                'surnames': user[2],
                'email': user[3],
                'is_admin': user[9]
            })
        return jsonify({'error': 'Usuario no encontrado'}), 404

    elif request.method == 'PUT':
        data = request.json
        try:
            if data['password']:
                hashed_password = generate_password_hash(data['password'])
                cur.execute("""
                    UPDATE users 
                    SET name = %s, surnames = %s, email = %s, password = %s, is_admin = %s
                    WHERE id = %s
                """, (data['name'], data['surnames'], data['email'], hashed_password, data['is_admin'], user_id))
            else:
                cur.execute("""
                    UPDATE users 
                    SET name = %s, surnames = %s, email = %s, is_admin = %s
                    WHERE id = %s
                """, (data['name'], data['surnames'], data['email'], data['is_admin'], user_id))
            
            mysql.connection.commit()
            cur.close()
            return jsonify({'success': True, 'message': 'Usuario actualizado exitosamente'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})

    elif request.method == 'DELETE':
        try:
            # No permitir eliminar al usuario actual
            if user_id == session.get('user_id'):
                return jsonify({'success': False, 'message': 'No puedes eliminar tu propio usuario'})
            
            cur.execute("DELETE FROM users WHERE id = %s", [user_id])
            mysql.connection.commit()
            cur.close()
            return jsonify({'success': True, 'message': 'Usuario eliminado exitosamente'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
