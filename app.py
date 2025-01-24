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

        # Si el correo no está registrado, proceder con el registro
        verification_code = randint(100000, 999999)  # Generar un código de verificación de 6 dígitos
        verification_sent_time = datetime.now()  # Obtener el tiempo actual
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

        session['email'] = email  # Guardar email en la sesión para usar en la verificación
        session['name'] = name  # Guardar el nombre en la sesión

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

                    # Guardar el nombre del usuario en la sesión si no está ya
                    if 'name' not in session:
                        session['name'] = name

                    # Enviar correo de bienvenida
                    subject = "Bienvenido a Task Manager"
                    body = f"Hola {session['name']},\n\nTu cuenta ha sido verificada exitosamente. ¡Bienvenido a Task Manager! Disfruta de la aplicación."
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
            verification_code = randint(100000, 999999) # Generar un nuevo código de verificación
            verification_sent_time = datetime.now()
            cur.execute("UPDATE users SET verification_code = %s, verification_sent_time = %s WHERE email = %s", (verification_code, verification_sent_time, email))
            mysql.connection.commit()
            cur.close()

            # Enviar el nuevo código de verificación por correo
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
    return user and user[0]  # Retorna True si el usuario está verificado, de lo contrario False

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
            recipients=[to_email],  # Lista de destinatarios
            body=body
        )
        with app.app_context():
            mail.send(msg)  # Enviar el correo
        print("Correo enviado exitosamente")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

# Manejo de imágenes de perfil
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_FILE_SIZE_MB = 2

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload-profile-image', methods=['POST'])
def upload_profile_image():
    if 'email' not in session:  # Verifica si el usuario no ha iniciado sesión
        return jsonify({'error': 'Debes iniciar sesión primero'}), 401  # Retorna un error JSON

    if 'file' not in request.files:  # Verifica si no se ha subido ningún archivo
        return jsonify({'error': 'No se ha seleccionado ningún archivo'}), 400  # Retorna un error JSON

    file = request.files['file']  # Obtiene el archivo subido

    if file.filename == '':  # Verifica si el nombre del archivo está vacío
        return jsonify({'error': 'No se ha seleccionado ningún archivo'}), 400  # Retorna un error JSON
    
    if not allowed_file(file.filename):  # Verifica si el archivo tiene una extensión permitida
        return jsonify({'error': 'Formato de archivo no permitido. Solo se permiten imágenes en formato PNG, JPG, JPEG, GIF o WEBP'}), 400  # Retorna un error JSON
    
    # Verificar el tamaño del archivo
    if 'file' in request.files:
        file_size_mb = request.cookies.get('file_size_mb')  # Obtiene el tamaño del archivo desde las cookies
        if file_size_mb and float(file_size_mb) > MAX_FILE_SIZE_MB:  # Verifica si el tamaño del archivo excede el máximo permitido
            return jsonify({'error': f'El tamaño máximo permitido del archivo es de {MAX_FILE_SIZE_MB} MB'}), 400  # Retorna un error JSON
    
    if request.method == 'POST':  # Verifica si la solicitud es POST
        file = request.files['file']  # Obtiene el archivo subido nuevamente
        cur = mysql.connection.cursor()  # Crea un cursor para ejecutar comandos SQL
        cur.execute("SELECT profile_image FROM users WHERE email = %s", (session['email'],))  # Consulta para obtener la imagen de perfil anterior del usuario
        previous_profile_image = cur.fetchone()  # Obtiene el resultado de la consulta
        cur.close()  # Cierra el cursor

        if previous_profile_image:  # Verifica si hay una imagen de perfil anterior
            previous_filename = previous_profile_image[0]  # Obtiene el nombre del archivo de la imagen de perfil anterior
            if previous_filename:  # Verifica si el nombre del archivo anterior no es None
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], previous_filename))  # Intenta eliminar la imagen de perfil anterior del sistema de archivos
                except FileNotFoundError:  # Maneja el caso en que el archivo no se encuentre
                    pass

        # Generar un nombre aleatorio único para el nuevo archivo
        filename = str(uuid.uuid4()) + secure_filename(file.filename)  # Genera un nombre único para el archivo
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # Guarda el archivo en el directorio de subida

        cur = mysql.connection.cursor()  # Crea un cursor para ejecutar comandos SQL
        cur.execute("UPDATE users SET profile_image = %s WHERE email = %s", (filename, session['email']))  # Actualiza la imagen de perfil del usuario en la base de datos
        mysql.connection.commit()  # Confirma los cambios en la base de datos
        cur.close()  # Cierra el cursor

        return jsonify({'message': 'Imagen de perfil actualizada correctamente'}), 200  # Retorna un mensaje de éxito como JSON
    else:
        return jsonify({'error': 'Método no permitido'}), 405  # Retorna un error JSON indicando que el método no está permitido

@app.route('/uploaded-profile-image/<filename>')
def uploaded_profile_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)  # Envía el archivo desde el directorio de subida

@app.route('/get-profile-image-url-master')
def get_profile_image_url_master():
    try:
        email = session.get('email')  # Obtiene el correo electrónico de la sesión
        if email:
            user_id = get_user_id_by_email(email)  # Obtiene el ID del usuario
            if user_id:
                cur = mysql.connection.cursor()  # Crea un cursor para ejecutar comandos SQL
                cur.execute("SELECT profile_image FROM users WHERE id = %s", (user_id,))  # Consulta para obtener la imagen de perfil del usuario
                profile_image = cur.fetchone()  # Obtiene el resultado de la consulta
                cur.close()  # Cierra el cursor
                profile_image_name = profile_image[0]  # Obtiene el nombre del archivo de la imagen de perfil
                if profile_image_name is None or not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], profile_image_name)):
                    # Si no hay imagen de perfil o no existe el archivo, usa una imagen por defecto
                    profile_image_name = "perfil-por-defecto.png"
                    profile_image_url = f"/uploaded-profile-image/{profile_image_name}"
                    return jsonify({'profile_image_url': profile_image_url})  # Retorna la URL de la imagen por defecto
                else:
                    profile_image_url = f"/uploaded-profile-image/{profile_image_name}"
                    return jsonify({'profile_image_url': profile_image_url})  # Retorna la URL de la imagen de perfil del usuario
            return jsonify({'profile_image_url': '/static/Profile_image/default_profile.jpg'})  # Retorna la URL de una imagen por defecto si no se encuentra el usuario
        else:
            return jsonify({'error': 'Correo electrónico no encontrado en la sesión'})  # Retorna un error JSON si no hay correo electrónico en la sesión
    except Exception as e:
        return jsonify({'error': str(e)})  # Retorna un error JSON en caso de excepción

def get_user_id_by_email(email):
    cur = mysql.connection.cursor()  # Crea un cursor para ejecutar comandos SQL
    cur.execute("SELECT id FROM users WHERE email = %s", (email,))  # Consulta para obtener el ID del usuario
    user_id = cur.fetchone()  # Obtiene el resultado de la consulta
    cur.close()  # Cierra el cursor
    if user_id:
        return user_id[0]  # Retorna el ID del usuario
    else:
        return None  # Retorna None si no se encuentra el usuario

# Notificaciones
@app.route('/api/notifications', methods=['GET'])
def api_notifications():
    if 'email' not in session:  # Verifica si el usuario no ha iniciado sesión
        return jsonify({'error': 'Usuario no autenticado'}), 401  # Retorna un error JSON

    email = session['email']  # Obtiene el correo electrónico del usuario desde la sesión
    cur = mysql.connection.cursor()  # Crea un cursor para ejecutar comandos SQL
    cur.execute("SELECT * FROM `notifications` WHERE email = %s", [email])  # Consulta para obtener las notificaciones del usuario
    notifications = cur.fetchall()  # Obtiene todos los resultados de la consulta
    cur.close()  # Cierra el cursor

    notifications_list = [{'id': n[0], 'notification': n[2], 'status': n[3]} for n in notifications]  # Procesa los resultados en una lista de diccionarios
    return jsonify(notifications_list)  # Retorna las notificaciones como JSON

@app.route('/api/update-notifications', methods=['POST'])
def update_notifications():
    if 'email' not in session:  # Verifica si el usuario no ha iniciado sesión
        return jsonify({'error': 'Usuario no autenticado'}), 401  # Retorna un error JSON

    email = session['email']  # Obtiene el correo electrónico del usuario desde la sesión
    try:
        conn = mysql.connection  # Obtiene la conexión a la base de datos
        cur = conn.cursor()  # Crea un cursor para ejecutar comandos SQL
        cur.execute("UPDATE notifications SET status = 'Inactiva' WHERE email = %s", [email])  # Consulta para actualizar el estado de las notificaciones
        conn.commit()  # Confirma los cambios en la base de datos
        cur.close()  # Cierra el cursor
        return jsonify({'message': 'Notificaciones actualizadas correctamente'}), 200  # Retorna un mensaje de éxito como JSON
    except Exception as e:  # Maneja cualquier excepción que ocurra
        return jsonify({'error': str(e)}), 500  # Retorna un error JSON

@app.route('/detect-face', methods=['POST'])
def detect_face():
    try:
        # Obtener la imagen desde la solicitud
        data = request.json['image']
        # Convertir base64 a imagen
        image_data = data.split(',')[1]
        image_bytes = base64.b64decode(image_data)
        image = Image.open(io.BytesIO(image_bytes))
        
        # Convertir a formato OpenCV
        opencv_image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        # Modifica esta línea para usar la ruta absoluta
        cascade_path = os.path.join(os.path.dirname(__file__), 
                                  'static/haarcascade/haarcascade_frontalface_default.xml')
        face_cascade = cv2.CascadeClassifier(cascade_path)
        
        if face_cascade.empty():
            raise Exception("Error al cargar el clasificador Haar Cascade")
            
        # Convertir a escala de grises
        gray = cv2.cvtColor(opencv_image, cv2.COLOR_BGR2GRAY)
        
        # Detectar rostros
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,
            minNeighbors=5,
            minSize=(30, 30)
        )
        
        # Retornar si se detectó un rostro
        return jsonify({'face_detected': len(faces) > 0})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
