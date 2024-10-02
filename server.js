const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const session = require('express-session'); // Módulo para sesiones

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));

// Configurar la sesión
app.use(session({
    secret: 'mi_secreto_seguro',  // Clave para firmar la sesión
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60000 } // Tiempo de vida de la sesión
}));

// Configuración de la base de datos
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '', // Cambiar si tienes una contraseña en MySQL
    database: 'login_db'
});

db.connect((err) => {
    if (err) throw err;
    console.log('Conectado a la base de datos');
});

// Ruta para el formulario de login
app.get('/login', (req, res) => {
    res.send(`
        <form action="/login" method="POST">
            <input type="text" name="username" placeholder="Usuario" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Iniciar sesión</button>
        </form>
    `);
});

// Ruta para el formulario de registro
app.get('/register', (req, res) => {
    res.send(`
        <form action="/register" method="POST">
            <input type="text" name="username" placeholder="Usuario" required>
            <input type="password" name="password" placeholder="Contraseña" required>
            <button type="submit">Registrar</button>
        </form>
    `);
});

// Registro de usuarios
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Encriptar la contraseña
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) throw err;

        // Insertar el nuevo usuario en la base de datos
        const query = `INSERT INTO usuarios (username, password) VALUES (?, ?)`;

        db.execute(query, [username, hash], (err, result) => {
            if (err) throw err;
            res.send('Usuario registrado exitosamente');
        });
    });
});

// Validar los datos del usuario (Login)
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Consulta para buscar el usuario en la base de datos
    const query = `SELECT * FROM usuarios WHERE username = ?`;

    db.execute(query, [username], (err, result) => {
        if (err) throw err;

        if (result.length > 0) {
            // Comparar la contraseña almacenada con la proporcionada
            bcrypt.compare(password, result[0].password, (err, isMatch) => {
                if (isMatch) {
                    // Crear sesión y permitir el ingreso
                    req.session.loggedin = true;
                    req.session.username = username;  // Guardar el nombre de usuario en la sesión
                    res.redirect('/dashboard');  // Redirigir a la página protegida
                } else {
                    res.send('Contraseña incorrecta.');
                }
            });
        } else {
            res.send('Usuario no encontrado.');
        }
    });
});

// Ruta protegida (solo accesible después de iniciar sesión)
app.get('/dashboard', (req, res) => {
    if (req.session.loggedin) {
        res.send(`Bienvenido ${req.session.username}, ¡Has iniciado sesión!`);
    } else {
        res.send('Por favor, inicia sesión para acceder a esta página.');
    }
});

// Cerrar sesión
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.send('Error al cerrar sesión');
        }
        res.send('Has cerrado sesión correctamente.');
    });
});

// Configuración del servidor
app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});

// Ruta raíz
app.get('/', (req, res) => {
    res.send(`
        <h1>Bienvenido</h1>
        <p>Por favor, <a href="/login">inicia sesión</a> o <a href="/register">regístrate</a>.</p>
    `);
});
