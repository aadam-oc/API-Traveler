// Import necessary modules
const express = require("express");
const mysql = require("mysql2");
const dotenv = require("dotenv");
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const bodyParser = require('body-parser');


// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'M12-Traveler';

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware to handle JSON requests
app.use(express.json());

// Middleware to handle URL-encoded form data
app.use(bodyParser.json());


// Enable CORS
app.use(cors());

// Configuración de Swagger
const swaggerOptions = {
    definition: {
        openapi: "3.0.0",
        info: {
            title: "Traveler API",
            version: "1.0.0",
            description: "API para gestionar usuarios y autenticación",
        },
        components: {
            securitySchemes: {
                BearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT"
                }
            }
        },
        security: [{ BearerAuth: [] }]
    },

    apis: ["./traveler.js"],
};


const swaggerDocs = swaggerJSDoc(swaggerOptions);

// Usar Swagger UI en el servidor
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Verify DB connection
db.connect((err) => {
    if (err) {
        console.error("Error connecting to the database:", err);
        process.exit(1);
    }
    console.log("Connected to the database.");
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied, token missing!' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Invalid token:', err);
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: Endpoints para la autenticación de usuarios y registro
 *   - name: Usuarios
 *     description: Endpoints para la gestión de usuarios
 *   - name: Roles
 *     description: Endpoints para la gestión de roles
 *   - name: Características Usuarios
 *     description: Endpoints para la gestión de características de usuarios
 *   - name: Destinos
 *     description: Endpoints para la gestión de destinos
 *   - name: Tipo Actividad
 *     description: Endpoints para la gestión de tipos de actividad
 *   - name: Actividades
 *     description: Endpoints para la gestión de actividades
 *   - name: Alojamientos
 *     description: Endpoints para la gestión de alojamientos
 *   - name: Valoraciones Alojamientos
 *     description: Endpoints para la gestión de valoraciones de alojamientos
 *   - name: Imagenes Alojamientos
 *     description: Endpoints para la gestión de imágenes de alojamientos
 *   - name: Imagenes Actividades
 *     description: Endpoints para la gestión de imágenes de actividades
 *   - name: Post Blog
 *     description: Endpoints para la gestión de publicaciones de blog
 *   - name: Reservas Actividades
 *     description: Endpoints para la gestión de reservas de actividades
 *   - name: Reservas Alojamientos
 *     description: Endpoints para la gestión de reservas de alojamientos
 *   - name: Reservas Vehículos
 *     description: Endpoints para la gestión de reservas de vehículos
 *   - name: Reservas Vuelos
 *     description: Endpoints para la gestión de reservas de vuelos
 *   - name: Contacto
 *     description: Endpoints para la gestión de contactos
 *   - name: Imágenes Usuarios
 *     description: Endpoints para la gestión de imágenes de usuarios
 */




//Login
/**
 * @swagger
 * /traveler/login:
 *   post:
 *     summary: User login
 *     description: Authenticates a user by email and password, and returns a JWT token if successful.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - correo
 *               - contrasena
 *             properties:
 *               correo:
 *                 type: string
 *                 example: admin@gmail.com
 *               contrasena:
 *                 type: string
 *                 example: admin
 *     responses:
 *       200:
 *         description: Login successful, returns JWT and user data
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT token
 *                 id_usuario:
 *                   type: integer
 *                   description: ID of the user
 *                 id_rol:
 *                   type: integer
 *                   description: Role ID of the user
 *                 correo:
 *                   type: string
 *                   description: Email of the user
 *       400:
 *         description: Missing email or password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Correo y contraseña son obligatorios
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Correo o contraseña incorrectos
 *       500:
 *         description: Server error during login process
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error processing login
 */
app.post('/traveler/login', (req, res) => {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    db.query('SELECT * FROM traveler.usuarios WHERE correo = ?', [correo], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ error: 'Error processing login' });
        }

        if (results.length === 0) {
            return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
        }

        const user = results[0];

        bcrypt.compare(contrasena, user.contrasena, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ error: 'Error processing login' });
            }

            if (!isMatch) {
                return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
            }

            const token = jwt.sign(
                { id: user.id_usuario, correo: user.correo },
                JWT_SECRET,
                { expiresIn: '10h' }
            );

            res.status(200).json({
                token,
                id_usuario: user.id_usuario,
                id_rol: user.id_rol,
                correo: user.correo
            });
        });
    });
});







//Register
/**
 * @swagger
 * /traveler/register:
 *   post:
 *     summary: Registrar un nuevo usuario
 *     description: Registra un nuevo usuario con correo y contraseña. Devuelve un token JWT al registrarse correctamente.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - correo
 *               - contrasena
 *             properties:
 *               correo:
 *                 type: string
 *                 description: Correo electrónico del usuario
 *                 example: ejemplo@correo.com
 *               contrasena:
 *                 type: string
 *                 description: Contraseña del usuario
 *                 example: MiContrasenaSegura123
 *     responses:
 *       201:
 *         description: Usuario registrado con éxito
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: Usuario registrado con éxito
 *                 token:
 *                   type: string
 *                   description: Token JWT generado para el usuario
 *       400:
 *         description: Correo o contraseña faltantes, o el correo ya está registrado
 *       500:
 *         description: Error interno del servidor al registrar el usuario
 */
app.post('/traveler/register', async (req, res) => {
    const { correo, contrasena } = req.body;

    if (!correo || !contrasena) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    db.query('SELECT * FROM traveler.usuarios WHERE correo = ?', [correo], (err, results) => {
        if (err) {
            console.error('Error checking user email:', err);
            return res.status(500).json({ error: 'Error checking email' });
        }

        if (results.length > 0) {
            return res.status(400).json({ error: 'El correo ya está registrado' });
        }

        bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({ error: 'Error hashing password' });
            }

            const query = 'INSERT INTO traveler.usuarios (correo, contrasena) VALUES (?, ?)';
            db.query(query, [correo, hashedPassword], (err, result) => {
                if (err) {
                    console.error('Error inserting user:', err);
                    return res.status(500).json({ error: 'Error registering user' });
                }

                const token = jwt.sign(
                    { id: result.insertId, correo },
                    JWT_SECRET,
                    { expiresIn: '10h' }
                );

                res.status(201).json({
                    message: 'Usuario registrado con éxito',
                    token,
                });
            });
        });
    });
});







// Usuarios
/**
 * @swagger
 * /traveler/usuarios:
 *   get:
 *     summary: Obtener todos los usuarios
 *     description: Retorna una lista de todos los usuarios registrados.
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de usuarios obtenida exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 usuarios:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_usuario:
 *                         type: integer
 *                         description: ID del usuario
 *                       correo:
 *                         type: string
 *                         description: Correo del usuario
 *                       id_rol:
 *                         type: integer
 *                         description: ID del rol del usuario
 *       401:
 *         description: Token no proporcionado o inválido
 *       500:
 *         description: Error al obtener los usuarios
 */
app.get('/traveler/usuarios', authenticateToken, (req, res) => {
    db.query('SELECT * FROM traveler.usuarios', (err, results) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).json({ error: 'Error fetching users' });
        }
        res.status(200).json({ usuarios: results });
    });
});

/**
 * @swagger
 * /traveler/usuarios_full:
 *   post:
 *     summary: Crear un usuario completo
 *     description: Crea un usuario con sus características asociadas.
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - correo
 *               - contrasena
 *               - id_rol
 *               - nombre
 *               - apellido1
 *               - telefono1
 *             properties:
 *               correo:
 *                 type: string
 *                 description: Correo del usuario
 *                 example: usuario@example.com
 *               contrasena:
 *                 type: string
 *                 description: Contraseña del usuario
 *                 example: MiContrasenaSegura123
 *               id_rol:
 *                 type: integer
 *                 description: ID del rol del usuario
 *                 example: 2
 *               nombre:
 *                 type: string
 *                 description: Nombre del usuario
 *                 example: Juan
 *               apellido1:
 *                 type: string
 *                 description: Primer apellido del usuario
 *                 example: Pérez
 *               apellido2:
 *                 type: string
 *                 description: Segundo apellido del usuario
 *                 example: García
 *               telefono1:
 *                 type: string
 *                 description: Teléfono principal del usuario
 *                 example: "612345678"
 *               telefono2:
 *                 type: string
 *                 description: Teléfono secundario del usuario
 *                 example: "698765432"
 *     responses:
 *       201:
 *         description: Usuario creado exitosamente
 *       400:
 *         description: Datos de entrada inválidos
 *       500:
 *         description: Error al crear el usuario
 */
app.post('/traveler/usuarios_full', authenticateToken, (req, res) => {
    const { correo, contrasena, id_rol, nombre, apellido1, apellido2, telefono1, telefono2 } = req.body;

    if (!correo || !contrasena || !id_rol || !nombre || !apellido1 || !apellido2 || !telefono1) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Error hashing password' });
        }

        db.query('INSERT INTO traveler.usuarios (correo, contrasena, id_rol) VALUES (?, ?, ?)', [correo, hashedPassword, id_rol], (err, result) => {
            if (err) {
                console.error('Error creating user:', err);
                return res.status(500).json({ error: 'Error creating user' });
            }

            const id_usuario = result.insertId;

            db.query(
                'INSERT INTO traveler.caracteristicas_usuarios (id_usuario, nombre, apellido1, apellido2, telefono1, telefono2) VALUES (?, ?, ?, ?, ?, ?)',
                [id_usuario, nombre, apellido1, apellido2, telefono1, telefono2],
                (err) => {
                    if (err) {
                        console.error('Error creating user characteristics:', err);
                        return res.status(500).json({ error: 'Error creating user characteristics' });
                    }

                    res.status(201).json({ id: id_usuario });
                }
            );
        });
    });
});

/**
 * @swagger
 * /traveler/usuarios_full/{id}:
 *   put:
 *     summary: Actualizar un usuario completo
 *     description: Actualiza los datos de un usuario y sus características asociadas.
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario a actualizar
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               correo:
 *                 type: string
 *                 description: Correo del usuario
 *               contrasena:
 *                 type: string
 *                 description: Contraseña del usuario
 *               id_rol:
 *                 type: integer
 *                 description: ID del rol del usuario
 *               nombre:
 *                 type: string
 *                 description: Nombre del usuario
 *               apellido1:
 *                 type: string
 *                 description: Primer apellido del usuario
 *               apellido2:
 *                 type: string
 *                 description: Segundo apellido del usuario
 *               telefono1:
 *                 type: string
 *                 description: Teléfono principal del usuario
 *               telefono2:
 *                 type: string
 *                 description: Teléfono secundario del usuario
 *     responses:
 *       200:
 *         description: Usuario actualizado exitosamente
 *       400:
 *         description: Datos de entrada inválidos
 *       404:
 *         description: Usuario no encontrado
 *       500:
 *         description: Error al actualizar el usuario
 */
app.put('/traveler/usuarios_full/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { correo, contrasena, id_rol, nombre, apellido1, apellido2, telefono1, telefono2 } = req.body;

    db.query(`SELECT * FROM traveler.usuarios WHERE id_usuario = ?`, [id], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ error: 'Error fetching user' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const updateUser = (hashedPassword) => {
            db.query(
                `UPDATE traveler.usuarios SET correo = ?, contrasena = ?, id_rol = ? WHERE id_usuario = ?`,
                [correo, hashedPassword, id_rol, id],
                (err) => {
                    if (err) {
                        console.error('Error updating user:', err);
                        return res.status(500).json({ error: 'Error updating user' });
                    }

                    db.query(
                        `UPDATE traveler.caracteristicas_usuarios SET nombre = ?, apellido1 = ?, apellido2 = ?, telefono1 = ?, telefono2 = ? WHERE id_usuario = ?`,
                        [nombre, apellido1, apellido2, telefono1, telefono2, id],
                        (err) => {
                            if (err) {
                                console.error('Error updating user characteristics:', err);
                                return res.status(500).json({ error: 'Error updating user characteristics' });
                            }
                            res.status(200).json({ success: true });
                        }
                    );
                }
            );
        };

        // Si se proporciona una nueva contraseña, se hashea. Si no, se usa la actual de la base de datos.
        if (contrasena) {
            bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
                if (err) {
                    console.error('Error hashing password:', err);
                    return res.status(500).json({ error: 'Error hashing password' });
                }
                updateUser(hashedPassword);
            });
        } else {
            // Si no se proporciona una nueva contraseña, se reutiliza la anterior
            updateUser(results[0].contrasena);
        }
    });
});

/**
 * @swagger
 * /traveler/usuarios/{id}:
 *   delete:
 *     summary: Eliminar un usuario
 *     description: Elimina un usuario por su ID.
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario a eliminar
 *     responses:
 *       200:
 *         description: Usuario eliminado exitosamente
 *       404:
 *         description: Usuario no encontrado
 *       500:
 *         description: Error al eliminar el usuario
 */
app.delete('/traveler/usuarios/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    db.query('DELETE FROM traveler.usuarios WHERE id_usuario = ?', [id], (err, result) => {
        if (err) {
            console.error('Error al eliminar usuario:', err);
            return res.status(500).json({ error: 'Error al eliminar usuario' });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        res.status(200).json({ success: true });
    });
});

/**
 * @swagger
 * /traveler/usuarios_full/{id}:
 *   get:
 *     summary: Obtener usuario completo por ID
 *     description: Obtiene un usuario junto con su rol y características personales.
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID del usuario
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Usuario encontrado
 *       404:
 *         description: Usuario no encontrado
 *       500:
 *         description: Error al obtener el usuario
 */
app.get('/traveler/usuarios_full/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query(` SELECT u.*, r.nombre_rol, c.nombre, c.apellido1, c.apellido2, c.telefono1, c.telefono2
        FROM traveler.usuarios u
        LEFT JOIN traveler.roles r ON u.id_rol = r.id_rol
        LEFT JOIN traveler.caracteristicas_usuarios c ON u.id_usuario = c.id_usuario
        WHERE u.id_usuario = ?
    `, [id], (err, results) => {
        if (err) {
            console.error('Error fetching user with roles and characteristics:', err);
            return res.status(500).json({ error: 'Error fetching user with roles and characteristics' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ usuario: results[0] });
    });
});

/**
 * @swagger
 * /traveler/usuarios_full:
 *   get:
 *     summary: Obtener todos los usuarios con detalles completos
 *     description: Devuelve una lista de todos los usuarios, incluyendo su rol y características personales (nombre, apellidos, teléfonos).
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de usuarios obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 usuarios:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_usuario:
 *                         type: integer
 *                       correo:
 *                         type: string
 *                       id_rol:
 *                         type: integer
 *                       nombre_rol:
 *                         type: string
 *                       nombre:
 *                         type: string
 *                       apellido1:
 *                         type: string
 *                       apellido2:
 *                         type: string
 *                       telefono1:
 *                         type: string
 *                       telefono2:
 *                         type: string
 *       500:
 *         description: Error interno al obtener usuarios
 */
app.get('/traveler/usuarios_full', authenticateToken, (req, res) => {
    db.query(`
        SELECT u.*, r.nombre_rol, c.nombre, c.apellido1, c.apellido2, c.telefono1, c.telefono2
        FROM traveler.usuarios u
        LEFT JOIN traveler.roles r ON u.id_rol = r.id_rol
        LEFT JOIN traveler.caracteristicas_usuarios c ON u.id_usuario = c.id_usuario
    `, (err, results) => {
        if (err) {
            console.error('Error fetching users with roles and characteristics:', err);
            return res.status(500).json({ error: 'Error fetching users with roles and characteristics' });
        }
        res.status(200).json({ usuarios: results });
    });
});

/**
 * @swagger
 * /traveler/usuarios/{id}:
 *   get:
 *     summary: Obtener usuario por ID
 *     description: Devuelve los datos básicos del usuario según su ID.
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID del usuario
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Usuario encontrado
 *       404:
 *         description: Usuario no encontrado
 *       500:
 *         description: Error al obtener el usuario
 */
app.get('/traveler/usuarios/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    db.query('SELECT * FROM traveler.usuarios WHERE id_usuario = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ error: 'Error fetching user' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ usuario: results[0] });
    });
});

/**
 * @swagger
 * /traveler/usuarios:
 *   post:
 *     summary: Crear usuario
 *     description: Crea un nuevo usuario con correo, contraseña e ID de rol.
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - correo
 *               - contrasena
 *               - id_rol
 *             properties:
 *               correo:
 *                 type: string
 *                 example: ejemplo@correo.com
 *               contrasena:
 *                 type: string
 *                 example: miContrasenaSegura
 *               id_rol:
 *                 type: integer
 *                 example: 2
 *     responses:
 *       201:
 *         description: Usuario creado exitosamente
 *       400:
 *         description: Datos de entrada inválidos
 *       500:
 *         description: Error al crear el usuario
 */
app.post('/traveler/usuarios', authenticateToken, (req, res) => {
    const { correo, contrasena, id_rol } = req.body;

    if (!correo || !contrasena || !id_rol) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
        if (err) {
            console.error('Error hashing password:', err);
            return res.status(500).json({ error: 'Error hashing password' });
        }

        const query = 'INSERT INTO traveler.usuarios (correo, contrasena, id_rol) VALUES (?, ?, ?)';
        db.query(query, [correo, hashedPassword, id_rol], (err, result) => {
            if (err) {
                console.error('Error creating user:', err);
                return res.status(500).json({ error: 'Error creating user' });
            }
            res.status(201).json({ id: result.insertId });
        });
    });
});

/**
 * @swagger
 * /traveler/usuarios/{id}:
 *   put:
 *     summary: Actualizar usuario
 *     description: Actualiza los campos del usuario (correo, contraseña, rol).
 *     tags: [Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID del usuario
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               correo:
 *                 type: string
 *                 example: nuevo@correo.com
 *               contrasena:
 *                 type: string
 *                 example: nuevaContrasena
 *               id_rol:
 *                 type: integer
 *                 example: 3
 *     responses:
 *       200:
 *         description: Usuario actualizado exitosamente
 *       400:
 *         description: Datos inválidos o faltantes
 *       404:
 *         description: Usuario no encontrado
 *       500:
 *         description: Error al actualizar el usuario
 */
app.put('/traveler/usuarios/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { correo, contrasena, id_rol } = req.body;

    if (!correo && !contrasena && id_rol === undefined) {
        return res.status(400).json({ error: 'Correo, contraseña o id_rol son requeridos' });
    }

    const updates = [];
    const params = [];

    const proceedUpdate = () => {
        if (updates.length === 0) {
            return res.status(400).json({ error: 'No hay datos para actualizar' });
        }

        params.push(id);
        const query = `UPDATE traveler.usuarios SET ${updates.join(', ')} WHERE id_usuario = ?`;

        db.query(query, params, (err, result) => {
            if (err) {
                console.error('Error al actualizar usuario:', err);
                return res.status(500).json({ error: 'Error al actualizar usuario' });
            }

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: 'Usuario no encontrado' });
            }

            res.status(200).json({ success: true });
        });
    };

    if (correo) {
        updates.push('correo = ?');
        params.push(correo);
    }

    if (id_rol !== undefined) {
        updates.push('id_rol = ?');
        params.push(id_rol);
    }

    if (contrasena) {
        bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Error al encriptar la contraseña:', err);
                return res.status(500).json({ error: 'Error al encriptar la contraseña' });
            }

            updates.push('contrasena = ?');
            params.push(hashedPassword);
            proceedUpdate();
        });
    } else {
        proceedUpdate();
    }
});







// Roles
/**
 * @swagger
 * /traveler/roles:
 *   get:
 *     summary: Obtener todos los roles
 *     tags: [Roles]
 *     responses:
 *       200:
 *         description: Lista de roles obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 roles:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_rol:
 *                         type: integer
 *                       nombre_rol:
 *                         type: string
 *       500:
 *         description: Error interno al obtener roles
 */
app.get('/traveler/roles', (req, res) => {
    db.query('SELECT * FROM traveler.roles', (err, results) => {
        if (err) {
            console.error('Error fetching roles:', err);
            res.status(500).json({ error: 'Error fetching roles' });
        } else {
            res.json({ roles: results });
        }
    });
});

/**
 * @swagger
 * /traveler/roles/{id}:
 *   get:
 *     summary: Obtener un rol por ID
 *     tags: [Roles]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del rol
 *     responses:
 *       200:
 *         description: Rol encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 role:
 *                   type: object
 *                   properties:
 *                     id_rol:
 *                       type: integer
 *                     nombre_rol:
 *                       type: string
 *       404:
 *         description: Rol no encontrado
 *       500:
 *         description: Error al obtener el rol
 */
app.get('/traveler/roles/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.roles WHERE id_rol = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching role:', err);
            res.status(500).json({ error: 'Error fetching role' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Role not found' });
            } else {
                res.json({ role: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/roles:
 *   post:
 *     summary: Crear un nuevo rol
 *     tags: [Roles]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nombre_rol
 *             properties:
 *               nombre_rol:
 *                 type: string
 *     responses:
 *       200:
 *         description: Rol creado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                 id:
 *                   type: integer
 *       400:
 *         description: Datos inválidos
 *       500:
 *         description: Error al crear el rol
 */
app.post('/traveler/roles', authenticateToken, (req, res) => {
    const { nombre_rol } = req.body;

    if (!nombre_rol) {
        return res.status(400).json({ error: 'Role name is required' });
    }

    db.query('INSERT INTO traveler.roles (nombre_rol) VALUES (?)', [nombre_rol], (err, result) => {
        if (err) {
            console.error('Error creating role:', err);
            res.status(500).json({ error: 'Error creating role' });
        } else {
            res.json({
                message: 'Role created successfully',
                id: result.insertId
            });
        }
    });
});

/**
 * @swagger
 * /traveler/roles/{id}:
 *   put:
 *     summary: Actualizar un rol por ID
 *     tags: [Roles]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del rol
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_rol:
 *                 type: string
 *     responses:
 *       200:
 *         description: Rol actualizado correctamente
 *       500:
 *         description: Error al actualizar el rol
 */
app.put('/traveler/roles/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { nombre_rol } = req.body;
    db.query('UPDATE traveler.roles SET nombre_rol = ? WHERE id_rol = ?', [nombre_rol, id], (err, result) => {
        if (err) {
            console.error('Error updating role:', err);
            res.status(500).json({ error: 'Error updating role' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/roles/{id}:
 *   delete:
 *     summary: Eliminar un rol por ID
 *     tags: [Roles]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del rol
 *     responses:
 *       200:
 *         description: Rol eliminado correctamente
 *       500:
 *         description: Error al eliminar el rol
 */
app.delete('/traveler/roles/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.roles WHERE id_rol = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting role:', err);
            res.status(500).json({ error: 'Error deleting role' });
        } else {
            res.json({ success: true });
        }
    });
});







// Caracteristicas Usuarios
/**
 * @swagger
 * /traveler/caracteristicas_usuarios:
 *   get:
 *     summary: Obtener todas las características de usuarios
 *     tags: [Características Usuarios]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de características obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 caracteristicas_usuarios:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_usuario:
 *                         type: integer
 *                       nombre:
 *                         type: string
 *                       apellido1:
 *                         type: string
 *                       apellido2:
 *                         type: string
 *                       telefono1:
 *                         type: string
 *                       telefono2:
 *                         type: string
 *       500:
 *         description: Error interno al obtener las características
 */
app.get('/traveler/caracteristicas_usuarios', authenticateToken, (req, res) => {
    db.query('SELECT * FROM traveler.caracteristicas_usuarios', (err, results) => {
        if (err) {
            console.error('Error fetching caracteristicas_usuarios:', err);
            res.status(500).json({ error: 'Error fetching caracteristicas_usuarios' });
        } else {
            res.json({ caracteristicas_usuarios: results });
        }
    });
});

/**
 * @swagger
 * /traveler/caracteristicas_usuarios/{id}:
 *   get:
 *     summary: Obtener una característica de usuario por ID
 *     tags: [Características Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario
 *     responses:
 *       200:
 *         description: Característica encontrada
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 caracteristica_usuario:
 *                   type: object
 *                   properties:
 *                     id_usuario:
 *                       type: integer
 *                     nombre:
 *                       type: string
 *                     apellido1:
 *                       type: string
 *                     apellido2:
 *                       type: string
 *                     telefono1:
 *                       type: string
 *                     telefono2:
 *                       type: string
 *       404:
 *         description: Característica no encontrada
 *       500:
 *         description: Error al obtener la característica
 */
app.get('/traveler/caracteristicas_usuarios/:id', authenticateToken, (req, res) => {
    const id_usuario = req.params.id;

    db.query('SELECT * FROM traveler.caracteristicas_usuarios WHERE id_usuario = ?', [id_usuario], (err, results) => {
        if (err) {
            console.error('Error fetching caracteristicas_usuarios:', err);
            res.status(500).json({ error: 'Error fetching caracteristicas_usuarios' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Caracteristica_usuario not found' });
            } else {
                res.json({ caracteristica_usuario: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/caracteristicas_usuarios:
 *   post:
 *     summary: Crear una nueva característica de usuario
 *     tags: [Características Usuarios]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - id_usuario
 *             properties:
 *               id_usuario:
 *                 type: integer
 *               nombre:
 *                 type: string
 *               apellido1:
 *                 type: string
 *               apellido2:
 *                 type: string
 *               telefono1:
 *                 type: string
 *               telefono2:
 *                 type: string
 *     responses:
 *       200:
 *         description: Característica creada correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 message:
 *                   type: string
 *       500:
 *         description: Error al crear la característica
 */
app.post('/traveler/caracteristicas_usuarios', authenticateToken, (req, res) => {
    const { id_usuario, nombre, apellido1, apellido2, telefono1, telefono2 } = req.body;

    db.query(
        'INSERT INTO traveler.caracteristicas_usuarios (id_usuario, nombre, apellido1, apellido2, telefono1, telefono2) VALUES (?, ?, ?, ?, ?, ?)',
        [
            id_usuario || null,
            nombre || null,
            apellido1 || null,
            apellido2 || null,
            telefono1 || null,
            telefono2 || null
        ],
        (err, result) => {
            if (err) {
                console.error('Error creating caracteristica_usuario:', err);
                res.status(500).json({ error: 'Error creating caracteristica_usuario' });
            } else {
                res.json({ id: result.insertId, message: 'Característica de usuario creada correctamente' });
            }
        }
    );
});

/**
 * @swagger
 * /traveler/caracteristicas_usuarios/{id}:
 *   put:
 *     summary: Actualizar una característica de usuario por ID
 *     tags: [Características Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               apellido1:
 *                 type: string
 *               apellido2:
 *                 type: string
 *               telefono1:
 *                 type: string
 *               telefono2:
 *                 type: string
 *     responses:
 *       200:
 *         description: Característica actualizada correctamente
 *       500:
 *         description: Error al actualizar la característica
 */
app.put('/traveler/caracteristicas_usuarios/:id', authenticateToken, (req, res) => {
    const id_usuario = req.params.id;
    const { nombre, apellido1, apellido2, telefono1, telefono2 } = req.body;
    db.query(
        'UPDATE traveler.caracteristicas_usuarios SET nombre = ?, apellido1 = ?, apellido2 = ?, telefono1 = ?, telefono2 = ? WHERE id_usuario = ?',
        [nombre, apellido1, apellido2, telefono1, telefono2, id_usuario],
        (err, result) => {
            if (err) {
                console.error('Error updating caracteristica_usuario:', err);
                res.status(500).json({ error: 'Error updating caracteristica_usuario' });
            } else {
                res.json({ success: true });
            }
        }
    );
});

/**
 * @swagger
 * /traveler/caracteristicas_usuarios/{id}:
 *   delete:
 *     summary: Eliminar una característica de usuario por ID
 *     tags: [Características Usuarios]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario
 *     responses:
 *       200:
 *         description: Característica eliminada correctamente
 *       500:
 *         description: Error al eliminar la característica
 */
app.delete('/traveler/caracteristicas_usuarios/:id', authenticateToken, (req, res) => {
    const id_usuario = req.params.id;
    db.query('DELETE FROM traveler.caracteristicas_usuarios WHERE id_usuario = ?', [id_usuario], (err, result) => {
        if (err) {
            console.error('Error deleting caracteristica_usuario:', err);
            res.status(500).json({ error: 'Error deleting caracteristica_usuario' });
        } else {
            res.json({ success: true });
        }
    });
});







// Destinos
/**
 * @swagger
 * /traveler/destinos:
 *   get:
 *     summary: Obtener todos los destinos
 *     tags: [Destinos]
 *     responses:
 *       200:
 *         description: Lista de destinos obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 destinos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_destino:
 *                         type: integer
 *                       pais:
 *                         type: string
 *                       ciudad:
 *                         type: string
 *       500:
 *         description: Error interno al obtener los destinos
 */
app.get('/traveler/destinos', (req, res) => {
    db.query('SELECT * FROM traveler.destinos', (err, results) => {
        if (err) {
            console.error('Error fetching destinos:', err);
            res.status(500).json({ error: 'Error fetching destinos' });
        } else {
            res.json({ destinos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/destinos/{id}:
 *   get:
 *     summary: Obtener un destino por ID
 *     tags: [Destinos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del destino
 *     responses:
 *       200:
 *         description: Destino encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 destino:
 *                   type: object
 *                   properties:
 *                     id_destino:
 *                       type: integer
 *                     pais:
 *                       type: string
 *                     ciudad:
 *                       type: string
 *       404:
 *         description: Destino no encontrado
 *       500:
 *         description: Error al obtener el destino
 */
app.get('/traveler/destinos/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.destinos WHERE id_destino = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching destino:', err);
            res.status(500).json({ error: 'Error fetching destino' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Destino not found' });
            } else {
                res.json({ destino: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/destinos:
 *   post:
 *     summary: Crear un nuevo destino
 *     tags: [Destinos]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - pais
 *               - ciudad
 *             properties:
 *               pais:
 *                 type: string
 *               ciudad:
 *                 type: string
 *     responses:
 *       200:
 *         description: Destino creado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear el destino
 */
app.post('/traveler/destinos', authenticateToken, (req, res) => {
    const { pais, ciudad } = req.body;
    db.query('INSERT INTO traveler.destinos (pais, ciudad) VALUES (?, ?)', [pais, ciudad], (err, result) => {
        if (err) {
            console.error('Error creating destino:', err);
            res.status(500).json({ error: 'Error creating destino' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/destinos/{id}:
 *   put:
 *     summary: Actualizar un destino por ID
 *     tags: [Destinos]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del destino
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               pais:
 *                 type: string
 *               ciudad:
 *                 type: string
 *     responses:
 *       200:
 *         description: Destino actualizado correctamente
 *       500:
 *         description: Error al actualizar el destino
 */
app.put('/traveler/destinos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { pais, ciudad } = req.body;
    db.query('UPDATE traveler.destinos SET pais = ?, ciudad = ? WHERE id_destino = ?', [pais, ciudad, id], (err, result) => {
        if (err) {
            console.error('Error updating destino:', err);
            res.status(500).json({ error: 'Error updating destino' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/destinos/{id}:
 *   delete:
 *     summary: Eliminar un destino por ID
 *     tags: [Destinos]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del destino
 *     responses:
 *       200:
 *         description: Destino eliminado correctamente
 *       500:
 *         description: Error al eliminar el destino
 */
app.delete('/traveler/destinos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.destinos WHERE id_destino = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting destino:', err);
            res.status(500).json({ error: 'Error deleting destino' });
        } else {
            res.json({ success: true });
        }
    });
});







// Tipo Actividad
/**
 * @swagger
 * /traveler/tipo_actividad:
 *   get:
 *     summary: Obtener todos los tipos de actividad
 *     tags: [Tipo Actividad]
 *     responses:
 *       200:
 *         description: Lista de tipos de actividad obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 tipo_actividad:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_tipo_actividad:
 *                         type: integer
 *                       nombre_tipo_actividad:
 *                         type: string
 *       500:
 *         description: Error interno al obtener los tipos de actividad
 */
app.get('/traveler/tipo_actividad', (req, res) => {
    db.query('SELECT * FROM traveler.tipo_actividad', (err, results) => {
        if (err) {
            console.error('Error fetching tipo_actividad:', err);
            res.status(500).json({ error: 'Error fetching tipo_actividad' });
        } else {
            res.json({ tipo_actividad: results });
        }
    });
});

/**
 * @swagger
 * /traveler/tipo_actividad/{id}:
 *   get:
 *     summary: Obtener un tipo de actividad por ID
 *     tags: [Tipo Actividad]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del tipo de actividad
 *     responses:
 *       200:
 *         description: Tipo de actividad encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 tipo_actividad:
 *                   type: object
 *                   properties:
 *                     id_tipo_actividad:
 *                       type: integer
 *                     nombre_tipo_actividad:
 *                       type: string
 *       404:
 *         description: Tipo de actividad no encontrado
 *       500:
 *         description: Error al obtener el tipo de actividad
 */
app.get('/traveler/tipo_actividad/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.tipo_actividad WHERE id_tipo_actividad = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching tipo_actividad:', err);
            res.status(500).json({ error: 'Error fetching tipo_actividad' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Tipo_actividad not found' });
            } else {
                res.json({ tipo_actividad: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/tipo_actividad:
 *   post:
 *     summary: Crear un nuevo tipo de actividad
 *     tags: [Tipo Actividad]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nombre_tipo_actividad
 *             properties:
 *               nombre_tipo_actividad:
 *                 type: string
 *     responses:
 *       200:
 *         description: Tipo de actividad creado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear el tipo de actividad
 */
app.post('/traveler/tipo_actividad', authenticateToken, (req, res) => {
    const { nombre_tipo_actividad } = req.body;
    db.query('INSERT INTO traveler.tipo_actividad (nombre_tipo_actividad) VALUES (?)', [nombre_tipo_actividad], (err, result) => {
        if (err) {
            console.error('Error creating tipo_actividad:', err);
            res.status(500).json({ error: 'Error creating tipo_actividad' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/tipo_actividad/{id}:
 *   put:
 *     summary: Actualizar un tipo de actividad por ID
 *     tags: [Tipo Actividad]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del tipo de actividad
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_tipo_actividad:
 *                 type: string
 *     responses:
 *       200:
 *         description: Tipo de actividad actualizado correctamente
 *       500:
 *         description: Error al actualizar el tipo de actividad
 */
app.put('/traveler/tipo_actividad/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { nombre_tipo_actividad } = req.body;
    db.query('UPDATE traveler.tipo_actividad SET nombre_tipo_actividad = ? WHERE id_tipo_actividad = ?', [nombre_tipo_actividad, id], (err, result) => {
        if (err) {
            console.error('Error updating tipo_actividad:', err);
            res.status(500).json({ error: 'Error updating tipo_actividad' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/tipo_actividad/{id}:
 *   delete:
 *     summary: Eliminar un tipo de actividad por ID
 *     tags: [Tipo Actividad]
 *     security:
 *       - BearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del tipo de actividad
 *     responses:
 *       200:
 *         description: Tipo de actividad eliminado correctamente
 *       500:
 *         description: Error al eliminar el tipo de actividad
 */
app.delete('/traveler/tipo_actividad/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.tipo_actividad WHERE id_tipo_actividad = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting tipo_actividad:', err);
            res.status(500).json({ error: 'Error deleting tipo_actividad' });
        } else {
            res.json({ success: true });
        }
    });
});







// Actividades
/**
 * @swagger
 * /traveler/actividades:
 *   get:
 *     summary: Obtener todas las actividades
 *     tags: [Actividades]
 *     responses:
 *       200:
 *         description: Lista de actividades obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 actividades:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_actividad:
 *                         type: integer
 *                       id_destino:
 *                         type: integer
 *                       id_tipo_actividad:
 *                         type: integer
 *                       disponibilidad_actividad:
 *                         type: boolean
 *                       precio:
 *                         type: number
 *                         format: float
 *                       descripcion:
 *                         type: string
 *       500:
 *         description: Error interno al obtener las actividades
 */
app.get('/traveler/actividades', (req, res) => {
    db.query('SELECT * FROM traveler.actividades', (err, results) => {
        if (err) {
            console.error('Error fetching actividades:', err);
            res.status(500).json({ error: 'Error fetching actividades' });
        } else {
            res.json({ actividades: results });
        }
    });
});

/**
 * @swagger
 * /traveler/actividades/{id}:
 *   get:
 *     summary: Obtener una actividad específica por su ID
 *     tags: [Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la actividad
 *     responses:
 *       200:
 *         description: Detalles de la actividad obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 actividad:
 *                   type: object
 *                   properties:
 *                     id_actividad:
 *                       type: integer
 *                     id_destino:
 *                       type: integer
 *                     id_tipo_actividad:
 *                       type: integer
 *                     disponibilidad_actividad:
 *                       type: boolean
 *                     precio:
 *                       type: number
 *                       format: float
 *                     descripcion:
 *                       type: string
 *       404:
 *         description: Actividad no encontrada
 *       500:
 *         description: Error interno al obtener la actividad
 */
app.get('/traveler/actividades/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.actividades WHERE id_actividad = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching actividad:', err);
            res.status(500).json({ error: 'Error fetching actividad' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Actividad not found' });
            } else {
                res.json({ actividad: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/actividades_completo:
 *   get:
 *     summary: Obtener todas las actividades con información completa (incluyendo imágenes)
 *     tags: [Actividades]
 *     responses:
 *       200:
 *         description: Lista de actividades completas obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 actividades:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_actividad:
 *                         type: integer
 *                       id_destino:
 *                         type: integer
 *                       id_tipo_actividad:
 *                         type: integer
 *                       disponibilidad_actividad:
 *                         type: boolean
 *                       precio:
 *                         type: number
 *                         format: float
 *                       descripcion:
 *                         type: string
 *                       imagen_actividad:
 *                         type: string
 *                         format: uri
 *       500:
 *         description: Error interno al obtener las actividades completas
 */
app.get('/traveler/actividades_completo', (req, res) => {
    db.query('SELECT * FROM actividades JOIN tipo_actividad ON actividades.id_tipo_actividad = tipo_actividad.id_tipo_actividad JOIN destinos ON actividades.id_destino = destinos.id_destino JOIN imagenes_actividades ON actividades.id_actividad = imagenes_actividades.id_actividad', (err, results) => {
        if (err) {
            console.error('Error fetching actividades:', err);
            res.status(500).json({ error: 'Error fetching actividades' });
        } else {
            res.json({ actividades: results });
        }
    });
});

/**
 * @swagger
 * /traveler/actividades_completo_sin_imagenes:
 *   get:
 *     summary: Obtener todas las actividades con información completa sin imágenes
 *     tags: [Actividades]
 *     responses:
 *       200:
 *         description: Lista de actividades completas sin imágenes obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 actividades:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_actividad:
 *                         type: integer
 *                       id_destino:
 *                         type: integer
 *                       id_tipo_actividad:
 *                         type: integer
 *                       disponibilidad_actividad:
 *                         type: boolean
 *                       precio:
 *                         type: number
 *                         format: float
 *                       descripcion:
 *                         type: string
 *       500:
 *         description: Error interno al obtener las actividades sin imágenes
 */
app.get('/traveler/actividades_completo_sin_imagenes', (req, res) => {
    db.query('SELECT * FROM actividades JOIN tipo_actividad ON actividades.id_tipo_actividad = tipo_actividad.id_tipo_actividad JOIN destinos ON actividades.id_destino = destinos.id_destino', (err, results) => {
        if (err) {
            console.error('Error fetching actividades:', err);
            res.status(500).json({ error: 'Error fetching actividades' });
        } else {
            res.json({ actividades: results });
        }
    });
}
);

/**
 * @swagger
 * /traveler/actividades_completo/{id}:
 *   get:
 *     summary: Obtener una actividad completa por su ID (incluyendo imágenes)
 *     tags: [Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la actividad
 *     responses:
 *       200:
 *         description: Detalles completos de la actividad obtenida correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 actividad:
 *                   type: object
 *                   properties:
 *                     id_actividad:
 *                       type: integer
 *                     id_destino:
 *                       type: integer
 *                     id_tipo_actividad:
 *                       type: integer
 *                     disponibilidad_actividad:
 *                       type: boolean
 *                     precio:
 *                       type: number
 *                       format: float
 *                     descripcion:
 *                       type: string
 *                     imagen_actividad:
 *                       type: string
 *                       format: uri
 *       404:
 *         description: Actividad no encontrada
 *       500:
 *         description: Error interno al obtener la actividad
 */
app.get('/traveler/actividades_completo/:id', (req, res) => {
    const id = req.params.id;
    db.query('SELECT * FROM actividades JOIN tipo_actividad ON actividades.id_tipo_actividad = tipo_actividad.id_tipo_actividad JOIN destinos ON actividades.id_destino = destinos.id_destino JOIN imagenes_actividades ON actividades.id_actividad = imagenes_actividades.id_actividad WHERE actividades.id_actividad = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching actividades:', err);
            res.status(500).json({ error: 'Error fetching actividades' });
        } else {
            res.json({ actividades: results });
        }
    });
});

/**
 * @swagger
 * /traveler/actividades_completo/{id}:
 *   put:
 *     summary: Actualizar los detalles de una actividad por su ID
 *     tags: [Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la actividad
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_destino:
 *                 type: integer
 *               id_tipo_actividad:
 *                 type: integer
 *               disponibilidad_actividad:
 *                 type: boolean
 *               precio:
 *                 type: number
 *                 format: float
 *     responses:
 *       200:
 *         description: Actividad actualizada correctamente
 *       400:
 *         description: Petición incorrecta
 *       500:
 *         description: Error interno al actualizar la actividad
 */
app.put('/traveler/actividades_completo/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_destino, id_tipo_actividad, disponibilidad_actividad, precio } = req.body;
    db.query('UPDATE traveler.actividades SET id_destino = ?, id_tipo_actividad = ?, disponibilidad_actividad = ?, precio = ? WHERE id_actividad = ?', [id_destino, id_tipo_actividad, disponibilidad_actividad, precio, id], (err, result) => {
        if (err) {
            console.error('Error updating actividad:', err);
            res.status(500).json({ error: 'Error updating actividad' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/actividades:
 *   post:
 *     summary: Crear una nueva actividad
 *     tags: [Actividades]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_destino:
 *                 type: integer
 *               id_tipo_actividad:
 *                 type: integer
 *               disponibilidad_actividad:
 *                 type: boolean
 *               precio:
 *                 type: number
 *                 format: float
 *               descripcion:
 *                 type: string
 *     responses:
 *       200:
 *         description: Actividad creada correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id_actividad:
 *                   type: integer
 *       400:
 *         description: Petición incorrecta
 *       500:
 *         description: Error interno al crear la actividad
 */
app.post('/traveler/actividades', authenticateToken, (req, res) => {
    const { id_destino, id_tipo_actividad, disponibilidad_actividad, precio, descripcion } = req.body;
    const disponibilidad = Boolean(disponibilidad_actividad);

    db.query('INSERT INTO traveler.actividades ( id_destino, id_tipo_actividad, disponibilidad_actividad, precio, descripcion) VALUES ( ?, ?, ?, ?, ?)', [id_destino, id_tipo_actividad, disponibilidad, precio, descripcion], (err, result) => {
        if (err) {
            console.error('Error creating actividad:', err);
            res.status(500).json({ error: 'Error creating actividad' });
        } else {
            res.json({ id_actividad: result.insertId });
        }
    }
    );

});

/**
 * @swagger
 * /traveler/actividades/{id}:
 *   put:
 *     summary: Actualizar los detalles de una actividad por su ID
 *     tags: [Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la actividad
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_destino:
 *                 type: integer
 *               id_tipo_actividad:
 *                 type: integer
 *               disponibilidad_actividad:
 *                 type: boolean
 *               precio:
 *                 type: number
 *                 format: float
 *     responses:
 *       200:
 *         description: Actividad actualizada correctamente
 *       400:
 *         description: Petición incorrecta
 *       500:
 *         description: Error interno al actualizar la actividad
 */
app.put('/traveler/actividades/:id', authenticateToken, (req, res) => {
    const id_actividad = req.params.id;
    const { id_destino, id_tipo_actividad, disponibilidad_actividad, precio } = req.body;
    const disponibilidad = Boolean(disponibilidad_actividad);

    db.query('UPDATE traveler.actividades SET id_destino = ?, id_tipo_actividad = ?, disponibilidad_actividad = ?, precio = ? WHERE id_actividad = ?', [id_destino, id_tipo_actividad, disponibilidad, id_actividad, precio], (err, result) => {
        if (err) {
            console.error('Error updating actividad:', err);
            res.status(500).json({ error: 'Error updating actividad' });
        } else {
            res.json({ success: true });
        }
    });

});

/**
 * @swagger
 * /traveler/actividades/{id}:
 *   delete:
 *     summary: Eliminar una actividad por su ID
 *     tags: [Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la actividad
 *     responses:
 *       200:
 *         description: Actividad eliminada correctamente
 *       404:
 *         description: Actividad no encontrada
 *       500:
 *         description: Error interno al eliminar la actividad
 */
app.delete('/traveler/actividades/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.actividades WHERE id_actividad = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting actividad:', err);
            res.status(500).json({ error: 'Error deleting actividad' });
        } else {
            res.json({ success: true });
        }
    });
});







// Alojamientos
/**
 * @swagger
 * /traveler/alojamientos:
 *   get:
 *     summary: Obtener todos los alojamientos
 *     tags: [Alojamientos]
 *     responses:
 *       200:
 *         description: Lista de alojamientos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 alojamientos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_alojamiento:
 *                         type: integer
 *                       nombre_alojamiento:
 *                         type: string
 *                       precio_dia:
 *                         type: number
 *                         format: float
 *                       descripcion:
 *                         type: string
 *                       direccion:
 *                         type: string
 *                       hora_entrada:
 *                         type: string
 *                       hora_salida:
 *                         type: string
 *       500:
 *         description: Error al obtener los alojamientos
 */
app.get('/traveler/alojamientos', (req, res) => {
    db.query('SELECT * FROM traveler.alojamientos', (err, results) => {
        if (err) {
            console.error('Error fetching alojamientos:', err);
            res.status(500).json({ error: 'Error fetching alojamientos' });
        } else {
            res.json({ alojamientos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/alojamientos_completo:
 *   get:
 *     summary: Obtener todos los alojamientos con detalles completos
 *     tags: [Alojamientos]
 *     responses:
 *       200:
 *         description: Lista de alojamientos completos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 alojamientos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_alojamiento:
 *                         type: integer
 *                       nombre_alojamiento:
 *                         type: string
 *                       precio_dia:
 *                         type: number
 *                         format: float
 *                       descripcion:
 *                         type: string
 *                       direccion:
 *                         type: string
 *                       hora_entrada:
 *                         type: string
 *                       hora_salida:
 *                         type: string
 *                       destino:
 *                         type: object
 *                         properties:
 *                           id_destino:
 *                             type: integer
 *                           nombre_destino:
 *                             type: string
 *                       usuario:
 *                         type: object
 *                         properties:
 *                           id_usuario:
 *                             type: integer
 *                           nombre_usuario:
 *                             type: string
 *       500:
 *         description: Error al obtener los alojamientos completos
 */
app.get('/traveler/alojamientos_completo', (req, res) => {
    db.query('SELECT * FROM traveler.alojamientos JOIN traveler.destinos ON alojamientos.id_destino = destinos.id_destino JOIN traveler.usuarios ON alojamientos.id_usuario = usuarios.id_usuario', (err, results) => {
        if (err) {
            console.error('Error fetching alojamientos:', err);
            res.status(500).json({ error: 'Error fetching alojamientos' });
        } else {
            res.json({ alojamientos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/alojamientos_completo/{id}:
 *   get:
 *     summary: Obtener alojamiento completo por ID
 *     tags: [Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del alojamiento
 *     responses:
 *       200:
 *         description: Información del alojamiento completo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 alojamiento:
 *                   type: object
 *                   properties:
 *                     id_alojamiento:
 *                       type: integer
 *                     nombre_alojamiento:
 *                       type: string
 *                     precio_dia:
 *                       type: number
 *                       format: float
 *                     descripcion:
 *                       type: string
 *                     direccion:
 *                       type: string
 *                     hora_entrada:
 *                       type: string
 *                     hora_salida:
 *                       type: string
 *                     destino:
 *                       type: object
 *                       properties:
 *                         id_destino:
 *                           type: integer
 *                         nombre_destino:
 *                           type: string
 *                     usuario:
 *                       type: object
 *                       properties:
 *                         id_usuario:
 *                           type: integer
 *                         nombre_usuario:
 *                           type: string
 *       404:
 *         description: Alojamiento no encontrado
 *       500:
 *         description: Error al obtener el alojamiento completo
 */
app.get('/traveler/alojamientos_completo/:id', (req, res) => {
    const id = req.params.id;
    db.query('SELECT * FROM traveler.alojamientos JOIN traveler.destinos ON alojamientos.id_destino = destinos.id_destino JOIN traveler.usuarios ON alojamientos.id_usuario = usuarios.id_usuario WHERE alojamientos.id_alojamiento = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching alojamientos:', err);
            res.status(500).json({ error: 'Error fetching alojamientos' });
        } else {
            res.json({ alojamientos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/alojamientos/{id}:
 *   get:
 *     summary: Obtener un alojamiento por ID
 *     tags: [Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del alojamiento
 *     responses:
 *       200:
 *         description: Información del alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 alojamiento:
 *                   type: object
 *                   properties:
 *                     id_alojamiento:
 *                       type: integer
 *                     nombre_alojamiento:
 *                       type: string
 *                     precio_dia:
 *                       type: number
 *                       format: float
 *                     descripcion:
 *                       type: string
 *                     direccion:
 *                       type: string
 *                     hora_entrada:
 *                       type: string
 *                     hora_salida:
 *                       type: string
 *       404:
 *         description: Alojamiento no encontrado
 *       500:
 *         description: Error al obtener el alojamiento
 */
app.get('/traveler/alojamientos/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.alojamientos WHERE id_alojamiento = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching alojamiento:', err);
            res.status(500).json({ error: 'Error fetching alojamiento' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Alojamiento not found' });
            } else {
                res.json({ alojamiento: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/alojamientos:
 *   post:
 *     summary: Crear un nuevo alojamiento
 *     tags: [Alojamientos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_alojamiento:
 *                 type: string
 *               id_destino:
 *                 type: integer
 *               precio_dia:
 *                 type: number
 *                 format: float
 *               descripcion:
 *                 type: string
 *               max_personas:
 *                 type: integer
 *               direccion:
 *                 type: string
 *               hora_entrada:
 *                 type: string
 *               hora_salida:
 *                 type: string
 *     responses:
 *       200:
 *         description: Alojamiento creado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id_alojamiento:
 *                   type: integer
 *       500:
 *         description: Error al crear alojamiento
 */
app.post('/traveler/alojamientos', authenticateToken, (req, res) => {
    const { nombre_alojamiento, id_destino, precio_dia, descripcion, max_personas, direccion, hora_entrada, hora_salida } = req.body;
    const id_usuario = req.user.id;
    db.query('INSERT INTO traveler.alojamientos (nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion, hora_entrada, hora_salida) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion, hora_entrada, hora_salida], (err, result) => {
        if (err) {
            console.error('Error creating alojamiento:', err);
            res.status(500).json({ error: 'Error creating alojamiento' });
        } else {
            res.json({ id_alojamiento: result.insertId });
        }
    }
    );
});

/**
 * @swagger
 * /traveler/alojamientos/{id}:
 *   put:
 *     summary: Actualizar un alojamiento por ID
 *     tags: [Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del alojamiento
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_alojamiento:
 *                 type: string
 *               id_destino:
 *                 type: integer
 *               precio_dia:
 *                 type: number
 *                 format: float
 *               descripcion:
 *                 type: string
 *               max_personas:
 *                 type: integer
 *               direccion:
 *                 type: string
 *               hora_entrada:
 *                 type: string
 *               hora_salida:
 *                 type: string
 *     responses:
 *       200:
 *         description: Alojamiento actualizado exitosamente
 *       500:
 *         description: Error al actualizar alojamiento
 */
app.put('/traveler/alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion, hora_entrada, hora_salida } = req.body;
    db.query('UPDATE traveler.alojamientos SET nombre_alojamiento = ?, id_destino = ?, precio_dia = ?, descripcion = ?, id_usuario = ?, max_personas = ?, direccion = ?, hora_entrada = ?, hora_salida = ? WHERE id_alojamiento = ?', [nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion, hora_entrada, hora_salida, id], (err, result) => {
        if (err) {
            console.error('Error updating alojamiento:', err);
            res.status(500).json({ error: 'Error updating alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/alojamientos_completo/{id}:
 *   put:
 *     summary: Actualizar un alojamiento completo por ID
 *     tags: [Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del alojamiento
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_alojamiento:
 *                 type: string
 *               id_destino:
 *                 type: integer
 *               precio_dia:
 *                 type: number
 *                 format: float
 *               descripcion:
 *                 type: string
 *               max_personas:
 *                 type: integer
 *               direccion:
 *                 type: string
 *               hora_entrada:
 *                 type: string
 *               hora_salida:
 *                 type: string
 *     responses:
 *       200:
 *         description: Alojamiento completo actualizado exitosamente
 *       500:
 *         description: Error al actualizar alojamiento completo
 */
app.put('/traveler/alojamientos_completo/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion, hora_entrada, hora_salida } = req.body;
    db.query('UPDATE traveler.alojamientos SET nombre_alojamiento = ?, id_destino = ?, precio_dia = ?, descripcion = ?, id_usuario = ?, max_personas = ?, direccion = ?, hora_entrada = ?, hora_salida = ? WHERE id_alojamiento = ?', [nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion, hora_entrada, hora_salida, id], (err, result) => {
        if (err) {
            console.error('Error updating alojamiento:', err);
            res.status(500).json({ error: 'Error updating alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/alojamientos/{id}:
 *   delete:
 *     summary: Eliminar un alojamiento por ID
 *     tags: [Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del alojamiento
 *     responses:
 *       200:
 *         description: Alojamiento eliminado exitosamente
 *       500:
 *         description: Error al eliminar alojamiento
 */
app.delete('/traveler/alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.alojamientos WHERE id_alojamiento = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting alojamiento:', err);
            res.status(500).json({ error: 'Error deleting alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});







// Valoraciones Alojamientos
/**
 * @swagger
 * /traveler/valoraciones_alojamientos:
 *   get:
 *     summary: Obtener todas las valoraciones de alojamientos
 *     tags: [Valoraciones Alojamientos]
 *     responses:
 *       200:
 *         description: Lista de valoraciones de alojamientos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 valoraciones_alojamientos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_valoracion:
 *                         type: integer
 *                       id_alojamiento:
 *                         type: integer
 *                       valoracion:
 *                         type: integer
 *                       comentario:
 *                         type: string
 *                       id_usuario:
 *                         type: integer
 *       500:
 *         description: Error al obtener las valoraciones de alojamientos
 */
app.get('/traveler/valoraciones_alojamientos', (req, res) => {
    db.query('SELECT * FROM traveler.valoraciones_alojamientos', (err, results) => {
        if (err) {
            console.error('Error fetching valoraciones_alojamientos:', err);
            res.status(500).json({ error: 'Error fetching valoraciones_alojamientos' });
        } else {
            res.json({ valoraciones_alojamientos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/valoraciones_alojamientos/{id}:
 *   get:
 *     summary: Obtener una valoración de alojamiento por ID
 *     tags: [Valoraciones Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la valoración
 *     responses:
 *       200:
 *         description: Información de la valoración de alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 valoracion_alojamiento:
 *                   type: object
 *                   properties:
 *                     id_valoracion:
 *                       type: integer
 *                     id_alojamiento:
 *                       type: integer
 *                     valoracion:
 *                       type: integer
 *                     comentario:
 *                       type: string
 *                     id_usuario:
 *                       type: integer
 *       404:
 *         description: Valoración de alojamiento no encontrada
 *       500:
 *         description: Error al obtener la valoración de alojamiento
 */
app.get('/traveler/valoraciones_alojamientos/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.valoraciones_alojamientos WHERE id_valoracion = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching valoraciones_alojamientos:', err);
            res.status(500).json({ error: 'Error fetching valoraciones_alojamientos' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Valoracion_alojamiento not found' });
            } else {
                res.json({ valoracion_alojamiento: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/valoraciones_alojamientos:
 *   post:
 *     summary: Crear una nueva valoración de alojamiento
 *     tags: [Valoraciones Alojamientos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *               valoracion:
 *                 type: integer
 *               comentario:
 *                 type: string
 *               id_usuario:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Valoración de alojamiento creada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear la valoración de alojamiento
 */
app.post('/traveler/valoraciones_alojamientos', authenticateToken, (req, res) => {
    const { id_alojamiento, valoracion, comentario, id_usuario } = req.body;
    db.query('INSERT INTO traveler.valoraciones_alojamientos (id_alojamiento, valoracion, comentario, id_usuario) VALUES (?, ?, ?, ?)', [id_alojamiento, valoracion, comentario, id_usuario], (err, result) => {
        if (err) {
            console.error('Error creating valoracion_alojamiento:', err);
            res.status(500).json({ error: 'Error creating valoracion_alojamiento' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/valoraciones_alojamientos/{id}:
 *   put:
 *     summary: Actualizar una valoración de alojamiento por ID
 *     tags: [Valoraciones Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la valoración
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *               valoracion:
 *                 type: integer
 *               comentario:
 *                 type: string
 *               id_usuario:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Valoración de alojamiento actualizada exitosamente
 *       500:
 *         description: Error al actualizar la valoración de alojamiento
 */
app.put('/traveler/valoraciones_alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_alojamiento, valoracion, comentario, id_usuario } = req.body;
    db.query('UPDATE traveler.valoraciones_alojamientos SET id_alojamiento = ?, valoracion = ?, comentario = ?, id_usuario = ? WHERE id_valoracion = ?', [id_alojamiento, valoracion, comentario, id_usuario, id], (err, result) => {
        if (err) {
            console.error('Error updating valoracion_alojamiento:', err);
            res.status(500).json({ error: 'Error updating valoracion_alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/valoraciones_alojamientos/{id}:
 *   delete:
 *     summary: Eliminar una valoración de alojamiento por ID
 *     tags: [Valoraciones Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la valoración
 *     responses:
 *       200:
 *         description: Valoración de alojamiento eliminada exitosamente
 *       500:
 *         description: Error al eliminar la valoración de alojamiento
 */
app.delete('/traveler/valoraciones_alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.valoraciones_alojamientos WHERE id_valoracion = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting valoracion_alojamiento:', err);
            res.status(500).json({ error: 'Error deleting valoracion_alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});







// Imagenes Alojamientos
/**
 * @swagger
 * /traveler/imagenes_alojamientos:
 *   get:
 *     summary: Obtener todas las imágenes de alojamientos
 *     tags: [Imagenes Alojamientos]
 *     responses:
 *       200:
 *         description: Lista de imágenes de alojamientos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagenes:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_imagen_alojamiento:
 *                         type: integer
 *                       id_alojamiento:
 *                         type: integer
 *                       nombre_imagen_alojamiento:
 *                         type: string
 *       500:
 *         description: Error al obtener las imágenes de alojamientos
 */
app.get('/traveler/imagenes_alojamientos', (req, res) => {
    db.query('SELECT * FROM traveler.imagenes_alojamientos', (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Error fetching imagenes_alojamientos' });
        } else {
            res.json({ imagenes: results });
        }
    });
});

/**
 * @swagger
 * /traveler/imagenes_alojamientos/{id}:
 *   get:
 *     summary: Obtener una imagen de alojamiento por ID
 *     tags: [Imagenes Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la imagen
 *     responses:
 *       200:
 *         description: Información de la imagen de alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagen_alojamiento:
 *                   type: object
 *                   properties:
 *                     id_imagen_alojamiento:
 *                       type: integer
 *                     id_alojamiento:
 *                       type: integer
 *                     nombre_imagen_alojamiento:
 *                       type: string
 *       404:
 *         description: Imagen de alojamiento no encontrada
 *       500:
 *         description: Error al obtener la imagen de alojamiento
 */
app.get('/traveler/imagenes_alojamientos/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.imagenes_alojamientos WHERE id_imagen_alojamiento = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching imagenes_alojamientos:', err);
            res.status(500).json({ error: 'Error fetching imagenes_alojamientos' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Imagen_alojamiento not found' });
            } else {
                res.json({ imagen_alojamiento: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/imagenes_alojamientos/alojamiento/{id}:
 *   get:
 *     summary: Obtener las imágenes de un alojamiento por ID de alojamiento
 *     tags: [Imagenes Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del alojamiento
 *     responses:
 *       200:
 *         description: Lista de nombres de imágenes de alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagenes:
 *                   type: array
 *                   items:
 *                     type: string
 *       404:
 *         description: No se encontraron imágenes para el alojamiento
 *       500:
 *         description: Error al obtener las imágenes de alojamiento
 */
app.get('/traveler/imagenes_alojamientos/alojamiento/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT nombre_imagen_alojamiento FROM traveler.imagenes_alojamientos WHERE id_alojamiento = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching imagenes_alojamientos:', err);
            res.status(500).json({ error: 'Error fetching imagenes_alojamientos' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Imagen_alojamiento not found' });
            } else {
                res.json({ imagenes: results.map(row => row.nombre_imagen_alojamiento) });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/imagenes_alojamientos:
 *   post:
 *     summary: Crear una nueva imagen de alojamiento
 *     tags: [Imagenes Alojamientos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *               nombre_imagen_alojamiento:
 *                 type: string
 *     responses:
 *       200:
 *         description: Imagen de alojamiento creada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear la imagen de alojamiento
 */
app.post('/traveler/imagenes_alojamientos', authenticateToken, (req, res) => {
    const { id_alojamiento, nombre_imagen_alojamiento } = req.body;
    db.query('INSERT INTO traveler.imagenes_alojamientos (id_alojamiento, nombre_imagen_alojamiento) VALUES (?, ?)', [id_alojamiento, nombre_imagen_alojamiento], (err, result) => {
        if (err) {
            console.error('Error creating imagen_alojamiento:', err);
            res.status(500).json({ error: 'Error creating imagen_alojamiento' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/imagenes_alojamientos/{id}:
 *   put:
 *     summary: Actualizar una imagen de alojamiento por ID
 *     tags: [Imagenes Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la imagen
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *               nombre_imagen_alojamiento:
 *                 type: string
 *     responses:
 *       200:
 *         description: Imagen de alojamiento actualizada exitosamente
 *       500:
 *         description: Error al actualizar la imagen de alojamiento
 */
app.put('/traveler/imagenes_alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_alojamiento, nombre_imagen_alojamiento } = req.body;
    db.query('UPDATE traveler.imagenes_alojamientos SET id_alojamiento = ?, nombre_imagen_alojamiento = ? WHERE id_imagen_alojamiento = ?', [id_alojamiento, nombre_imagen_alojamiento, id], (err, result) => {
        if (err) {
            console.error('Error updating imagen_alojamiento:', err);
            res.status(500).json({ error: 'Error updating imagen_alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/imagenes_alojamientos/{id}:
 *   delete:
 *     summary: Eliminar una imagen de alojamiento por ID
 *     tags: [Imagenes Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la imagen
 *     responses:
 *       200:
 *         description: Imagen de alojamiento eliminada exitosamente
 *       500:
 *         description: Error al eliminar la imagen de alojamiento
 */
app.delete('/traveler/imagenes_alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.imagenes_alojamientos WHERE id_imagen_alojamiento = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting imagen_alojamiento:', err);
            res.status(500).json({ error: 'Error deleting imagen_alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});







//imagenes actividades
/**
 * @swagger
 * /traveler/imagenes_actividades:
 *   get:
 *     summary: Obtener todas las imágenes de actividades
 *     tags: [Imagenes Actividades]
 *     responses:
 *       200:
 *         description: Lista de imágenes de actividades
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagenes_actividades:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_imagen_actividad:
 *                         type: integer
 *                       id_actividad:
 *                         type: integer
 *                       nombre_imagen_actividad:
 *                         type: string
 *       500:
 *         description: Error al obtener las imágenes de actividades
 */
app.get('/traveler/imagenes_actividades', (req, res) => {
    db.query('SELECT * FROM traveler.imagenes_actividades', (err, results) => {
        if (err) {
            console.error('Error fetching imagenes_actividades:', err);
            res.status(500).json({ error: 'Error fetching imagenes_actividades' });
        } else {
            res.json({ imagenes_actividades: results });
        }
    });
});

/**
 * @swagger
 * /traveler/imagenes_actividades:
 *   post:
 *     summary: Crear una nueva imagen de actividad
 *     tags: [Imagenes Actividades]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_actividad:
 *                 type: integer
 *               nombre_imagen_actividad:
 *                 type: string
 *     responses:
 *       200:
 *         description: Imagen de actividad creada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear la imagen de actividad
 */
app.post('/traveler/imagenes_actividades', authenticateToken, (req, res) => {
    const { id_actividad, nombre_imagen_actividad } = req.body;
    db.query('INSERT INTO traveler.imagenes_actividades (id_actividad, nombre_imagen_actividad) VALUES (?, ?)', [id_actividad, nombre_imagen_actividad], (err, result) => {
        if (err) {
            console.error('Error creating imagen_actividad:', err);
            res.status(500).json({ error: 'Error creating imagen_actividad' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/imagenes_actividades/{id}:
 *   get:
 *     summary: Obtener una imagen de actividad por ID
 *     tags: [Imagenes Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la imagen
 *     responses:
 *       200:
 *         description: Información de la imagen de actividad
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagen_actividad:
 *                   type: object
 *                   properties:
 *                     id_imagen_actividad:
 *                       type: integer
 *                     id_actividad:
 *                       type: integer
 *                     nombre_imagen_actividad:
 *                       type: string
 *       404:
 *         description: Imagen de actividad no encontrada
 *       500:
 *         description: Error al obtener la imagen de actividad
 */
app.get('/traveler/imagenes_actividades/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.imagenes_actividades WHERE id_imagen_actividad = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching imagenes_actividades:', err);
            res.status(500).json({ error: 'Error fetching imagenes_actividades' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Imagen_actividad not found' });
            } else {
                res.json({ imagen_actividad: results[0] });
            }
        }
    });
});







// Post Blog
/**
 * @swagger
 * /traveler/post_blog:
 *   get:
 *     summary: Obtener todos los posts de blog
 *     tags: [Post Blog]
 *     responses:
 *       200:
 *         description: Lista de posts de blog
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 post_blog:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_post:
 *                         type: integer
 *                       id_usuario:
 *                         type: integer
 *                       titulo:
 *                         type: string
 *                       mensaje_post:
 *                         type: string
 *       500:
 *         description: Error al obtener los posts de blog
 */
app.get('/traveler/post_blog', (req, res) => {
    db.query('SELECT * FROM traveler.post_blog', (err, results) => {
        if (err) {
            console.error('Error fetching post_blog:', err);
            res.status(500).json({ error: 'Error fetching post_blog' });
        } else {
            res.json({ post_blog: results });
        }
    });
});

/**
 * @swagger
 * /traveler/post_blog/{id}:
 *   get:
 *     summary: Obtener un post de blog por ID
 *     tags: [Post Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del post
 *     responses:
 *       200:
 *         description: Información del post de blog
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 post_blog:
 *                   type: object
 *                   properties:
 *                     id_post:
 *                       type: integer
 *                     id_usuario:
 *                       type: integer
 *                     titulo:
 *                       type: string
 *                     mensaje_post:
 *                       type: string
 *       404:
 *         description: Post de blog no encontrado
 *       500:
 *         description: Error al obtener el post de blog
 */
app.get('/traveler/post_blog/:id', (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.post_blog WHERE id_post = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching post_blog:', err);
            res.status(500).json({ error: 'Error fetching post_blog' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Post_blog not found' });
            } else {
                res.json({ post_blog: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/post_blog:
 *   post:
 *     summary: Crear un nuevo post de blog
 *     tags: [Post Blog]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *               titulo:
 *                 type: string
 *               contenido:
 *                 type: string
 *     responses:
 *       200:
 *         description: Post de blog creado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear el post de blog
 */
app.post('/traveler/post_blog', authenticateToken, (req, res) => {
    const { id_usuario, titulo, contenido } = req.body;
    db.query('INSERT INTO traveler.post_blog (id_usuario, titulo, mensaje_post) VALUES (?, ?, ?)', [id_usuario, titulo, contenido], (err, result) => {
        if (err) {
            console.error('Error creating post_blog:', err);
            res.status(500).json({ error: 'Error creating post_blog' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/post_blog/{id}:
 *   put:
 *     summary: Actualizar un post de blog por ID
 *     tags: [Post Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del post
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *               titulo:
 *                 type: string
 *               contenido:
 *                 type: string
 *     responses:
 *       200:
 *         description: Post de blog actualizado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al actualizar el post de blog
 */
app.put('/traveler/post_blog/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_usuario, titulo, contenido } = req.body;
    db.query('UPDATE traveler.post_blog SET id_usuario = ?, titulo = ?, mensaje_post = ? WHERE id_post = ?', [id_usuario, titulo, contenido, id], (err, result) => {
        if (err) {
            console.error('Error updating post_blog:', err);
            res.status(500).json({ error: 'Error updating post_blog' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/post_blog/{id}:
 *   delete:
 *     summary: Eliminar un post de blog por ID
 *     tags: [Post Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del post
 *     responses:
 *       200:
 *         description: Post de blog eliminado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al eliminar el post de blog
 */
app.delete('/traveler/post_blog/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.post_blog WHERE id_post = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting post_blog:', err);
            res.status(500).json({ error: 'Error deleting post_blog' });
        } else {
            res.json({ success: true });
        }
    });
});







// Reservas Alojamientos
app.post('/traveler/reservas_alojamientos', authenticateToken, (req, res) => {
    const { id_alojamiento, fecha_reserva_alojamiento, id_usuario, nombre, apellidos, email, telefono, fecha_entrada_alojamiento, fecha_salida_alojamiento,hora_entrada_alojamiento,
  hora_salida_alojamiento, } = req.body;
    db.query('INSERT INTO traveler.reservas_alojamientos (id_alojamiento, fecha_reserva_alojamiento, id_usuario, nombre, apellidos, email, telefono, fecha_entrada_alojamiento, fecha_salida_alojamiento, hora_entrada_alojamiento, hora_salida_alojamiento) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [id_alojamiento, fecha_reserva_alojamiento, id_usuario, nombre, apellidos, email, telefono, fecha_entrada_alojamiento, fecha_salida_alojamiento, hora_entrada_alojamiento, hora_salida_alojamiento], (err, result) => {
        if (err) {
            console.error('Error creating reserva:', err);
            res.status(500).json({ error: 'Error creating reserva' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_actividades:
 *   get:
 *     summary: Obtener todas las reservas de actividades
 *     tags: [Reservas Actividades]
 *     responses:
 *       200:
 *         description: Lista de reservas de actividades
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reservas_actividades:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_reserva_actividad:
 *                         type: integer
 *                       id_actividad:
 *                         type: integer
 *                       fecha_reserva_actividad:
 *                         type: string
 *                       id_usuario:
 *                         type: integer
 *       500:
 *         description: Error al obtener las reservas de actividades
 */
app.get('/traveler/reservas_actividades', authenticateToken, (req, res) => {
    db.query('SELECT * FROM traveler.reservas_actividades', (err, results) => {
        if (err) {
            console.error('Error fetching reservas_actividades:', err);
            res.status(500).json({ error: 'Error fetching reservas_actividades' });
        } else {
            res.json({ reservas_actividades: results });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_actividades/{id}:
 *   get:
 *     summary: Obtener una reserva de actividad por ID
 *     tags: [Reservas Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de actividad
 *     responses:
 *       200:
 *         description: Información de la reserva de actividad
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reserva_actividad:
 *                   type: object
 *                   properties:
 *                     id_reserva_actividad:
 *                       type: integer
 *                     id_actividad:
 *                       type: integer
 *                     fecha_reserva_actividad:
 *                       type: string
 *                     id_usuario:
 *                       type: integer
 *       404:
 *         description: Reserva de actividad no encontrada
 *       500:
 *         description: Error al obtener la reserva de actividad
 */
app.get('/traveler/reservas_actividades/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.reservas_actividades WHERE id_reserva_actividad = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching reservas_actividades:', err);
            res.status(500).json({ error: 'Error fetching reservas_actividades' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Reserva_actividad not found' });
            } else {
                res.json({ reserva_actividad: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_actividades:
 *   post:
 *     summary: Crear una nueva reserva de actividad
 *     tags: [Reservas Actividades]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_actividad:
 *                 type: integer
 *               fecha_reserva_actividad:
 *                 type: string
 *               id_usuario:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Reserva de actividad creada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear la reserva de actividad
 */
app.post('/traveler/reservas_actividades', authenticateToken, (req, res) => {
    const { id_actividad, fecha_reserva_actividad, id_usuario, fecha_actividad, hora_actividad, nombre, apellidos, email, telefono } = req.body;
    db.query('INSERT INTO traveler.reservas_actividades (id_actividad, fecha_reserva_actividad, id_usuario, fecha_actividad, hora_actividad, nombre, apellidos, email, telefono) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [id_actividad, fecha_reserva_actividad, id_usuario, fecha_actividad, hora_actividad, nombre, apellidos, email, telefono], (err, result) => {
        if (err) {
            console.error('Error creating reserva_actividad:', err);
            res.status(500).json({ error: 'Error creating reserva_actividad' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_actividades/{id}:
 *   put:
 *     summary: Actualizar una reserva de actividad por ID
 *     tags: [Reservas Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de actividad
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_actividad:
 *                 type: integer
 *               fecha_reserva_actividad:
 *                 type: string
 *               id_usuario:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Reserva de actividad actualizada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al actualizar la reserva de actividad
 */
app.put('/traveler/reservas_actividades/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_actividad, fecha_reserva_actividad, id_usuario } = req.body;
    db.query('UPDATE traveler.reservas_actividades SET id_actividad = ?, fecha_reserva_actividad = ?, id_usuario = ? WHERE id_reserva_actividad = ?', [id_actividad, fecha_reserva_actividad, id_usuario, id], (err, result) => {
        if (err) {
            console.error('Error updating reserva_actividad:', err);
            res.status(500).json({ error: 'Error updating reserva_actividad' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_actividades/{id}:
 *   delete:
 *     summary: Eliminar una reserva de actividad por ID
 *     tags: [Reservas Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de actividad
 *     responses:
 *       200:
 *         description: Reserva de actividad eliminada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al eliminar la reserva de actividad
 */
app.delete('/traveler/reservas_actividades/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.reservas_actividades WHERE id_reserva_actividad = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting reserva_actividad:', err);
            res.status(500).json({ error: 'Error deleting reserva_actividad' });
        } else {
            res.json({ success: true });
        }
    });
});







// Reservas Alojamientos
app.get('/traveler/reservas_alojamientos', authenticateToken, (req, res) => {
    db.query('SELECT * FROM traveler.reservas_alojamientos', (err, results) => {
        if (err) {
            console.error('Error fetching reservas_alojamientos:', err);
            res.status(500).json({ error: 'Error fetching reservas_alojamientos' });
        } else {
            res.json({ reservas_alojamientos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_alojamientos/{id}:
 *   get:
 *     summary: Obtener una reserva de alojamiento por ID
 *     tags: [Reservas Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de alojamiento
 *     responses:
 *       200:
 *         description: Información de la reserva de alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reserva_alojamiento:
 *                   type: object
 *                   properties:
 *                     id_reserva_alojamiento:
 *                       type: integer
 *                     id_alojamiento:
 *                       type: integer
 *                     id_usuario:
 *                       type: integer
 *                     fecha_reserva_inicio_alojamiento:
 *                       type: string
 *                     fecha_reserva_final_alojamiento:
 *                       type: string
 *                     hora_entrada_alojamiento:
 *                       type: string
 *                     hora_salida_alojamiento:
 *                       type: string
 *       404:
 *         description: Reserva de alojamiento no encontrada
 *       500:
 *         description: Error al obtener la reserva de alojamiento
 */
app.get('/traveler/reservas_alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.reservas_alojamientos WHERE id_reserva_alojamiento = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching reservas_alojamientos:', err);
            res.status(500).json({ error: 'Error fetching reservas_alojamientos' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Reserva_alojamiento not found' });
            } else {
                res.json({ reserva_alojamiento: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_alojamientos:
 *   post:
 *     summary: Crear una nueva reserva de alojamiento
 *     tags: [Reservas Alojamientos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *               id_usuario:
 *                 type: integer
 *               fecha_reserva_alojamiento:
 *                 type: string
 *               fecha_entrada_alojamiento:
 *                 type: string
 *               fecha_salida_alojamiento:
 *                 type: string
 *               hora_entrada_alojamiento:
 *                 type: string
 *               hora_salida_alojamiento:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reserva de alojamiento creada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear la reserva de alojamiento
 */
app.post('/traveler/reservas_alojamientos', authenticateToken, (req, res) => {
    const { id_alojamiento, id_usuario, fecha_reserva_alojamiento, fecha_entrada_alojamiento, fecha_salida_alojamiento, hora_entrada_alojamiento, hora_salida_alojamiento } = req.body;
    db.query('INSERT INTO traveler.reservas_alojamientos (id_alojamiento, id_usuario, fecha_entrada_alojamiento, fecha_salida_alojamiento) VALUES (?, ?, ?, ?)', [id_alojamiento, id_usuario, fecha_reserva_alojamiento, fecha_entrada_alojamiento, fecha_salida_alojamiento, hora_entrada_alojamiento, hora_salida_alojamiento], (err, result) => {
        if (err) {
            console.error('Error creating reserva_alojamiento:', err);
            res.status(500).json({ error: 'Error creating reserva_alojamiento' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_alojamientos/{id}:
 *   put:
 *     summary: Actualizar una reserva de alojamiento por ID
 *     tags: [Reservas Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de alojamiento
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *               id_usuario:
 *                 type: integer
 *               fecha_reserva_alojamiento:
 *                 type: string
 *               fecha_entrada_alojamiento:
 *                 type: string
 *               fecha_salida_alojamiento:
 *                 type: string
 *               hora_entrada_alojamiento:
 *                 type: string
 *               hora_salida_alojamiento:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reserva de alojamiento actualizada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al actualizar la reserva de alojamiento
 */
app.put('/traveler/reservas_alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_alojamiento, id_usuario, fecha_reserva_alojamiento, fecha_entrada_alojamiento, fecha_salida_alojamiento, hora_entrada_alojamiento, hora_salida_alojamiento } = req.body;
    db.query('UPDATE traveler.reservas_alojamientos SET id_alojamiento = ?, id_usuario = ?, fecha_entrada_alojamiento = ?, fecha_salida_alojamiento = ? WHERE id_reserva_alojamiento = ?', [id_alojamiento, id_usuario, fecha_reserva_alojamiento, fecha_entrada_alojamiento, fecha_salida_alojamiento, hora_entrada_alojamiento, hora_salida_alojamiento, id], (err, result) => {
        if (err) {
            console.error('Error updating reserva_alojamiento:', err);
            res.status(500).json({ error: 'Error updating reserva_alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_alojamientos/{id}:
 *   delete:
 *     summary: Eliminar una reserva de alojamiento por ID
 *     tags: [Reservas Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de alojamiento
 *     responses:
 *       200:
 *         description: Reserva de alojamiento eliminada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al eliminar la reserva de alojamiento
 */
app.delete('/traveler/reservas_alojamientos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.reservas_alojamientos WHERE id_reserva_alojamiento = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting reserva_alojamiento:', err);
            res.status(500).json({ error: 'Error deleting reserva_alojamiento' });
        } else {
            res.json({ success: true });
        }
    });
});







// Reservas Vehiculos
/**
 * @swagger
 * /traveler/reservas_vehiculos:
 *   get:
 *     summary: Obtener todas las reservas de vehículos
 *     tags: [Reservas Vehículos]
 *     responses:
 *       200:
 *         description: Lista de reservas de vehículos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reservas_vehiculos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_reserva_vehiculo:
 *                         type: integer
 *                       id_usuario:
 *                         type: integer
 *                       fecha_reserva_vehiculo:
 *                         type: string
 *       500:
 *         description: Error al obtener las reservas de vehículos
 */
app.get('/traveler/reservas_vehiculos', authenticateToken, (req, res) => {
    db.query('SELECT * FROM traveler.reservas_vehiculos', (err, results) => {
        if (err) {
            console.error('Error fetching reservas_vehiculos:', err);
            res.status(500).json({ error: 'Error fetching reservas_vehiculos' });
        } else {
            res.json({ reservas_vehiculos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vehiculos/{id}:
 *   get:
 *     summary: Obtener una reserva de vehículo por ID
 *     tags: [Reservas Vehículos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de vehículo
 *     responses:
 *       200:
 *         description: Información de la reserva de vehículo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reserva_vehiculo:
 *                   type: object
 *                   properties:
 *                     id_reserva_vehiculo:
 *                       type: integer
 *                     id_usuario:
 *                       type: integer
 *                     fecha_reserva_vehiculo:
 *                       type: string
 *       404:
 *         description: Reserva de vehículo no encontrada
 *       500:
 *         description: Error al obtener la reserva de vehículo
 */
app.get('/traveler/reservas_vehiculos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.reservas_vehiculos WHERE id_reserva_vehiculo = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching reservas_vehiculos:', err);
            res.status(500).json({ error: 'Error fetching reservas_vehiculos' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Reserva_vehiculo not found' });
            } else {
                res.json({ reserva_vehiculo: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vehiculos:
 *   post:
 *     summary: Crear una nueva reserva de vehículo
 *     tags: [Reservas Vehículos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *               fecha_reserva_vehiculo:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reserva de vehículo creada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear la reserva de vehículo
 */
app.post('/traveler/reservas_vehiculos', authenticateToken, (req, res) => {
    const { id_usuario, fecha_reserva_vehiculo } = req.body;
    db.query('INSERT INTO traveler.reservas_vehiculos (id_usuario, fecha_reserva_vehiculo) VALUES (?, ?)', [id_usuario, fecha_reserva_vehiculo], (err, result) => {
        if (err) {
            console.error('Error creating reserva_vehiculo:', err);
            res.status(500).json({ error: 'Error creating reserva_vehiculo' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vehiculos/{id}:
 *   put:
 *     summary: Actualizar una reserva de vehículo por ID
 *     tags: [Reservas Vehículos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de vehículo
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *               fecha_reserva_vehiculo:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reserva de vehículo actualizada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al actualizar la reserva de vehículo
 */
app.put('/traveler/reservas_vehiculos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_usuario, fecha_reserva_vehiculo } = req.body;
    db.query('UPDATE traveler.reservas_vehiculos SET id_usuario = ?, fecha_reserva_vehiculo = ? WHERE id_reserva_vehiculo = ?', [id_usuario, fecha_reserva_vehiculo, id], (err, result) => {
        if (err) {
            console.error('Error updating reserva_vehiculo:', err);
            res.status(500).json({ error: 'Error updating reserva_vehiculo' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vehiculos/{id}:
 *   delete:
 *     summary: Eliminar una reserva de vehículo por ID
 *     tags: [Reservas Vehículos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de vehículo
 *     responses:
 *       200:
 *         description: Reserva de vehículo eliminada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al eliminar la reserva de vehículo
 */
app.delete('/traveler/reservas_vehiculos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.reservas_vehiculos WHERE id_reserva_vehiculo = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting reserva_vehiculo:', err);
            res.status(500).json({ error: 'Error deleting reserva_vehiculo' });
        } else {
            res.json({ success: true });
        }
    });
});







// Reservas Vuelos
/**
 * @swagger
 * /traveler/reservas_vuelos:
 *   get:
 *     summary: Obtener todas las reservas de vuelos
 *     tags: [Reservas Vuelos]
 *     responses:
 *       200:
 *         description: Lista de reservas de vuelos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reservas_vuelos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_reserva_vuelo:
 *                         type: integer
 *                       id_usuario:
 *                         type: integer
 *                       id_vuelo:
 *                         type: integer
 *                       fecha_reserva_vuelo:
 *                         type: string
 *       500:
 *         description: Error al obtener las reservas de vuelos
 */
app.get('/traveler/reservas_vuelos', authenticateToken, (req, res) => {
    db.query('SELECT * FROM traveler.reservas_vuelos', (err, results) => {
        if (err) {
            console.error('Error fetching reservas_vuelos:', err);
            res.status(500).json({ error: 'Error fetching reservas_vuelos' });
        } else {
            res.json({ reservas_vuelos: results });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vuelos/{id}:
 *   get:
 *     summary: Obtener una reserva de vuelo por ID
 *     tags: [Reservas Vuelos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de vuelo
 *     responses:
 *       200:
 *         description: Información de la reserva de vuelo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reserva_vuelo:
 *                   type: object
 *                   properties:
 *                     id_reserva_vuelo:
 *                       type: integer
 *                     id_usuario:
 *                       type: integer
 *                     id_vuelo:
 *                       type: integer
 *                     fecha_reserva_vuelo:
 *                       type: string
 *       404:
 *         description: Reserva de vuelo no encontrada
 *       500:
 *         description: Error al obtener la reserva de vuelo
 */
app.get('/traveler/reservas_vuelos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM traveler.reservas_vuelos WHERE id_reserva_vuelo = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching reservas_vuelos:', err);
            res.status(500).json({ error: 'Error fetching reservas_vuelos' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Reserva_vuelo not found' });
            } else {
                res.json({ reserva_vuelo: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vuelos:
 *   post:
 *     summary: Crear una nueva reserva de vuelo
 *     tags: [Reservas Vuelos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *               id_vuelo:
 *                 type: integer
 *               fecha_reserva_vuelo:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reserva de vuelo creada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear la reserva de vuelo
 */
app.post('/traveler/reservas_vuelos', authenticateToken, (req, res) => {
    const { id_usuario, id_vuelo, fecha_reserva_vuelo } = req.body;
    db.query('INSERT INTO traveler.reservas_vuelos (id_usuario, id_vuelo, fecha_reserva_vuelo) VALUES (?, ?, ?)', [id_usuario, id_vuelo, fecha_reserva_vuelo], (err, result) => {
        if (err) {
            console.error('Error creating reserva_vuelo:', err);
            res.status(500).json({ error: 'Error creating reserva_vuelo' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vuelos/{id}:
 *   put:
 *     summary: Actualizar una reserva de vuelo por ID
 *     tags: [Reservas Vuelos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de vuelo
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *               id_vuelo:
 *                 type: integer
 *               fecha_reserva_vuelo:
 *                 type: string
 *     responses:
 *       200:
 *         description: Reserva de vuelo actualizada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al actualizar la reserva de vuelo
 */
app.put('/traveler/reservas_vuelos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { id_usuario, id_vuelo, fecha_reserva_vuelo } = req.body;
    db.query('UPDATE traveler.reservas_vuelos SET id_usuario = ?, id_vuelo = ?, fecha_reserva_vuelo = ? WHERE id_reserva_vuelo = ?', [id_usuario, id_vuelo, fecha_reserva_vuelo, id], (err, result) => {
        if (err) {
            console.error('Error updating reserva_vuelo:', err);
            res.status(500).json({ error: 'Error updating reserva_vuelo' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /traveler/reservas_vuelos/{id}:
 *   delete:
 *     summary: Eliminar una reserva de vuelo por ID
 *     tags: [Reservas Vuelos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID de la reserva de vuelo
 *     responses:
 *       200:
 *         description: Reserva de vuelo eliminada exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al eliminar la reserva de vuelo
 */
app.delete('/traveler/reservas_vuelos/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM traveler.reservas_vuelos WHERE id_reserva_vuelo = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting reserva_vuelo:', err);
            res.status(500).json({ error: 'Error deleting reserva_vuelo' });
        } else {
            res.json({ success: true });
        }
    });
});







// contacto.contacto
/**
 * @swagger
 * /contacto/contacto:
 *   get:
 *     summary: Obtener todos los registros de contacto
 *     tags: [Contacto]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Lista de contactos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 contacto:
 *                   type: array
 *                   items:
 *                     type: object
 */
app.get('/contacto/contacto', authenticateToken, (req, res) => {
    db.query('SELECT * FROM contacto.contacto', (err, results) => {
        if (err) {
            console.error('Error fetching contacto:', err);
            res.status(500).json({ error: 'Error fetching contacto' });
        } else {
            res.json({ contacto: results });
        }
    });
});

/**
 * @swagger
 * /contacto/contacto/{id}:
 *   get:
 *     summary: Obtener un contacto por ID
 *     tags: [Contacto]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del contacto
 *     responses:
 *       200:
 *         description: Contacto encontrado
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 contacto:
 *                   type: object
 *       404:
 *         description: Contacto no encontrado
 */
app.get('/contacto/contacto/:id', authenticateToken, (req, res) => {
    const id = req.params.id;

    db.query('SELECT * FROM contacto.contacto WHERE id_contacto = ?', [id], (err, results) => {
        if (err) {
            console.error('Error fetching contacto:', err);
            res.status(500).json({ error: 'Error fetching contacto' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Contacto entry not found' });
            } else {
                res.json({ contacto: results[0] });
            }
        }
    });
});

/**
 * @swagger
 * /contacto/contacto:
 *   post:
 *     summary: Crear un nuevo contacto
 *     tags: [Contacto]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nombre
 *               - apellido1
 *               - correo
 *               - mensaje
 *             properties:
 *               nombre:
 *                 type: string
 *               apellido1:
 *                 type: string
 *               apellido2:
 *                 type: string
 *               correo:
 *                 type: string
 *               telefono:
 *                 type: string
 *               asunto:
 *                 type: string
 *               mensaje:
 *                 type: string
 *     responses:
 *       200:
 *         description: Contacto creado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error al crear el contacto
 */
app.post('/contacto/contacto', /*authenticateToken,*/(req, res) => {
    const { nombre, apellido1, apellido2, correo, telefono, asunto, mensaje } = req.body;
    db.query('INSERT INTO contacto.contacto (nombre, apellido1, apellido2, correo, telefono, asunto, mensaje) VALUES (?, ?, ?, ?, ?, ?, ?)', [nombre, apellido1, apellido2, correo, telefono, asunto, mensaje], (err, result) => {
        if (err) {
            console.error('Error creating contacto:', err);
            res.status(500).json({ error: 'Error creating contacto' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /contacto/contacto/{id}:
 *   put:
 *     summary: Actualizar un contacto por ID
 *     tags: [Contacto]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del contacto
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *               apellido1:
 *                 type: string
 *               apellido2:
 *                 type: string
 *               correo:
 *                 type: string
 *               telefono:
 *                 type: string
 *               asunto:
 *                 type: string
 *               mensaje:
 *                 type: string
 *     responses:
 *       200:
 *         description: Contacto actualizado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al actualizar el contacto
 */
app.put('/contacto/contacto/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { nombre, apellido1, apellido2, correo, telefono, asunto, mensaje } = req.body;

    db.query(
        'UPDATE contacto.contacto SET nombre = ?, apellido1 = ?, apellido2 = ?, correo = ?, telefono = ?, asunto = ?, mensaje = ? WHERE `id_contacto` = ?',
        [nombre, apellido1, apellido2, correo, telefono, asunto, mensaje, id],
        (err, result) => {
            if (err) {
                console.error('Error updating contacto:', err);
                res.status(500).json({ error: 'Error updating contacto entry' });
            } else {
                res.json({ success: true });
            }
        }
    );
});

/**
 * @swagger
 * /contacto/contacto/resuelto/{id}:
 *   put:
 *     summary: Marcar un contacto como resuelto
 *     tags: [Contacto]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del contacto
 *     responses:
 *       200:
 *         description: Contacto marcado como resuelto
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al marcar como resuelto
 */
app.put('/contacto/contacto/resuelto/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('UPDATE contacto.contacto SET resuelto = 1 WHERE `id_contacto` = ?', [id], (err, result) => {
        if (err) {
            console.error('Error marking contacto as resolved:', err);
            res.status(500).json({ error: 'Error marking contacto entry as resolved' });
        } else {
            res.json({ success: true });
        }
    });
});

/**
 * @swagger
 * /contacto/contacto/{id}:
 *   delete:
 *     summary: Eliminar un contacto por ID
 *     tags: [Contacto]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del contacto
 *     responses:
 *       200:
 *         description: Contacto eliminado exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error al eliminar el contacto
 */
app.delete('/contacto/contacto/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.query('DELETE FROM contacto.contacto WHERE id_contacto = ?', [id], (err, result) => {
        if (err) {
            console.error('Error deleting contacto:', err);
            res.status(500).json({ error: 'Error deleting contacto' });
        } else {
            res.json({ success: true });
        }
    });
});







//imagenes_usuarios
/**
 * @swagger
 * /traveler/imagenes_usuarios/{id}:
 *   get:
 *     summary: Obtener la imagen de un usuario por ID
 *     tags: [Imágenes Usuarios]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID del usuario
 *     responses:
 *       200:
 *         description: Imagen del usuario obtenida exitosamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagen:
 *                   type: object
 *       404:
 *         description: Imagen no encontrada
 *       500:
 *         description: Error al obtener la imagen del usuario
 */
app.get('/traveler/imagenes_usuarios/:id', authenticateToken, (req, res) => {
    db.query('SELECT * FROM traveler.imagenes_usuarios WHERE id_usuario = ?', [req.params.id], (err, results) => {
        if (err) {
            console.error('Error fetching imagenes_usuarios:', err);
            res.status(500).json({ error: 'Error fetching imagenes_usuarios' });
        } else {
            if (results.length === 0) {
                res.status(404).json({ error: 'Imagen not found' });
            } else {
                res.json({ imagen: results[0] });
            }
        }
    });
}
);





















// Handle undefined routes
app.use((req, res, next) => {
    res.status(404).json({ error: "Route not found" });
});

// Set port and start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});