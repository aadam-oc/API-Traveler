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
                    bearerFormat: "JWT"  // Esto indica que el esquema usa JWT
                }
            }
        },
        security: [{ BearerAuth: [] }]
    },

    apis: ["./traveler.js"], // Ensure this points to the correct file
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
        process.exit(1); // Exit if connection fails
    }
    console.log("Connected to the database.");
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    // Verifica si el token está en el encabezado 'Authorization'
    const token = req.headers['authorization']?.split(' ')[1];  // Extrae el token de "Bearer <token>"

    if (!token) {
        return res.status(401).json({ error: 'Access denied, token missing!' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Invalid token:', err);
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;  // Agregar el usuario al objeto de la solicitud
        next();  // Continuar con la solicitud
    });
};





//Login

/**
 * @swagger
 * /traveler/login:
 *   post:
 *     summary: Login a user and generate a JWT token
 *     description: Authenticates a user by verifying email and password, and returns a JWT token upon successful login.
 *     tags:
 *       - Auth
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               correo:
 *                 type: string
 *                 description: User's email address
 *                 example: adamortcas@gmail.com
 *               contrasena:
 *                 type: string
 *                 description: User's password
 *                 example: adamortcas
 *     responses:
 *       200:
 *         description: Successful login, returns a JWT token
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT token for authentication
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Correo o contraseña incorrectos"
 *       500:
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Error processing login"
 */
app.post('/traveler/login', (req, res) => {
    const { correo, contrasena } = req.body;

    // Validate input fields
    if (!correo || !contrasena) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    // Query the database for the user
    db.query('SELECT * FROM traveler.usuarios WHERE correo = ?', [correo], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ error: 'Error processing login' });
        }

        if (results.length === 0) {
            // User not found
            return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
        }

        const user = results[0];

        // Compare the provided password with the stored hashed password
        bcrypt.compare(contrasena, user.contrasena, (err, isMatch) => {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).json({ error: 'Error processing login' });
            }

            if (!isMatch) {
                // Passwords do not match
                return res.status(401).json({ error: 'Correo o contraseña incorrectos' });
            }

            // Generate JWT token
            const token = jwt.sign(
                { id: user.id_usuario, correo: user.correo },
                JWT_SECRET,
                { expiresIn: '1h' }
            );

            // Return the token
            res.status(200).json({ token });
        });
    });
});




//Register

/**
 * @swagger
 * /traveler/register:
 *   post:
 *     summary: Register a new user and generate a JWT token
 *     description: Register a new user with their email and password, and generate a JWT token for authentication.
 *     tags:
 *       - Auth
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               correo:
 *                 type: string
 *                 description: User's email address
 *                 example: user@example.com
 *               contrasena:
 *                 type: string
 *                 description: User's password
 *                 example: password123
 *     responses:
 *       201:
 *         description: User registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Usuario registrado con éxito"
 *                 token:
 *                   type: string
 *                   description: JWT token for authentication
 *                   example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
 *       400:
 *         description: Missing required fields or email already registered
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Correo y contraseña son obligatorios"
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: "Error registering user"
 */
app.post('/traveler/register', async (req, res) => {
    const { correo, contrasena } = req.body;

    // Validate required fields
    if (!correo || !contrasena) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios' });
    }

    // Check if the email is already registered
    db.query('SELECT * FROM traveler.usuarios WHERE correo = ?', [correo], (err, results) => {
        if (err) {
            console.error('Error checking user email:', err);
            return res.status(500).json({ error: 'Error checking email' });
        }

        if (results.length > 0) {
            return res.status(400).json({ error: 'El correo ya está registrado' });
        }

        // Hash the password
        bcrypt.hash(contrasena, 10, (err, hashedPassword) => {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).json({ error: 'Error hashing password' });
            }

            // Insert user into the database
            const query = 'INSERT INTO traveler.usuarios (correo, contrasena) VALUES (?, ?)';
            db.query(query, [correo, hashedPassword], (err, result) => {
                if (err) {
                    console.error('Error inserting user:', err);
                    return res.status(500).json({ error: 'Error registering user' });
                }

                // Generate JWT token
                const token = jwt.sign(
                    { id: result.insertId, correo },
                    JWT_SECRET,
                    { expiresIn: '1h' }
                );

                // Respond with success message and token
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
 *     description: Recupera una lista de todos los usuarios registrados en la base de datos. Requiere autenticación JWT.
 *     tags:
 *       - Usuarios
 *     responses:
 *       200:
 *         description: Lista de usuarios obtenida con éxito
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
 *                         example: 1
 *                       nombre:
 *                         type: string
 *                         example: "Juan Pérez"
 *                       email:
 *                         type: string
 *                         example: "juan.perez@example.com"
 *                       rol:
 *                         type: string
 *                         example: "Administrador"
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.get('/traveler/usuarios', /*authenticateToken,*/(req, res) => {
    db.query('SELECT * FROM traveler.usuarios', (err, results) => {
        if (err) {
            console.error('Error fetching users:', err);
            return res.status(500).json({ error: 'Error fetching users' });
        }
        res.status(200).json({ usuarios: results });
    });
});



//crear usuario completo con rol y caracteristicas
app.post('/traveler/usuarios_full', (req, res) => {
    const { correo, contrasena, id_rol, nombre, apellido1, apellido2, telefono1, telefono2 } = req.body;

    // Validate required fields
    if (!correo || !contrasena || !id_rol || !nombre || !apellido1 || !apellido2 || !telefono1) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    db.query('INSERT INTO traveler.usuarios (correo, contrasena, id_rol) VALUES (?, ?, ?)', [correo, contrasena, id_rol], (err, result) => {
        if (err) {
            console.error('Error creating user:', err);
            return res.status(500).json({ error: 'Error creating user' });
        }

        const id_usuario = result.insertId; // Get the ID of the newly created user

        db.query('INSERT INTO traveler.caracteristicas_usuarios (id_usuario, nombre, apellido1, apellido2, telefono1, telefono2) VALUES (?, ?, ?, ?, ?, ?)', [id_usuario, nombre, apellido1, apellido2, telefono1, telefono2], (err) => {
            if (err) {
                console.error('Error creating user characteristics:', err);
                return res.status(500).json({ error: 'Error creating user characteristics' });
            }
            res.status(201).json({ id: id_usuario });
        });
    });
});


app.put('/traveler/usuarios_full/:id', (req, res) => {
    const { id } = req.params;
    const { correo, contrasena, id_rol, nombre, apellido1, apellido2, telefono1, telefono2 } = req.body;
    db.query(` SELECT * FROM traveler.usuarios WHERE id_usuario = ?`, [id], (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ error: 'Error fetching user' });
        }
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        db.query(`UPDATE traveler.usuarios SET correo = ?, contrasena = ?, id_rol = ? WHERE id_usuario = ?`, [correo, contrasena, id_rol, id], (err) => {
            if (err) {
                console.error('Error updating user:', err);
                return res.status(500).json({ error: 'Error updating user' });
            }

            db.query(`UPDATE traveler.caracteristicas_usuarios SET nombre = ?, apellido1 = ?, apellido2 = ?, telefono1 = ?, telefono2 = ? WHERE id_usuario = ?`, [nombre, apellido1, apellido2, telefono1, telefono2, id], (err) => {
                if (err) {
                    console.error('Error updating user characteristics:', err);
                    return res.status(500).json({ error: 'Error updating user characteristics' });
                }
                res.status(200).json({ success: true });
            });
        });
    });
});



app.get('/traveler/usuarios_full/:id', (req, res) => {
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
 *     summary: Get all users with their roles and characteristics
 *     description: Retrieves all users along with their roles and characteristics using a join query.
 *     tags: [Usuarios]
 *     responses:
 *       200:
 *         description: Successfully fetched users with roles and characteristics
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
 *                         description: User ID
 *                       correo:
 *                         type: string
 *                         description: User email
 *                       contrasena:
 *                         type: string
 *                         description: User password (hashed)
 *                       id_rol:
 *                         type: integer
 *                         description: Role ID
 *                       nombre_rol:
 *                         type: string
 *                         description: Role name
 *                       nombre:
 *                         type: string
 *                         description: User's first name
 *                       apellido1:
 *                         type: string
 *                         description: User's first surname
 *                       apellido2:
 *                         type: string
 *                         description: User's second surname
 *                       telefono1:
 *                         type: string
 *                         description: User's primary phone number
 *                       telefono2:
 *                         type: string
 *                         description: User's secondary phone number
 *       500:
 *         description: Error fetching users with roles and characteristics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 */
app.get('/traveler/usuarios_full', (req, res) => {
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
 *     summary: Get user by ID
 *     description: Fetches a user by their ID from the database. Requires authentication using a valid JWT token.
 *     tags:
 *       - Usuarios
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the user to fetch.
 *         schema:
 *           type: integer
 *           example: 1
 *     responses:
 *       200:
 *         description: Successfully fetched the user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 usuario:
 *                   type: object
 *                   properties:
 *                     id_usuario:
 *                       type: integer
 *                       description: User ID.
 *                       example: 1
 *                     correo:
 *                       type: string
 *                       description: User email.
 *                       example: user@example.com
 *                     id_rol:
 *                       type: integer
 *                       description: Role ID of the user.
 *                       example: 2
 *       404:
 *         description: User not found.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: User not found.
 *       401:
 *         description: Unauthorized - Invalid or missing token.
 *       500:
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error fetching user.
 */
app.get('/traveler/usuarios/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new user
 *     description: Adds a new user to the database. Requires authentication.
 *     tags:
 *       - Usuarios
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               correo:
 *                 type: string
 *                 description: Email of the user.
 *                 example: user@example.com
 *               contrasena:
 *                 type: string
 *                 description: Password of the user.
 *                 example: password123
 *               id_rol:
 *                 type: integer
 *                 description: Role ID of the user.
 *                 example: 2
 *     responses:
 *       201:
 *         description: User created successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the created user.
 *                   example: 1
 *       400:
 *         description: Bad Request - Missing or invalid data.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Invalid input data.
 *       500:
 *         description: Error creating user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   example: Error creating user.
 */
app.post('/traveler/usuarios', /*authenticateToken,*/(req, res) => {
    const { correo, contrasena, id_rol } = req.body;

    // Validate required fields
    if (!correo || !contrasena || !id_rol) {
        return res.status(400).json({ error: 'Invalid input data' });
    }

    db.query('INSERT INTO traveler.usuarios (correo, contrasena, id_rol) VALUES (?, ?, ?)', [correo, contrasena, id_rol], (err, result) => {
        if (err) {
            console.error('Error creating user:', err);
            return res.status(500).json({ error: 'Error creating user' });
        }
        res.status(201).json({ id: result.insertId });
    });
});

/**
 * @swagger
 * /traveler/usuarios/{id}:
 *   put:
 *     summary: Actualizar usuario por ID
 *     description: Permite actualizar los datos de un usuario (correo, contraseña o rol) mediante su ID. Requiere autenticación JWT.
 *     tags:
 *       - Usuarios
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               correo:
 *                 type: string
 *                 example: updated@example.com
 *               contrasena:
 *                 type: string
 *                 example: newpassword123
 *               id_rol:
 *                 type: integer
 *                 example: 2
 *     responses:
 *       200:
 *         description: Usuario actualizado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *       400:
 *         description: Solicitud inválida
 *       401:
 *         description: No autorizado, token inválido
 *       404:
 *         description: Usuario no encontrado
 *       500:
 *         description: Error interno del servidor
 */
app.put('/traveler/usuarios/:id', /*authenticateToken,*/(req, res) => {
    const id = req.params.id;
    const { correo, contrasena, id_rol } = req.body;

    // Validar entrada
    if (!correo && !contrasena && id_rol === undefined) {
        return res.status(400).json({ error: 'Correo, contraseña o id_rol son requeridos' });
    }

    const updates = [];
    const params = [];

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
            finalizeUpdate();
        });
    } else {
        finalizeUpdate();
    }

    function finalizeUpdate() {
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
    }
});

/**
 * @swagger
 * /traveler/usuarios/{id}:
 *   delete:
 *     summary: Eliminar usuario por ID
 *     description: Elimina un usuario de la base de datos utilizando su ID. Requiere autenticación JWT.
 *     tags:
 *       - Usuarios
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     responses:
 *       200:
 *         description: Usuario eliminado correctamente
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *       404:
 *         description: Usuario no encontrado
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.delete('/traveler/usuarios/:id', /*authenticateToken,*/(req, res) => {
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



// Roles

/**
 * @swagger
 * /traveler/roles:
 *   get:
 *     summary: Obtener todos los roles
 *     description: Recupera una lista de todos los roles disponibles en la base de datos. Requiere autenticación JWT.
 *     tags:
 *       - Roles
 *     responses:
 *       200:
 *         description: Lista de roles obtenida con éxito
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
 *                         example: 1
 *                       nombre:
 *                         type: string
 *                         example: "Administrador"
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.get('/traveler/roles', /*authenticateToken,*/(req, res) => {
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
 *     summary: Obtener rol por ID
 *     description: Recupera un rol por su ID. Requiere autenticación JWT.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     tags:
 *       - Roles
 *     responses:
 *       200:
 *         description: Rol obtenido con éxito
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
 *                       example: 1
 *                     nombre:
 *                       type: string
 *                       example: "Administrador"
 *       404:
 *         description: Rol no encontrado
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.get('/traveler/roles/:id', /*authenticateToken,*/(req, res) => {
    const id = req.params.id;
    console.log("Fetching role with ID:", id); // Log the ID to check if it's correct

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
 *     description: Crea un nuevo rol en la base de datos. Requiere autenticación JWT.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_rol:
 *                 type: string
 *                 example: "Administrador"
 *     tags:
 *       - Roles
 *     responses:
 *       200:
 *         description: Rol creado con éxito
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Role created successfully"
 *                 id:
 *                   type: integer
 *                   example: 1
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.post('/traveler/roles', /*authenticateToken,*/(req, res) => {
    const { nombre_rol } = req.body;
    console.log("Received role name:", nombre_rol);  // Log the received role name

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
 *     description: Actualiza el nombre de un rol por su ID. Requiere autenticación JWT.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_rol:
 *                 type: string
 *                 example: "Administrador"
 *     tags:
 *       - Roles
 *     responses:
 *       200:
 *         description: Rol actualizado con éxito
 *       400:
 *         description: Solicitud incorrecta
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.put('/traveler/roles/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Eliminar rol por ID
 *     description: Elimina un rol de la base de datos por su ID. Requiere autenticación JWT.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     tags:
 *       - Roles
 *     responses:
 *       200:
 *         description: Rol eliminado con éxito
 *       404:
 *         description: Rol no encontrado
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.delete('/traveler/roles/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Obtener todas las características de los usuarios
 *     description: Recupera una lista de todas las características de los usuarios disponibles en la base de datos. Requiere autenticación JWT.
 *     tags:
 *       - Caracteristicas Usuarios
 *     responses:
 *       200:
 *         description: Lista de características de usuarios obtenida con éxito
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
 *                         example: 1
 *                       nombre:
 *                         type: string
 *                         example: "Juan"
 *                       apellido1:
 *                         type: string
 *                         example: "Pérez"
 *                       apellido2:
 *                         type: string
 *                         example: "Gómez"
 *                       telefono1:
 *                         type: string
 *                         example: "+123456789"
 *                       telefono2:
 *                         type: string
 *                         example: "+987654321"
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.get('/traveler/caracteristicas_usuarios', /*authenticateToken,*/(req, res) => {
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
 *     summary: Obtener características de usuario por ID
 *     description: Recupera las características de un usuario por su ID. Requiere autenticación JWT.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     tags:
 *       - Caracteristicas Usuarios
 *     responses:
 *       200:
 *         description: Características de usuario obtenidas con éxito
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
 *                       example: 1
 *                     nombre:
 *                       type: string
 *                       example: "Juan"
 *                     apellido1:
 *                       type: string
 *                       example: "Pérez"
 *                     apellido2:
 *                       type: string
 *                       example: "Gómez"
 *                     telefono1:
 *                       type: string
 *                       example: "+123456789"
 *                     telefono2:
 *                       type: string
 *                       example: "+987654321"
 *       404:
 *         description: Característica de usuario no encontrada
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.get('/traveler/caracteristicas_usuarios/:id', /*authenticateToken,*/(req, res) => {
    const id_usuario = req.params.id;
    console.log("Fetching caracteristicas_usuarios with ID:", id_usuario); // Log the ID to check if it's correct

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
 *     description: Crea una nueva característica de usuario en la base de datos. Requiere autenticación JWT.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *                 example: 1
 *               nombre:
 *                 type: string
 *                 example: "Juan"
 *               apellido1:
 *                 type: string
 *                 example: "Pérez"
 *               apellido2:
 *                 type: string
 *                 example: "Gómez"
 *               telefono1:
 *                 type: string
 *                 example: "+123456789"
 *               telefono2:
 *                 type: string
 *                 example: "+987654321"
 *     tags:
 *       - Caracteristicas Usuarios
 *     responses:
 *       200:
 *         description: Característica de usuario creada con éxito
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Característica de usuario creada correctamente"
 *                 id:
 *                   type: integer
 *                   example: 1
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.post('/traveler/caracteristicas_usuarios', /*authenticateToken,*/(req, res) => {
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
 *     summary: Actualizar características de usuario por ID
 *     description: Actualiza las características de un usuario por su ID. Requiere autenticación JWT.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre:
 *                 type: string
 *                 example: "Juan"
 *               apellido1:
 *                 type: string
 *                 example: "Pérez"
 *               apellido2:
 *                 type: string
 *                 example: "Gómez"
 *               telefono1:
 *                 type: string
 *                 example: "+123456789"
 *               telefono2:
 *                 type: string
 *                 example: "+987654321"
 *     tags:
 *       - Caracteristicas Usuarios
 *     responses:
 *       200:
 *         description: Característica de usuario actualizada con éxito
 *       400:
 *         description: Solicitud incorrecta
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.put('/traveler/caracteristicas_usuarios/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Eliminar características de usuario por ID
 *     description: Elimina las características de un usuario por su ID. Requiere autenticación JWT.
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *           example: 1
 *     tags:
 *       - Caracteristicas Usuarios
 *     responses:
 *       200:
 *         description: Característica de usuario eliminada con éxito
 *       404:
 *         description: Característica de usuario no encontrada
 *       401:
 *         description: No autorizado, token inválido
 *       500:
 *         description: Error interno del servidor
 */
app.delete('/traveler/caracteristicas_usuarios/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get all destinos
 *     description: Fetches all the destinos from the database.
 *     tags: [Destinos]
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: A list of all destinos
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
 *         description: Error fetching destinos
 *       401:
 *         description: Unauthorized access
 */
//app.get('/traveler/destinos', /*authenticateToken,*/ (req, res) => {
//    db.query('SELECT * FROM traveler.destinos', (err, results) => {
//        if (err) {
//            console.error('Error fetching destinos:', err);
//           res.status(500).json({ error: 'Error fetching destinos' });
//       } else {
//            res.json({ destinos: results });
//        }
//    });
//}); 

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
 *     summary: Get a destino by ID
 *     description: Fetch a specific destino from the database using its ID.
 *     tags: [Destinos]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the destino to fetch.
 *         schema:
 *           type: integer
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: A specific destino
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
 *         description: Destino not found
 *       500:
 *         description: Error fetching destino
 *       401:
 *         description: Unauthorized access
 */
app.get('/traveler/destinos/:id', (req, res) => {
    const id = req.params.id;
    console.log("Fetching destino with ID:", id); // Log the ID to check if it's correct

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
 *     summary: Create a new destino
 *     description: Adds a new destino (country and city) to the database.
 *     tags: [Destinos]
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               pais:
 *                 type: string
 *                 example: "Spain"
 *               ciudad:
 *                 type: string
 *                 example: "Barcelona"
 *     responses:
 *       200:
 *         description: The newly created destino ID
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error creating destino
 *       401:
 *         description: Unauthorized access
 */
app.post('/traveler/destinos', (req, res) => {
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
 *     summary: Update a destino by ID
 *     description: Updates the details of a specific destino identified by its ID.
 *     tags: [Destinos]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the destino to update
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               pais:
 *                 type: string
 *                 example: "France"
 *               ciudad:
 *                 type: string
 *                 example: "Paris"
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Successful update
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error updating destino
 *       401:
 *         description: Unauthorized access
 */
app.put('/traveler/destinos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete a destino by ID
 *     description: Deletes a specific destino identified by its ID from the database.
 *     tags: [Destinos]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the destino to delete
 *         schema:
 *           type: integer
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Successful deletion
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *       500:
 *         description: Error deleting destino
 *       401:
 *         description: Unauthorized access
 */
app.delete('/traveler/destinos/:id', /*authenticateToken,*/(req, res) => {
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
 * tags:
 *   - Tipo Actividad
 * /traveler/tipo_actividad:
 *   get:
 *     summary: Retrieve all tipo_actividad records
 *     description: Fetches a list of all tipo_actividad from the database.
 *     tags: [Tipo Actividad]
 *     responses:
 *       200:
 *         description: List of tipo_actividad records
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
 *                         description: The ID of the tipo_actividad
 *                       nombre_tipo_actividad:
 *                         type: string
 *                         description: The name of the tipo_actividad
 *       500:
 *         description: Error fetching tipo_actividad
 */
app.get('/traveler/tipo_actividad', /*authenticateToken,*/(req, res) => {
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
 * tags:
 *   - Tipo Actividad
 * /traveler/tipo_actividad/{id}:
 *   get:
 *     summary: Retrieve tipo_actividad by ID
 *     description: Fetches a tipo_actividad record by its ID.
 *     tags: [Tipo Actividad]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the tipo_actividad
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: tipo_actividad record
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
 *                       description: The ID of the tipo_actividad
 *                     nombre_tipo_actividad:
 *                       type: string
 *                       description: The name of the tipo_actividad
 *       404:
 *         description: tipo_actividad not found
 *       500:
 *         description: Error fetching tipo_actividad
 */
app.get('/traveler/tipo_actividad/:id', /*authenticateToken,*/(req, res) => {
    const id = req.params.id;
    console.log("Fetching tipo_actividad with ID:", id);

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
 * tags:
 *   - Tipo Actividad
 * /traveler/tipo_actividad:
 *   post:
 *     summary: Create a new tipo_actividad
 *     description: Creates a new tipo_actividad record in the database.
 *     tags: [Tipo Actividad]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_tipo_actividad:
 *                 type: string
 *                 description: The name of the tipo_actividad
 *     responses:
 *       200:
 *         description: tipo_actividad created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the newly created tipo_actividad
 *       500:
 *         description: Error creating tipo_actividad
 */
app.post('/traveler/tipo_actividad', /*authenticateToken,*/(req, res) => {
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
 * tags:
 *   - Tipo Actividad
 * /traveler/tipo_actividad/{id}:
 *   put:
 *     summary: Update tipo_actividad by ID
 *     description: Updates an existing tipo_actividad record by its ID.
 *     tags: [Tipo Actividad]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the tipo_actividad
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre_tipo_actividad:
 *                 type: string
 *                 description: The name of the tipo_actividad
 *     responses:
 *       200:
 *         description: tipo_actividad updated successfully
 *       500:
 *         description: Error updating tipo_actividad
 */
app.put('/traveler/tipo_actividad/:id', /*authenticateToken,*/(req, res) => {
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
 * tags:
 *   - Tipo Actividad
 * /traveler/tipo_actividad/{id}:
 *   delete:
 *     summary: Delete tipo_actividad by ID
 *     description: Deletes a tipo_actividad record by its ID.
 *     tags: [Tipo Actividad]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID of the tipo_actividad to delete
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: tipo_actividad deleted successfully
 *       500:
 *         description: Error deleting tipo_actividad
 */
app.delete('/traveler/tipo_actividad/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get all actividades
 *     description: Retrieve a list of all activities from the database.
 *     tags: [Actividades]
 *     responses:
 *       200:
 *         description: A list of actividades
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
 */
app.get('/traveler/actividades', /*authenticateToken,*/(req, res) => {
    db.query('SELECT * FROM traveler.actividades', (err, results) => {
        if (err) {
            console.error('Error fetching actividades:', err);
            res.status(500).json({ error: 'Error fetching actividades' });
        } else {
            res.json({ actividades: results });
        }
    });
});

//actividades completo
/**
 * @swagger
 * /actividades_completo:
 *   get:
 *     summary: Get all actividades with their type
 *     description: Retrieves all activities with their corresponding type.
 *     tags: [Actividades]
 *     responses:
 *       200:
 *         description: List of activities with their type
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
 *                         description: The ID of the activity.
 *                       nombre:
 *                         type: string
 *                         description: The name of the activity.
 *                       descripcion:
 *                         type: string
 *                         description: The description of the activity.
 *                       precio:
 *                         type: number
 *                         description: The price of the activity.
 *                       id_tipo_actividad:
 *                         type: integer
 *                         description: The ID of the activity type.
 *                       tipo_actividad:
 *                         type: string
 *                         description: The name of the activity type.
 *       500:
 *         description: Error fetching actividades
 */
app.get('/traveler/actividades_completo', (req, res) => {
    // Ensure the query retrieves all activities even if there are no matching images
    db.query(`
        SELECT 
            actividades.*, 
            tipo_actividad.nombre_tipo_actividad, 
            destinos.pais, 
            destinos.ciudad, 
            imagenes_actividades.nombre_imagen_actividad
        FROM actividades
        JOIN tipo_actividad ON actividades.id_tipo_actividad = tipo_actividad.id_tipo_actividad
        JOIN destinos ON actividades.id_destino = destinos.id_destino
        LEFT JOIN imagenes_actividades ON actividades.id_actividad = imagenes_actividades.id_actividad
    `, (err, results) => {
        if (err) {
            console.error('Error fetching actividades:', err);
            res.status(500).json({ error: 'Error fetching actividades' });
        } else {
            res.json({ actividades: results });
        }
    });
});

//actividades completo

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


//puto de actividades completo

app.put('/traveler/actividades_completo/:id', (req, res) => {
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
 * /traveler/actividades/{id}:
 *   get:
 *     summary: Get actividad by ID
 *     description: Retrieve an activity by its ID.
 *     tags: [Actividades]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the actividad
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: A single actividad
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
 *       404:
 *         description: Actividad not found
 */
app.get('/traveler/actividades/:id', /*authenticateToken,*/(req, res) => {
    const id = req.params.id;
    console.log("Fetching actividad with ID:", id); // Log the ID to check if it's correct

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
 * /traveler/actividades:
 *   post:
 *     summary: Create a new actividad
 *     description: Add a new actividad to the database.
 *     tags: [Actividades]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_actividad:
 *                 type: integer
 *               id_destino:
 *                 type: integer
 *               id_tipo_actividad:
 *                 type: integer
 *               disponibilidad_actividad:
 *                 type: boolean
 *               precio:
 *                 type: number
 *     responses:
 *       201:
 *         description: Successfully created actividad
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 */
app.post('/traveler/actividades', /*authenticateToken,*/(req, res) => {
    const { id_destino, id_tipo_actividad, disponibilidad_actividad, precio, descripcion } = req.body;
    const disponibilidad = Boolean(disponibilidad_actividad);

    db.query('INSERT INTO traveler.actividades ( id_destino, id_tipo_actividad, disponibilidad_actividad, precio, descripcion) VALUES ( ?, ?, ?, ?, ?)', [id_destino, id_tipo_actividad, disponibilidad, precio, descripcion], (err, result) => {
        if (err) {
            console.error('Error creating actividad:', err);
            res.status(500).json({ error: 'Error creating actividad' });
        } else {
            res.json({ id: result.insertId });
        }
    }
    );

});



/**
 * @swagger
 * /traveler/actividades/{id}:
 *   put:
 *     summary: Update actividad by ID
 *     description: Update an existing actividad by its ID.
 *     tags: [Actividades]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the actividad
 *         required: true
 *         schema:
 *           type: integer
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
 *     responses:
 *       200:
 *         description: Successfully updated actividad
 *       404:
 *         description: Actividad not found
 */
app.put('/traveler/actividades/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete actividad by ID
 *     description: Delete an actividad by its ID.
 *     tags: [Actividades]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the actividad
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully deleted actividad
 *       404:
 *         description: Actividad not found
 */
app.delete('/traveler/actividades/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get all alojamientos
 *     description: Retrieve a list of all alojamientos from the database.
 *     tags: [Alojamientos]
 *     responses:
 *       200:
 *         description: A list of alojamientos
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
 *                       id_destino:
 *                         type: integer
 *                       precio_dia:
 *                         type: number
 *                       descripcion:
 *                         type: string
 *                       id_usuario:
 *                         type: integer
 *                       max_personas:
 *                         type: integer
 */
app.get('/traveler/alojamientos', /*authenticateToken,*/(req, res) => {
    db.query('SELECT * FROM traveler.alojamientos', (err, results) => {
        if (err) {
            console.error('Error fetching alojamientos:', err);
            res.status(500).json({ error: 'Error fetching alojamientos' });
        } else {
            res.json({ alojamientos: results });
        }
    });
});


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
 * /traveler/alojamientos/{id}:
 *   get:
 *     summary: Get alojamiento by ID
 *     description: Retrieve an alojamiento by its ID.
 *     tags: [Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the alojamiento
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: A single alojamiento
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
 *                     id_destino:
 *                       type: integer
 *                     precio_dia:
 *                       type: number
 *                     descripcion:
 *                       type: string
 *                     id_usuario:
 *                       type: integer
 *                     max_personas:
 *                       type: integer
 *       404:
 *         description: Alojamiento not found
 */
app.get('/traveler/alojamientos/:id', /*authenticateToken,*/(req, res) => {
    const id = req.params.id;
    console.log("Fetching alojamiento with ID:", id); // Log the ID to check if it's correct

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
 *     summary: Create a new alojamiento
 *     description: Add a new alojamiento to the database.
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
 *               descripcion:
 *                 type: string
 *               id_usuario:
 *                 type: integer
 *               max_personas:
 *                 type: integer
 *     responses:
 *       201:
 *         description: Successfully created alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 */
app.post('/traveler/alojamientos', /*authenticateToken,*/(req, res) => {
    const { nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion } = req.body;
    db.query('INSERT INTO traveler.alojamientos (nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion) VALUES (?, ?, ?, ?, ?, ?, ?)', [nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, direccion], (err, result) => {
        if (err) {
            console.error('Error creating alojamiento:', err);
            res.status(500).json({ error: 'Error creating alojamiento' });
        } else {
            res.json({ id: result.insertId });
        }
    });
});

/**
 * @swagger
 * /traveler/alojamientos/{id}:
 *   put:
 *     summary: Update alojamiento by ID
 *     description: Update an existing alojamiento by its ID.
 *     tags: [Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the alojamiento
 *         required: true
 *         schema:
 *           type: integer
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
 *               descripcion:
 *                 type: string
 *               id_usuario:
 *                 type: integer
 *               max_personas:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Successfully updated alojamiento
 *       404:
 *         description: Alojamiento not found
 */
app.put('/traveler/alojamientos/:id', /*authenticateToken,*/(req, res) => {
    const id = req.params.id;
    const { nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas } = req.body;
    db.query('UPDATE traveler.alojamientos SET nombre_alojamiento = ?, id_destino = ?, precio_dia = ?, descripcion = ?, id_usuario = ?, max_personas = ? WHERE id_alojamiento = ?', [nombre_alojamiento, id_destino, precio_dia, descripcion, id_usuario, max_personas, id], (err, result) => {
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
 *     summary: Delete alojamiento by ID
 *     description: Delete an alojamiento by its ID.
 *     tags: [Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the alojamiento
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully deleted alojamiento
 *       404:
 *         description: Alojamiento not found
 */
app.delete('/traveler/alojamientos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get all valoraciones_alojamientos
 *     description: Retrieves all valoraciones_alojamientos from the database.
 *     tags: [Valoraciones Alojamientos]
 *     responses:
 *       200:
 *         description: Successfully fetched all valoraciones_alojamientos
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
 *                         description: The ID of the valoracion.
 *                       id_alojamiento:
 *                         type: integer
 *                         description: The ID of the alojamiento being rated.
 *                       id_usuario:
 *                         type: integer
 *                         description: The ID of the user who made the rating.
 *                       valoracion:
 *                         type: integer
 *                         description: The rating value (e.g., 1-5).
 *                       comentario:
 *                         type: string
 *                         description: The comment left by the user.
 *       500:
 *         description: Error fetching valoraciones_alojamientos
 */
app.get('/traveler/valoraciones_alojamientos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get valoraciones_alojamientos by ID
 *     description: Retrieves a single valoracion_alojamiento by its ID.
 *     tags: [Valoraciones Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the valoracion_alojamiento to retrieve
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully fetched valoracion_alojamiento
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
 *                       description: The ID of the valoracion.
 *                     id_alojamiento:
 *                       type: integer
 *                       description: The ID of the alojamiento being rated.
 *                     id_usuario:
 *                       type: integer
 *                       description: The ID of the user who made the rating.
 *                     valoracion:
 *                       type: integer
 *                       description: The rating value (e.g., 1-5).
 *                     comentario:
 *                       type: string
 *                       description: The comment left by the user.
 *       404:
 *         description: Valoracion_alojamiento not found
 *       500:
 *         description: Error fetching valoraciones_alojamientos
 */
app.get('/traveler/valoraciones_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new valoracion_alojamiento
 *     description: Create a new valoracion_alojamiento to rate an accommodation.
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
 *                 description: The ID of the alojamiento being rated.
 *               valoracion:
 *                 type: integer
 *                 description: The rating value (e.g., 1-5).
 *               comentario:
 *                 type: string
 *                 description: The comment left by the user.
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user who made the rating.
 *     responses:
 *       200:
 *         description: Successfully created valoracion_alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the newly created valoracion_alojamiento.
 *       500:
 *         description: Error creating valoracion_alojamiento
 */
app.post('/traveler/valoraciones_alojamientos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Update valoracion_alojamiento by ID
 *     description: Update a valoracion_alojamiento by its ID.
 *     tags: [Valoraciones Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the valoracion_alojamiento to update
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *                 description: The ID of the alojamiento being rated.
 *               valoracion:
 *                 type: integer
 *                 description: The rating value (e.g., 1-5).
 *               comentario:
 *                 type: string
 *                 description: The comment left by the user.
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user who made the rating.
 *     responses:
 *       200:
 *         description: Successfully updated valoracion_alojamiento
 *       404:
 *         description: Valoracion_alojamiento not found
 *       500:
 *         description: Error updating valoracion_alojamiento
 */
app.put('/traveler/valoraciones_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete valoracion_alojamiento by ID
 *     description: Delete a valoracion_alojamiento by its ID.
 *     tags: [Valoraciones Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the valoracion_alojamiento to delete
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully deleted valoracion_alojamiento
 *       404:
 *         description: Valoracion_alojamiento not found
 *       500:
 *         description: Error deleting valoracion_alojamiento
 */
app.delete('/traveler/valoraciones_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get all imagenes_alojamientos
 *     description: Retrieve a list of all imagenes_alojamientos.
 *     tags: [Imagenes Alojamientos]
 *     responses:
 *       200:
 *         description: Successfully fetched imagenes_alojamientos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagenes_alojamientos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_imagen:
 *                         type: integer
 *                       id_alojamiento:
 *                         type: integer
 *                       url_imagen:
 *                         type: string
 *       500:
 *         description: Error fetching imagenes_alojamientos
 */
app.get('/traveler/imagenes_alojamientos', /*authenticateToken,*/(req, res) => {
    db.query('SELECT * FROM traveler.imagenes_alojamientos', (err, results) => {
        if (err) {
            console.log('Todavia no tiene imagenes');
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
 *     summary: Get imagenes_alojamientos by ID
 *     description: Retrieve a specific imagen_alojamiento by its ID.
 *     tags: [Imagenes Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         description: The ID of the imagen_alojamiento
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully fetched imagen_alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 imagen_alojamiento:
 *                   type: object
 *                   properties:
 *                     id_imagen:
 *                       type: integer
 *                     id_alojamiento:
 *                       type: integer
 *                     url_imagen:
 *                       type: string
 *       404:
 *         description: Imagen_alojamiento not found
 *       500:
 *         description: Error fetching imagen_alojamiento
 */
app.get('/traveler/imagenes_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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

app.get('/traveler/imagenes_alojamientos/alojamiento/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new imagen_alojamiento
 *     description: Add a new imagen_alojamiento to the database.
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
 *         description: Successfully created imagen_alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *       500:
 *         description: Error creating imagen_alojamiento
 */
app.post('/traveler/imagenes_alojamientos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Update an existing imagen_alojamiento by ID
 *     description: Update the details of an existing imagen_alojamiento.
 *     tags: [Imagenes Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the imagen_alojamiento to update.
 *         schema:
 *           type: integer
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
 *         description: Successfully updated imagen_alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *       500:
 *         description: Error updating imagen_alojamiento
 */
app.put('/traveler/imagenes_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete an imagen_alojamiento by ID
 *     description: Deletes a specific imagen_alojamiento based on the provided ID.
 *     tags: [Imagenes Alojamientos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the imagen_alojamiento to delete.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully deleted imagen_alojamiento
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   example: true
 *       500:
 *         description: Error deleting imagen_alojamiento
 */
app.delete('/traveler/imagenes_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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




// Post Blog
/**
 * @swagger
 * /traveler/post_blog:
 *   get:
 *     summary: Get all post_blog
 *     description: Retrieves a list of all `post_blog` entries.
 *     tags: [Post Blog]
 *     responses:
 *       200:
 *         description: A list of all post_blog entries
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
 *                       id_post_blog:
 *                         type: integer
 *                         description: The unique identifier of the post.
 *                       title:
 *                         type: string
 *                         description: The title of the post.
 *                       content:
 *                         type: string
 *                         description: The content of the post.
 *                       created_at:
 *                         type: string
 *                         format: date-time
 *                         description: The date and time when the post was created.
 *       500:
 *         description: Error fetching post_blog
 */
app.get('/traveler/post_blog', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get post_blog by ID
 *     description: Retrieves a specific `post_blog` entry by its ID.
 *     tags: [Post Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the `post_blog` entry to retrieve.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: The `post_blog` entry with the specified ID
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 post_blog:
 *                   type: object
 *                   properties:
 *                     id_post_blog:
 *                       type: integer
 *                       description: The unique identifier of the post.
 *                     title:
 *                       type: string
 *                       description: The title of the post.
 *                     content:
 *                       type: string
 *                       description: The content of the post.
 *                     created_at:
 *                       type: string
 *                       format: date-time
 *                       description: The date and time when the post was created.
 *       404:
 *         description: Post_blog not found
 *       500:
 *         description: Error fetching post_blog
 */
app.get('/traveler/post_blog/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new post_blog entry
 *     description: Creates a new `post_blog` entry with the provided information.
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
 *                 description: The ID of the user creating the post.
 *               titulo:
 *                 type: string
 *                 description: The title of the post.
 *               contenido:
 *                 type: string
 *                 description: The content of the post.
 *     responses:
 *       200:
 *         description: The ID of the created post_blog entry
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the newly created post_blog entry.
 *       500:
 *         description: Error creating post_blog
 */
app.post('/traveler/post_blog', /*authenticateToken,*/(req, res) => {
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
 *     summary: Update an existing post_blog entry by ID
 *     description: Updates an existing `post_blog` entry with the provided ID and new information.
 *     tags: [Post Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the post_blog entry to update.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user updating the post.
 *               titulo:
 *                 type: string
 *                 description: The title of the post.
 *               contenido:
 *                 type: string
 *                 description: The updated content of the post.
 *     responses:
 *       200:
 *         description: The post_blog entry was updated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates whether the update was successful.
 *       500:
 *         description: Error updating post_blog
 */
app.put('/traveler/post_blog/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete a post_blog entry by ID
 *     description: Deletes the `post_blog` entry with the provided ID.
 *     tags: [Post Blog]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the post_blog entry to delete.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: The post_blog entry was deleted successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates whether the deletion was successful.
 *       500:
 *         description: Error deleting post_blog
 */
app.delete('/traveler/post_blog/:id', /*authenticateToken,*/(req, res) => {
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

/**
 * @swagger
 * /traveler/reservas_actividades:
 *   get:
 *     summary: Get all reservas_actividades entries
 *     description: Retrieves all the `reservas_actividades` entries.
 *     tags: [Reservas Actividades]
 *     responses:
 *       200:
 *         description: List of reservas_actividades entries.
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
 *                       id_reserva:
 *                         type: integer
 *                         description: The ID of the reservation.
 *                       id_actividad:
 *                         type: integer
 *                         description: The ID of the activity.
 *                       id_usuario:
 *                         type: integer
 *                         description: The ID of the user who made the reservation.
 *                       fecha_reserva:
 *                         type: string
 *                         format: date-time
 *                         description: The date and time when the reservation was made.
 *                       estado_reserva:
 *                         type: string
 *                         description: The status of the reservation.
 *       500:
 *         description: Error fetching reservas_actividades
 */
app.get('/traveler/reservas_actividades', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get a reservas_actividad by ID
 *     description: Retrieves a specific `reserva_actividad` entry by its ID.
 *     tags: [Reservas Actividades]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the reserva_actividad.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: The requested reserva_actividad entry.
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
 *                       description: The ID of the reserva_actividad.
 *                     id_actividad:
 *                       type: integer
 *                       description: The ID of the activity.
 *                     id_usuario:
 *                       type: integer
 *                       description: The ID of the user who made the reservation.
 *                     fecha_reserva:
 *                       type: string
 *                       format: date-time
 *                       description: The date and time when the reservation was made.
 *                     estado_reserva:
 *                       type: string
 *                       description: The status of the reservation.
 *       404:
 *         description: Reserva_actividad not found
 *       500:
 *         description: Error fetching reserva_actividad
 */
app.get('/traveler/reservas_actividades/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new reserva_actividad
 *     description: Creates a new reservation for an activity.
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
 *                 description: The ID of the activity being reserved.
 *               fecha_reserva_actividad:
 *                 type: string
 *                 format: date-time
 *                 description: The date and time when the reservation is made.
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user making the reservation.
 *     responses:
 *       200:
 *         description: The ID of the created reserva_actividad.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the created reserva_actividad.
 *       500:
 *         description: Error creating reserva_actividad
 */
app.post('/traveler/reservas_actividades', /*authenticateToken,*/(req, res) => {
    const { id_actividad, fecha_reserva_actividad, id_usuario } = req.body;
    db.query('INSERT INTO traveler.reservas_actividades (id_actividad, fecha_reserva_actividad, id_usuario) VALUES (?, ?, ?)', [id_actividad, fecha_reserva_actividad, id_usuario], (err, result) => {
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
 *     summary: Update an existing reserva_actividad by ID
 *     description: Updates the details of an existing reserva_actividad.
 *     tags: [Reservas Actividades]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the reserva_actividad to be updated.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_actividad:
 *                 type: integer
 *                 description: The updated ID of the activity being reserved.
 *               fecha_reserva_actividad:
 *                 type: string
 *                 format: date-time
 *                 description: The updated date and time when the reservation is made.
 *               id_usuario:
 *                 type: integer
 *                 description: The updated ID of the user making the reservation.
 *     responses:
 *       200:
 *         description: Successful update of the reserva_actividad.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Whether the update was successful.
 *       500:
 *         description: Error updating reserva_actividad
 *       404:
 *         description: reserva_actividad not found
 */
app.put('/traveler/reservas_actividades/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete a reserva_actividad by ID
 *     description: Deletes a specific reserva_actividad by its ID.
 *     tags: [Reservas Actividades]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the reserva_actividad to be deleted.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successful deletion of the reserva_actividad.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Whether the deletion was successful.
 *       500:
 *         description: Error deleting reserva_actividad
 *       404:
 *         description: reserva_actividad not found
 */
app.delete('/traveler/reservas_actividades/:id', /*authenticateToken,*/(req, res) => {
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

/**
 * @swagger
 * /traveler/reservas_alojamientos:
 *   get:
 *     summary: Get all reservas_alojamientos
 *     description: Retrieves all the reservas_alojamientos (accommodation bookings) from the database.
 *     tags: [Reservas Alojamientos]
 *     responses:
 *       200:
 *         description: A list of reservas_alojamientos
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 reservas_alojamientos:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_reserva_alojamiento:
 *                         type: integer
 *                         description: The ID of the reserva_alojamiento.
 *                       id_alojamiento:
 *                         type: integer
 *                         description: The ID of the accommodation.
 *                       id_usuario:
 *                         type: integer
 *                         description: The ID of the user who made the reservation.
 *                       fecha_reserva_inicio_alojamiento:
 *                         type: string
 *                         format: date
 *                         description: The start date of the reservation.
 *                       fecha_reserva_final_alojamiento:
 *                         type: string
 *                         format: date
 *                         description: The end date of the reservation.
 *       500:
 *         description: Error fetching reservas_alojamientos
 */
app.get('/traveler/reservas_alojamientos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get a reserva_alojamiento by ID
 *     description: Retrieves a specific reserva_alojamiento (accommodation booking) by its ID from the database.
 *     tags: [Reservas Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the reserva_alojamiento to retrieve.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: The requested reserva_alojamiento details
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
 *                       description: The ID of the reserva_alojamiento.
 *                     id_alojamiento:
 *                       type: integer
 *                       description: The ID of the accommodation.
 *                     id_usuario:
 *                       type: integer
 *                       description: The ID of the user who made the reservation.
 *                     fecha_reserva_inicio_alojamiento:
 *                       type: string
 *                       format: date
 *                       description: The start date of the reservation.
 *                     fecha_reserva_final_alojamiento:
 *                       type: string
 *                       format: date
 *                       description: The end date of the reservation.
 *       404:
 *         description: Reserva_alojamiento not found
 *       500:
 *         description: Error fetching reservas_alojamientos
 */
app.get('/traveler/reservas_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new reserva_alojamiento (accommodation booking)
 *     description: Creates a new reserva_alojamiento (accommodation booking) with provided details in the database.
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
 *                 description: The ID of the accommodation being booked.
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user making the reservation.
 *               fecha_reserva_inicio_alojamiento:
 *                 type: string
 *                 format: date
 *                 description: The start date of the accommodation reservation.
 *               fecha_reserva_final_alojamiento:
 *                 type: string
 *                 format: date
 *                 description: The end date of the accommodation reservation.
 *     responses:
 *       200:
 *         description: Reservation successfully created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the newly created reserva_alojamiento.
 *       500:
 *         description: Error creating reserva_alojamiento
 */
app.post('/traveler/reservas_alojamientos', /*authenticateToken,*/(req, res) => {
    const { id_alojamiento, id_usuario, fecha_reserva_inicio_alojamiento, fecha_reserva_final_alojamiento } = req.body;
    db.query('INSERT INTO traveler.reservas_alojamientos (id_alojamiento, id_usuario, fecha_reserva_inicio_alojamiento, fecha_reserva_final_alojamiento) VALUES (?, ?, ?, ?)',
        [id_alojamiento, id_usuario, fecha_reserva_inicio_alojamiento, fecha_reserva_final_alojamiento], (err, result) => {
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
 *     summary: Update an existing reserva_alojamiento (accommodation booking) by ID
 *     description: Updates the details of an existing reserva_alojamiento (accommodation booking) in the database.
 *     tags: [Reservas Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the reserva_alojamiento to be updated.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_alojamiento:
 *                 type: integer
 *                 description: The ID of the accommodation being booked.
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user making the reservation.
 *               fecha_reserva_inicio_alojamiento:
 *                 type: string
 *                 format: date
 *                 description: The start date of the accommodation reservation.
 *               fecha_reserva_final_alojamiento:
 *                 type: string
 *                 format: date
 *                 description: The end date of the accommodation reservation.
 *     responses:
 *       200:
 *         description: Reservation successfully updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates whether the update was successful.
 *       500:
 *         description: Error updating reserva_alojamiento
 *       404:
 *         description: reserva_alojamiento not found
 */
app.put('/traveler/reservas_alojamientos/:id', /*authenticateToken,*/(req, res) => {
    const id = req.params.id;
    const { id_alojamiento, id_usuario, fecha_reserva_inicio_alojamiento, fecha_reserva_final_alojamiento } = req.body;
    db.query('UPDATE traveler.reservas_alojamientos SET id_alojamiento = ?, id_usuario = ?, fecha_reserva_inicio_alojamiento = ?, fecha_reserva_final_alojamiento = ? WHERE id_reserva_alojamiento = ?',
        [id_alojamiento, id_usuario, fecha_reserva_inicio_alojamiento, fecha_reserva_final_alojamiento, id], (err, result) => {
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
 *     summary: Delete a reserva_alojamiento (accommodation booking) by ID
 *     description: Deletes a reserva_alojamiento (accommodation booking) from the database based on the given ID.
 *     tags: [Reservas Alojamientos]
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         description: The ID of the reserva_alojamiento to be deleted.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Reservation successfully deleted
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates whether the deletion was successful.
 *       500:
 *         description: Error deleting reserva_alojamiento
 *       404:
 *         description: reserva_alojamiento not found
 */
app.delete('/traveler/reservas_alojamientos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get all reservas_vehiculos (vehicle reservations)
 *     description: Retrieves all reservas_vehiculos (vehicle reservations) from the database.
 *     tags: [Reservas Vehiculos]
 *     responses:
 *       200:
 *         description: Successfully retrieved all reservas_vehiculos
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
 *                         description: The ID of the vehicle reservation.
 *                       id_vehiculo:
 *                         type: integer
 *                         description: The ID of the vehicle being reserved.
 *                       id_usuario:
 *                         type: integer
 *                         description: The ID of the user making the reservation.
 *                       fecha_reserva_inicio_vehiculo:
 *                         type: string
 *                         format: date
 *                         description: The start date of the vehicle reservation.
 *                       fecha_reserva_final_vehiculo:
 *                         type: string
 *                         format: date
 *                         description: The end date of the vehicle reservation.
 *       500:
 *         description: Error fetching reservas_vehiculos
 */
app.get('/traveler/reservas_vehiculos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get a reservas_vehiculos (vehicle reservation) by ID
 *     description: Retrieves a specific reservas_vehiculos (vehicle reservation) from the database using the provided reservation ID.
 *     tags: [Reservas Vehiculos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the vehicle reservation.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully retrieved the reservas_vehiculos
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
 *                       description: The ID of the vehicle reservation.
 *                     id_vehiculo:
 *                       type: integer
 *                       description: The ID of the vehicle being reserved.
 *                     id_usuario:
 *                       type: integer
 *                       description: The ID of the user making the reservation.
 *                     fecha_reserva_inicio_vehiculo:
 *                       type: string
 *                       format: date
 *                       description: The start date of the vehicle reservation.
 *                     fecha_reserva_final_vehiculo:
 *                       type: string
 *                       format: date
 *                       description: The end date of the vehicle reservation.
 *       404:
 *         description: Reserva_vehiculo not found
 *       500:
 *         description: Error fetching reservas_vehiculos
 */
app.get('/traveler/reservas_vehiculos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new reservas_vehiculos (vehicle reservation)
 *     description: Creates a new vehicle reservation for a user with the provided reservation details.
 *     tags: [Reservas Vehiculos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user making the reservation.
 *               fecha_reserva_vehiculo:
 *                 type: string
 *                 format: date
 *                 description: The date of the vehicle reservation.
 *             required:
 *               - id_usuario
 *               - fecha_reserva_vehiculo
 *     responses:
 *       200:
 *         description: Successfully created the reserva_vehiculo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the created vehicle reservation.
 *       500:
 *         description: Error creating reserva_vehiculo
 */
app.post('/traveler/reservas_vehiculos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Update an existing reservas_vehiculos (vehicle reservation) by ID
 *     description: Updates the vehicle reservation details for a specific reservation ID.
 *     tags: [Reservas Vehiculos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the vehicle reservation to update.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user making the reservation.
 *               fecha_reserva_vehiculo:
 *                 type: string
 *                 format: date
 *                 description: The updated date of the vehicle reservation.
 *             required:
 *               - id_usuario
 *               - fecha_reserva_vehiculo
 *     responses:
 *       200:
 *         description: Successfully updated the reserva_vehiculo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates that the reservation was successfully updated.
 *       404:
 *         description: Reserva_vehiculo not found
 *       500:
 *         description: Error updating reserva_vehiculo
 */
app.put('/traveler/reservas_vehiculos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete a reservas_vehiculos (vehicle reservation) by ID
 *     description: Deletes the specified vehicle reservation by its ID.
 *     tags: [Reservas Vehiculos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the vehicle reservation to delete.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successfully deleted the reserva_vehiculo
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates that the reservation was successfully deleted.
 *       404:
 *         description: Reserva_vehiculo not found
 *       500:
 *         description: Error deleting reserva_vehiculo
 */
app.delete('/traveler/reservas_vehiculos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get all reservas_vuelos (flight reservations)
 *     description: Retrieves a list of all flight reservations.
 *     tags: [Reservas Vuelos]
 *     responses:
 *       200:
 *         description: A list of flight reservations
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
 *                         description: The ID of the flight reservation.
 *                       id_vuelo:
 *                         type: integer
 *                         description: The ID of the flight.
 *                       id_usuario:
 *                         type: integer
 *                         description: The ID of the user making the reservation.
 *                       fecha_reserva_vuelo:
 *                         type: string
 *                         format: date-time
 *                         description: The date and time of the flight reservation.
 *       500:
 *         description: Error fetching reservas_vuelos
 */
app.get('/traveler/reservas_vuelos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Get a reserva_vuelo (flight reservation) by ID
 *     description: Retrieves a specific flight reservation based on its ID.
 *     tags: [Reservas Vuelos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the flight reservation.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: A specific flight reservation
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
 *                       description: The ID of the flight reservation.
 *                     id_vuelo:
 *                       type: integer
 *                       description: The ID of the flight.
 *                     id_usuario:
 *                       type: integer
 *                       description: The ID of the user making the reservation.
 *                     fecha_reserva_vuelo:
 *                       type: string
 *                       format: date-time
 *                       description: The date and time of the flight reservation.
 *       404:
 *         description: Reserva_vuelo not found
 *       500:
 *         description: Error fetching reserva_vuelo
 */
app.get('/traveler/reservas_vuelos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Create a new reserva_vuelo (flight reservation)
 *     description: Creates a new flight reservation with the provided details.
 *     tags: [Reservas Vuelos]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - id_usuario
 *               - id_vuelo
 *               - fecha_reserva_vuelo
 *             properties:
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user making the reservation.
 *               id_vuelo:
 *                 type: integer
 *                 description: The ID of the flight being reserved.
 *               fecha_reserva_vuelo:
 *                 type: string
 *                 format: date-time
 *                 description: The date and time of the flight reservation.
 *     responses:
 *       200:
 *         description: The created flight reservation ID
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the newly created flight reservation.
 *       500:
 *         description: Error creating reserva_vuelo
 */
app.post('/traveler/reservas_vuelos', /*authenticateToken,*/(req, res) => {
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
 *     summary: Update a reserva_vuelo (flight reservation) by ID
 *     description: Updates the details of a flight reservation by its ID.
 *     tags: [Reservas Vuelos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the flight reservation to update.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - id_usuario
 *               - id_vuelo
 *               - fecha_reserva_vuelo
 *             properties:
 *               id_usuario:
 *                 type: integer
 *                 description: The ID of the user making the reservation.
 *               id_vuelo:
 *                 type: integer
 *                 description: The ID of the flight being reserved.
 *               fecha_reserva_vuelo:
 *                 type: string
 *                 format: date-time
 *                 description: The date and time of the flight reservation.
 *     responses:
 *       200:
 *         description: Successful update of reserva_vuelo
 *       500:
 *         description: Error updating reserva_vuelo
 */
app.put('/traveler/reservas_vuelos/:id', /*authenticateToken,*/(req, res) => {
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
 *     summary: Delete a reserva_vuelo (flight reservation) by ID
 *     description: Deletes the flight reservation identified by the given ID.
 *     tags: [Reservas Vuelos]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the flight reservation to delete.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Successful deletion of reserva_vuelo
 *       500:
 *         description: Error deleting reserva_vuelo
 */
app.delete('/traveler/reservas_vuelos/:id', /*authenticateToken,*/(req, res) => {
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



// Reservas contacto.contacto
/**
 * @swagger
 * /contacto/contacto:
 *   get:
 *     summary: Get all contacto entries
 *     description: Retrieves all the contacto entries from the database.
 *     tags: [Contacto]
 *     responses:
 *       200:
 *         description: List of contacto entries.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 contacto:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id_contacto:
 *                         type: integer
 *                         description: The ID of the contacto entry.
 *                       nombre:
 *                         type: string
 *                         description: The name of the contact.
 *                       email:
 *                         type: string
 *                         description: The email of the contact.
 *                       mensaje:
 *                         type: string
 *                         description: The message from the contact.
 *       500:
 *         description: Error fetching contacto
 */
app.get('/contacto/contacto', /*authenticateToken,*/(req, res) => {
    db.query('SELECT * FROM contacto.contacto', (err, results) => {
        if (err) {
            console.error('Error fetching contacto:', err);
            res.status(500).json({ error: 'Error fetching contacto' });
        } else {
            res.json({ contacto: results });
        }
    });
});

//get contacto by id
/**
 * @swagger
 * /contacto/contacto/{id}:
 *   get:
 *     summary: Get a contacto entry by ID
 *     description: Retrieves a specific contacto entry by its ID.
 *     tags: [Contacto]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the contacto entry.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: The requested contacto entry
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 contacto:
 *                   type: object
 *                   properties:
 *                     id_contacto:
 *                       type: integer
 *                       description: The ID of the contacto entry.
 *                     nombre:
 *                       type: string
 *                       description: The name of the contact.
 *                     email:
 *                       type: string
 *                       description: The email of the contact.
 *                     mensaje:
 *                       type: string
 *                       description: The message from the contact.
 *       404:
 *         description: Contacto entry not found
 *       500:
 *         description: Error fetching contacto
 */
app.get('/contacto/contacto/:id', /*authenticateToken,*/(req, res) => {
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

//create contacto
/**
 * @swagger
 * /contacto/contacto:
 *   post:
 *     summary: Create a new contacto entry
 *     description: Creates a new contacto entry with the provided details.
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
 *               - apellido2
 *               - correo
 *               - telefono
 *               - asunto
 *               - mensaje
 *             properties:
 *               nombre:
 *                 type: string
 *                 description: The name of the contact.
 *               apellido1:
 *                 type: string
 *                 description: The first surname of the contact.
 *               apellido2:
 *                 type: string
 *                 description: The second surname of the contact.
 *               correo:
 *                 type: string
 *                 description: The email of the contact.
 *               telefono:
 *                 type: string
 *                 description: The phone number of the contact.
 *               asunto:
 *                 type: string
 *                 description: The subject of the contact.
 *               mensaje:
 *                 type: string
 *                 description: The message from the contact.
 *     responses:
 *       200:
 *         description: Contacto entry successfully created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: The ID of the newly created contacto entry.
 *       500:
 *         description: Error creating contacto
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

//update contacto
/**
 * @swagger
 * /contacto/contacto/{id}:
 *   put:
 *     summary: Update a contacto entry by ID
 *     description: Updates a specific contacto entry by its ID.
 *     tags: [Contacto]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the contacto entry to update.
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - nombre
 *               - email
 *               - mensaje
 *             properties:
 *               nombre:
 *                 type: string
 *                 description: The name of the contact.
 *               email:
 *                 type: string
 *                 description: The email of the contact.
 *               mensaje:
 *                 type: string
 *                 description: The message from the contact.
 *     responses:
 *       200:
 *         description: Contacto entry successfully updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                   description: Indicates whether the update was successful.
 *       500:
 *         description: Error updating contacto entry
 *       404:
 *         description: Contacto entry not found
 */
app.put('/contacto/contacto/:id', /*authenticateToken,*/(req, res) => {
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


//set resuelto
/**
 * @swagger
 * /contacto/contacto/resuelto/{id}:
 *   put:
 *     summary: Set contacto entry as resolved by ID
 *     description: Marks a specific contacto entry as resolved by its ID.
 *     tags: [Contacto]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the contacto entry to mark as resolved.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Contacto entry successfully marked as resolved
 *       500:
 *         description: Error marking contacto entry as resolved
 */
app.put('/contacto/contacto/resuelto/:id', /*authenticateToken,*/(req, res) => {
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


//delete contacto
/**
 * @swagger
 * /contacto/contacto/{id}:
 *   delete:
 *     summary: Delete a contacto entry by ID
 *     description: Deletes a specific contacto entry by its ID.
 *     tags: [Contacto]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: The ID of the contacto entry to delete.
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Contacto entry successfully deleted
 *       500:
 *         description: Error deleting contacto entry
 */
app.delete('/contacto/contacto/:id', /*authenticateToken,*/(req, res) => {
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





















// Handle undefined routes
app.use((req, res, next) => {
    res.status(404).json({ error: "Route not found" });
});

// Set port and start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
