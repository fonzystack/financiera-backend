// 1. REQUERIMIENTOS E INICIALIZACIÓN
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Carga las variables de entorno

const app = express();
const port = 4000; // Usaremos un puerto diferente (4000) para no chocar con el otro backend

// 2. MIDDLEWARE
app.use(cors());
app.use(express.json());
// --- MIDDLEWARE DE AUTENTICACIÓN ---
// Este "guardia" se ejecutará antes de cualquier ruta que queramos proteger.
const authMiddleware = (req, res, next) => {
    // Buscamos el token en la cabecera 'Authorization'
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

    if (token == null) return res.sendStatus(401); // 401 Unauthorized: No hay token

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403); // 403 Forbidden: El token no es válido
        req.user = user; // Guardamos la info del usuario en la petición
        next(); // ¡El guardia da paso! La petición puede continuar a la ruta.
    });
};

// --- RUTA PROTEGIDA PARA OBTENER TODOS LOS PROSPECTOS ---
// Nota cómo pasamos 'authMiddleware' antes de la lógica de la ruta.
app.get('/api/prospectos', authMiddleware, async (req, res) => {
    try {
        const prospectos = await Prospecto.find().sort({ createdAt: -1 });
        res.json(prospectos);
    } catch (error) {
        res.status(500).json({ message: 'Error al obtener los prospectos.' });
    }
});

// 3. CONEXIÓN A MONGODB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Base de datos conectada exitosamente.'))
    .catch(err => console.error('Error al conectar a la base de datos:', err));

// 4. MODELO DE DATOS PARA EL USUARIO (ASESOR)
// Este es el "plano" que le dice a Mongoose cómo deben ser los documentos de nuestros usuarios.
const UserSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true, // El email es obligatorio
        unique: true,   // No puede haber dos usuarios con el mismo email
        trim: true      // Elimina espacios en blanco al principio y al final
    },
    password: {
        type: String,
        required: true // La contraseña es obligatoria
    },
    role: {
        type: String,
        enum: ['asesor', 'admin'], // El rol solo puede ser uno de estos dos valores
        default: 'asesor'         // Por defecto, cualquier nuevo usuario es un 'asesor'
    }
    
}, {
    timestamps: true // Añade automáticamente los campos 'createdAt' y 'updatedAt'
});

const User = mongoose.model('User', UserSchema);

// 5. RUTAS (POR AHORA, UNA DE PRUEBA)
app.get('/', (req, res) => {
    res.send('API de la Financiera funcionando.');
});
// ...Debajo de tu Modelo 'User'...

// NUEVO MODELO PARA CLIENTES POTENCIALES
const ProspectoSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String },
    // --- NUEVOS CAMPOS ---
    status: {
        type: String,
        required: true,
        enum: ['Nuevo', 'Contactado', 'Interesado', 'No Interesado'], // Solo permite estos valores
        default: 'Nuevo' // Valor por defecto para nuevos prospectos
    },
    notes: {
        type: String,
        default: '' // Por defecto, las notas están vacías
    }
}, { timestamps: true });

const Prospecto = mongoose.model('Prospecto', ProspectoSchema);

// ...Debajo de tus rutas de login/register...

// RUTA PÚBLICA PARA CREAR UN NUEVO PROSPECTO
app.post('/api/prospectos', async (req, res) => {
    try {
        const nuevoProspecto = new Prospecto(req.body);
        await nuevoProspecto.save();
        res.status(201).json({ message: 'Datos recibidos. Un asesor se pondrá en contacto pronto.' });
    } catch (error) {
        res.status(500).json({ message: 'Error al guardar los datos del prospecto.' });
    }
});

// 6. INICIAR SERVIDOR
app.listen(port, () => {
    console.log(`Servidor corriendo en el puerto ${port}`);
});
// ... todo tu código anterior ...

// --- RUTA PARA REGISTRAR UN NUEVO USUARIO (ASESOR) ---
// server.js
app.post('/api/register', authMiddleware, async (req, res) => {
    try {
        // 1. Verificamos el rol del usuario que hace la petición
        const adminUser = await User.findById(req.user.id);
        if (!adminUser || adminUser.role !== 'admin') {
            return res.status(403).json({ message: 'Acción no autorizada. Se requiere rol de administrador.' });
        }

        // 2. Si es admin, procedemos a registrar al nuevo usuario
        const { email, password, role } = req.body; // El admin puede especificar el rol del nuevo usuario

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'El correo electrónico ya está en uso.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword, role });
        await newUser.save();

        res.status(201).json({ message: `Usuario ${newUser.email} registrado exitosamente como ${newUser.role}.` });

    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor.', error: error.message });
    }
});


// 6. INICIAR SERVIDOR 
app.listen(port, () => {
    // ...
});
// ... tu código anterior y la ruta /api/register ...

// --- RUTA PARA LOGIN DE USUARIO ---
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Buscar al usuario por su email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        // 2. Comparar la contraseña enviada con la hasheada en la BD
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Credenciales inválidas.' });
        }

        // 3. Si todo es correcto, crear el token (JWT)
        const payload = {
            user: {
                id: user.id // Guardamos el ID del usuario en el token
            }
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET, // Usamos la clave secreta del .env
            { expiresIn: '1h' }, // El token expira en 1 hora
            (err, token) => {
                if (err) throw err;
                // Enviamos el token y un objeto de usuario con la info esencial
                res.json({ 
                    token, 
                    user: { 
                        id: user.id, 
                        email: user.email, 
                        role: user.role 
                    } 
                });
            }
        );

    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor.', error: error.message });
    }
});
// --- RUTA PROTEGIDA PARA ACTUALIZAR UN PROSPECTO ---
// Usamos :id como un parámetro dinámico en la URL para saber qué prospecto actualizar
app.put('/api/prospectos/:id', authMiddleware, async (req, res) => {
    try {
        // Los nuevos datos (status, notes) vienen en el cuerpo de la petición
        const { status, notes } = req.body;

        // Buscamos el prospecto por su ID y lo actualizamos con los nuevos datos.
        // El { new: true } asegura que la respuesta devuelva el documento ya actualizado.
        const prospectoActualizado = await Prospecto.findByIdAndUpdate(
            req.params.id, 
            { status, notes },
            { new: true }
        );

        if (!prospectoActualizado) {
            return res.status(404).json({ message: 'Prospecto no encontrado.' });
        }

        res.json(prospectoActualizado); // Enviamos el prospecto actualizado como confirmación

    } catch (error) {
        res.status(500).json({ message: 'Error al actualizar el prospecto.' });
    }
});
// app.listen ...