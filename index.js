// Servidor de gestión deportiva implementado por Juan Antonio
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "express-async-errors";
import rateLimit from "express-rate-limit";
import { MongoClient, ObjectId } from 'mongodb';
import swaggerUi from "swagger-ui-express";
import swaggerDocument from "./openapi.json" with { type: "json" };

const SECRET_KEY = process.env.JWT_SECRET;
const REFRESH_KEY = process.env.JWT_REFRESH_SECRET;
const app = express();

app.use(express.json());
app.use(cors());
app.set('trust proxy', 1);

const limitMsg = { mensaje: "Demasiadas peticiones desde esta IP, espere unos minutos." };
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, message: limitMsg }));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, message: limitMsg });

const cdnSwagger = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5";
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument, {
    customCssUrl: `${cdnSwagger}/swagger-ui.css`,
    customJs: [`${cdnSwagger}/swagger-ui-bundle.js`, `${cdnSwagger}/swagger-ui-standalone-preset.js`]
}));

function validarTokenJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(403).json({ message: "Se requiere un token de autenticación" });

    try {
        req.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        return res.status(403).json({ message: "Token inválido o expirado" });
    }
}

const PORT = process.env.PORT ?? 3000;
const DB_URL = process.env.MONGODB_URI ?? 'mongodb://localhost:27017';
const DB_NAME = process.env.DB_NAME ?? 'api_deportes';
const COLLECTION_USERS = 'usuarios';
const COLLECTION_SPORTS = 'deportes';
const COLLECTION_TOKENS = 'tokens_refresco';

const client = new MongoClient(DB_URL);

app.get("/", (req, res) => {
    res.redirect("/api-docs");
});

// -------------- SECCIÓN: DEPORTES (CAMBIADO DE ORDEN) ------------------

app.get('/api/deportes', async (req, res) => {
    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_SPORTS);
    const resultados = await col.find({}).toArray();
    res.status(200).json(resultados);
});

app.post('/api/deportes', validarTokenJWT, async (req, res) => {
    if (!req.is('json')) return res.status(400).json({ message: 'El formato debe ser JSON' });

    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_SPORTS);
    const { nombre, intensidad, equipoRequerido } = req.body;

    const resultado = await col.insertOne({ nombre, intensidad, intensidad: intensidad ?? 'Media', equipoRequerido: equipoRequerido ?? false });
    return res.status(201).json(resultado);
});

app.get('/api/deportes/:id', async (req, res) => {
    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_SPORTS);
    const { id } = req.params;
    const resultado = await col.find({ _id: new ObjectId(id) }).toArray();
    res.status(200).json(resultado);
});

app.put('/api/deportes/:id', validarTokenJWT, async (req, res) => {
    if (!req.is('json')) return res.status(400).json({ message: 'El formato debe ser JSON' });

    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_SPORTS);
    const { id } = req.params;
    const { nombre, intensidad, equipoRequerido } = req.body;

    const resultado = await col.updateOne({ _id: new ObjectId(id) }, { $set: { nombre, intensidad, equipoRequerido } });
    res.status(200).json(resultado);
});

app.delete('/api/deportes/:id', validarTokenJWT, async (req, res) => {
    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_SPORTS);
    const { id } = req.params;
    const resultado = await col.deleteOne({ _id: new ObjectId(id) });
    res.status(200).json(resultado);
});

// -------------- SECCIÓN: USUARIOS ------------------

app.get('/api/users', async (req, res) => {
    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_USERS);
    const resultados = await col.find({}, { projection: { password: 0 } }).toArray();
    res.status(200).json(resultados);
});

app.post('/api/users', validarTokenJWT, async (req, res) => {
    if (!req.is('json')) return res.status(400).json({ message: 'El formato debe ser JSON' });

    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_USERS);
    const { nombre, edad } = req.body;
    const resultado = await col.insertOne({ nombre, edad });
    return res.status(201).json(resultado);
});

app.get('/api/users/:id', async (req, res) => {
    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_USERS);
    const { id } = req.params;
    const resultado = await col.find({ _id: new ObjectId(id) }, { projection: { password: 0 } }).toArray();
    res.status(200).json(resultado);
});

app.put('/api/users/:id', validarTokenJWT, async (req, res) => {
    if (!req.is('json')) return res.status(400).json({ message: 'El formato debe ser JSON' });

    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_USERS);
    const { id } = req.params;
    const { nombre, edad } = req.body;
    const resultado = await col.updateOne({ _id: new ObjectId(id) }, { $set: { nombre, edad } });
    res.status(200).json(resultado);
});

app.delete('/api/users/:id', validarTokenJWT, async (req, res) => {
    const db = client.db(DB_NAME);
    const col = db.collection(COLLECTION_USERS);
    const { id } = req.params;
    const resultado = await col.deleteOne({ _id: new ObjectId(id) });
    res.status(200).json(resultado);
});

// -------------- SECCIÓN: AUTENTICACIÓN ------------------

app.post('/api/register', loginLimiter, async (req, res) => {
    if (!req.is('json')) return res.status(400).json({ message: 'El formato debe ser JSON' });

    const { nombre, edad, password } = req.body;
    if (!nombre || !password) return res.status(400).json({ message: "Nombre y contraseña obligatorios" });

    const col = client.db(DB_NAME).collection(COLLECTION_USERS);
    if (await col.findOne({ nombre })) return res.status(409).json({ message: "El usuario ya se encuentra registrado" });

    const passwordHash = await bcrypt.hash(password, 10);
    const nuevoUsuario = await col.insertOne({ nombre, edad, password: passwordHash });

    res.status(201).json({ _id: nuevoUsuario.insertedId, nombre, edad });
});

app.post('/api/login', loginLimiter, async (req, res) => {
    if (!req.is('json')) return res.status(400).json({ message: 'El formato debe ser JSON' });

    const { nombre, password } = req.body;
    const usuarioEncontrado = await client.db(DB_NAME).collection(COLLECTION_USERS).findOne({ nombre });

    if (!usuarioEncontrado) return res.status(401).json({ message: "Usuario no registrado" });

    const passwordValida = await bcrypt.compare(password ?? "", usuarioEncontrado.password ?? "");
    if (!passwordValida) return res.status(401).json({ message: "Contraseña incorrecta" });

    const payload = { id: usuarioEncontrado._id.toString(), nombre: usuarioEncontrado.nombre };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '5m' });
    const refreshToken = jwt.sign(payload, REFRESH_KEY, { expiresIn: '7d' });

    await client.db(DB_NAME).collection(COLLECTION_TOKENS).insertOne({ token: refreshToken });

    res.json({ token, refreshToken });
});

app.post('/api/refresh', loginLimiter, async (req, res) => {
    const { refreshToken } = req.body ?? {};
    if (!refreshToken) return res.status(400).json({ message: "Token de refresco requerido" });

    const col = client.db(DB_NAME).collection(COLLECTION_TOKENS);
    if (!await col.findOne({ token: refreshToken })) return res.status(403).json({ message: "Token de refresco no válido" });

    try {
        const { id, nombre } = jwt.verify(refreshToken, REFRESH_KEY);
        const token = jwt.sign({ id, nombre }, SECRET_KEY, { expiresIn: '5m' });
        res.json({ token });
    } catch (err) {
        await col.deleteOne({ token: refreshToken });
        res.status(403).json({ message: "Token de refresco caducado" });
    }
});

app.post('/api/logout', async (req, res) => {
    const { refreshToken } = req.body ?? {};
    await client.db(DB_NAME).collection(COLLECTION_TOKENS).deleteOne({ token: refreshToken });
    res.json({ message: "Sesión cerrada correctamente" });
});

// Manejador de errores global
app.use((err, req, res, next) => {
    console.error(err);
    if (err.name === 'BSONError') return res.status(400).json({ message: "ID con formato incorrecto" });
    res.status(500).json({ message: "Error interno del servidor" });
});

try {
    await client.connect();
    console.log("Conectado exitosamente a MongoDB");
} catch (err) {
    console.error("Fallo al conectar con la base de datos:", err.message);
}

app.listen(PORT, () => console.log(`API de deportes iniciada por Juan Antonio en el puerto: ${PORT}`));

export default app;