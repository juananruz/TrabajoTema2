import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";
import swaggerUi from "swagger-ui-express";
import fs from "fs";

const swaggerDocument = JSON.parse(fs.readFileSync(new URL("./openapi.json", import.meta.url)));

const SECRET_KEY = process.env.JWT_SECRET || "secreto";
const REFRESH_SECRET_KEY = process.env.JWT_REFRESH_SECRET || "refresh_secreto";
const app = express();

app.use(express.json());
app.use(cors());
app.use(
    "/api-docs",
    swaggerUi.serve,
    swaggerUi.setup(swaggerDocument)
);

const MONGO_URI = process.env.MONGODB_URI;

mongoose.connect(MONGO_URI)
    .then(() => console.log("Conectado a MongoDB Atlas"))
    .catch(err => console.error("Error al conectar a MongoDB:", err));

const userSchema = new mongoose.Schema({
    nombre: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const User = mongoose.model("User", userSchema);

const deporteSchema = new mongoose.Schema({
    id: { type: Number, required: true, unique: true },
    nombre: { type: String, required: true },
    caloriasHora: { type: Number, required: true }
});
const Deporte = mongoose.model("Deporte", deporteSchema);

function verifyToken(request, response, next) {
    const token = request.headers.authorization?.split(" ")[1];

    if (!token) return response.status(403).json({ message: "Token requerido" });

    try {
        request.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        return response.status(403).json({ message: "Token inválido" });
    }
}

app.get("/", (request, response) => response.redirect("/api-docs"));

app.post('/api/register', async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' });

    const { nombre, password } = request.body;
    try {
        const existingUser = await User.findOne({ nombre });
        if (existingUser) {
            return response.json({ message: "El usuario ya existe" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await User.create({ nombre, password: hashedPassword });
        response.json({ message: "Usuario registrado con éxito", id: newUser._id });
    } catch (error) {
        response.status(500).json({ message: "Error en el servidor", error: error.message });
    }
});

app.post('/api/login', async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' });

    const { nombre, password } = request.body;
    try {
        const user = await User.findOne({ nombre });

        if (!user) {
            return response.json({ message: "Usuario no encontrado" });
        }

        const correctPassword = await bcrypt.compare(password, user.password);

        if (!correctPassword) {
            return response.json({ message: "Contraseña incorrecta" });
        }

        const accessToken = jwt.sign(
            { id: user._id, nombre: user.nombre },
            SECRET_KEY,
            { expiresIn: '5m' }
        );

        const refreshToken = jwt.sign(
            { id: user._id, nombre: user.nombre },
            REFRESH_SECRET_KEY,
            { expiresIn: '7d' }
        );

        response.json({ accessToken, refreshToken });
    } catch (error) {
        response.status(500).json({ message: "Error en el servidor", error: error.message });
    }
});

app.post('/api/refresh', (request, response) => {
    const { refreshToken } = request.body;
    if (!refreshToken) return response.status(403).json({ message: "Refresh Token requerido" });

    try {
        const user = jwt.verify(refreshToken, REFRESH_SECRET_KEY);
        const accessToken = jwt.sign(
            { id: user.id, nombre: user.nombre },
            SECRET_KEY,
            { expiresIn: '5m' }
        );
        response.json({ accessToken });
    } catch (err) {
        return response.status(403).json({ message: "Refresh Token inválido o expirado" });
    }
});

app.post('/api/logout', (request, response) => {
    response.json({ message: "Sesión cerrada correctamente" });
});

app.get('/api/deportes', async (request, response) => {
    try {
        const deportes = await Deporte.find({}, { _id: 0, __v: 0 });
        response.json(deportes);
    } catch (error) {
        response.status(500).json({ message: "Error al obtener los deportes" });
    }
});

app.get('/api/deportes/:id', async (request, response) => {
    try {
        const dep = await Deporte.findOne({ id: request.params.id }, { _id: 0, __v: 0 });

        if (dep) {
            return response.json(dep);
        } else {
            response.json({ message: 'El elemento no ha sido encontrado' });
        }
    } catch (error) {
        response.status(500).json({ message: "Error en la búsqueda" });
    }
});

app.post('/api/deportes', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' });

    try {
        const lastDep = await Deporte.findOne().sort({ id: -1 });
        let sig = lastDep ? lastDep.id + 1 : 0;

        const { nombre, caloriasHora } = request.body;
        await Deporte.create({ id: sig, nombre, caloriasHora });

        const deportes = await Deporte.find({}, { _id: 0, __v: 0 });
        return response.json(deportes);
    } catch (error) {
        response.status(500).json({ message: "Error al crear el deporte", error: error.message });
    }
});

app.put('/api/deportes/:id', verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' });

    const { id } = request.params;
    const { nombre, caloriasHora } = request.body;

    try {
        const updated = await Deporte.findOneAndUpdate(
            { id: Number(id) },
            { nombre, caloriasHora },
            { new: true }
        );

        if (updated) {
            const deportes = await Deporte.find({}, { _id: 0, __v: 0 });
            return response.json(deportes);
        } else {
            response.json({ message: 'El elemento no ha sido encontrado' });
        }
    } catch (error) {
        response.status(500).json({ message: "Error al actualizar" });
    }
});

app.delete('/api/deportes/:id', verifyToken, async (request, response) => {
    try {
        const deleted = await Deporte.findOneAndDelete({ id: Number(request.params.id) });

        if (deleted) {
            const deportes = await Deporte.find({}, { _id: 0, __v: 0 });
            return response.json(deportes);
        } else {
            response.json({ message: 'El elemento no ha sido encontrado' });
        }
    } catch (error) {
        response.status(500).json({ message: "Error al eliminar" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));

export default app;