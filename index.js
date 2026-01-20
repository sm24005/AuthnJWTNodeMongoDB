const express = require('express');
const mongoose = require('mongoose') ;
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken') ;

const app = express();
const port = 3000;
const hostname = '127.0.0.1';

mongoose.connect('mongodb://127.0.0.1:27017/practicaauthnjwt');

const db = mongoose.connection;
db.on( "error", (error) => console.log(error));
db.once( "open", () => console.log("Connected to Database"));

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: String,
});

const User = mongoose.model('User', userSchema);
app.use(express.json());

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Contraseña incorrecta' });
        }

        const token = jwt.sign({ userId: user._id }, 'secret_key');
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: 'El usuario ya existe' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Usuario registrado exitosamente' });
    } catch (error) {
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: 'Acceso denegado, no se proporcionó un token' });
    }

    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Token inválido' });
        }
        req.userId = decoded.userId;
        next();
    });
};

app.get('/protected', verifyToken, (req, res) => {
    res.json({ message: 'Acceso concedido a la ruta protegida'});
});

app.listen(port, () => {
    console.log(`Servidor corriendo en http://${hostname}:${port}/`);
});