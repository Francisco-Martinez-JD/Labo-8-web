import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import bodyParser from "body-parser";
import cors from "cors";
import controllers from "./controladores/controllers.js";
import { pool } from "./data/db/connection.js";

const app = express();
const PORT = 5001;
const JWT_SECRET = "hola"; // Use a strong, secure key in production

app.use(bodyParser.json());
app.use(cors());

// Middleware: Verify Token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "Unauthorized" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Routes
app.post("/signIn", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    // Buscar usuario por email
    const result = await pool.query('SELECT email, password FROM users WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = result.rows[0];
    
    // Verificar contraseña
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Generar token
    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ 
      token,
      message: "Inicio de sesión exitoso"
    });
  } catch (error) {
    console.error("SignIn error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.get("/protected", verifyToken, (req, res) => {
  res.status(200).json({ message: "Protected data accessed", user: req.user });
});


app.get('/', controllers.displayHome);

app.get("/users", controllers.getUsers);

app.get("/users/:id", controllers.getUserById);

app.post("/users", controllers.createUser);

app.put("/users/:id", controllers.updateUser);

app.delete("/users/:id", controllers.deleteUser);

app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);