import React, { useState } from "react";
import API from "./utils/api"; 
import { useNavigate } from "react-router-dom"; // Hook para redireccionar

const Login = () => {
    const [email, setEmail] = useState("test@example.com");
    const [password, setPassword] = useState("password123");
    const [error, setError] = useState("");
    const navigate = useNavigate(); // Inicializa el hook

    const handleLogin = async (e) => {
        e.preventDefault();
        setError(""); // Limpia errores previos

        try {
            // Envía la petición al backend (http://localhost:5000/signin)
            const response = await API.post("/signin", { email, password });
            
            // Guarda el token JWT en el almacenamiento local
            localStorage.setItem("token", response.data.token);
            
            alert("¡Inicio de sesión exitoso!");
            
            // Redirecciona a la ruta protegida
            navigate("/protected"); 

        } catch (err) {
            // Muestra un mensaje de error si falla
            const message = err.response?.data?.message || "Error de conexión con el servidor.";
            setError(message);
        }
    };

    return (
        <div style={{ padding: '20px' }}>
            <h2>Iniciar Sesión (Cliente-FE)</h2>
            <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxWidth: '300px' }}>
                <input 
                    type="email" 
                    placeholder="Email" 
                    value={email} 
                    onChange={(e) => setEmail(e.target.value)} 
                    required
                />
                <input 
                    type="password" 
                    placeholder="Password" 
                    value={password} 
                    onChange={(e) => setPassword(e.target.value)} 
                    required
                />
                <button type="submit">Entrar</button>
            </form>
            {error && <p style={{ color: 'red' }}>{error}</p>}
            <p>Usuario de prueba: test@example.com / password123</p>
        </div>
    );
};

export default Login;