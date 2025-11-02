import React from "react";
import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import Login from "./Login";
import Protected from "./Protected";

// Función para simular el cierre de sesión
const handleLogout = () => {
    localStorage.removeItem("token");
    alert("Sesión cerrada.");
};

const App = () => (
    <Router>
        <nav style={{ padding: '10px', borderBottom: '1px solid #ccc' }}>
            <Link to="/login" style={{ marginRight: '15px' }}>Login</Link>
            <Link to="/protected" style={{ marginRight: '15px' }}>Protegido</Link>
            <button onClick={handleLogout}>Cerrar Sesión</button>
        </nav>

        <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/protected" element={<Protected />} />
            {/* Ruta por defecto o de inicio */}
            <Route path="/" element={<h1>Bienvenido. Por favor, inicie sesión.</h1>} />
        </Routes>
    </Router>
);

export default App;