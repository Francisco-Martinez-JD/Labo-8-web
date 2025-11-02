import React, { useEffect, useState } from "react";
import API from "./utils/api";

const Protected = () => {
    const [message, setMessage] = useState("Cargando...");
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                // Petición a la ruta protegida (el token se adjunta automáticamente)
                const response = await API.get("/protected");
                setMessage(response.data.message);

            } catch (err) {
                // Si la petición falla (e.g., por token inválido o no existente)
                const errorMessage = err.response?.data?.message || "Acceso Denegado. Por favor, inicie sesión.";
                setError(errorMessage);
                setMessage("");
            }
        };
        fetchData();
    }, []);

    return (
        <div style={{ padding: '20px' }}>
            <h2>Ruta Protegida</h2>
            {error ? (
                <p style={{ color: 'red' }}>{error}</p>
            ) : (
                <p style={{ color: 'green' }}>{message}</p>
            )}
        </div>
    );
};

export default Protected;