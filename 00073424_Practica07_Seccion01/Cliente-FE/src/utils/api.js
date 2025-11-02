import axios from "axios";

// 1. Crea una instancia de Axios con la URL base de tu backend
const API = axios.create({
    baseURL: "http://localhost:5000", 
    // Debe coincidir con el PORT configurado en Server-BE/app.js
});

// 2. Interceptor: Se ejecuta antes de cada solicitud
API.interceptors.request.use((req) => {
    // Obtiene el token de autenticación del almacenamiento local
    const token = localStorage.getItem("token");

    // Si el token existe, lo añade al encabezado de la solicitud (Authorization: Bearer <token>)
    if (token) {
        req.headers.Authorization = `Bearer ${token}`;
    }
    
    return req;
});

export default API;