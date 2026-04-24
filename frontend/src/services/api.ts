import axios from 'axios';

// Empty baseURL = requests go through Vite proxy on same origin
// This is critical for cookies to be sent with cross-origin API calls
export const api = axios.create({
  baseURL: '',
  withCredentials: true,
});

// Setup response interceptors for global error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      console.warn("Unauthorized: User needs to login");
      // Handle redirect to login page logic here later
    }
    return Promise.reject(error);
  }
);
