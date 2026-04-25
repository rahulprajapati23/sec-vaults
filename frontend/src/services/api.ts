import axios from 'axios';

const apiBaseUrl = import.meta.env.VITE_API_URL?.trim() || '';

export const api = axios.create({
  baseURL: apiBaseUrl,
  withCredentials: true,
});

export interface ApiResponse<T = any> {
  success: boolean;
  data: T;
  error: string | null;
}

api.interceptors.response.use(
  (response) => {
    // Return only the data portion of the axios response (the StandardResponse)
    return response.data;
  },
  (error) => {
    if (error.response?.status === 401) {
      console.warn("Unauthorized session");
    }
    // Transform axios error into our standard format if possible
    return Promise.reject({
      success: false,
      data: null,
      error: error.response?.data?.error || error.message || 'Unknown error'
    });
  }
);
