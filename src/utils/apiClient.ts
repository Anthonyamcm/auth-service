import axios from 'axios';
import Logger from './logger';

const apiClient = axios.create({
  baseURL: process.env.USER_SERVICE_URL, // Ensure this is set in .env
  timeout: 5000, // 5 seconds timeout
});

// Add a response interceptor for error handling
apiClient.interceptors.response.use(
  response => response,
  error => {
    Logger.error(
      'Error in response interceptor:',
      error.response?.data || error.message
    );
    return Promise.reject(error);
  }
);

export default apiClient;
