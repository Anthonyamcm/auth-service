import axios from 'axios';
import Logger from './logger';

/**
 * Axios instance configured for API requests to the User-Service.
 */
const apiClient = axios.create({
  baseURL: process.env.USER_SERVICE_URL || 'http://localhost:4000/api',
  timeout: 5000, // Adjust the timeout as needed
});

// Optional: Add request/response interceptors for logging or error handling
apiClient.interceptors.request.use(
  config => {
    Logger.info(
      `Sending ${config.method?.toUpperCase()} request to ${config.url}`
    );
    return config;
  },
  error => {
    Logger.error('Error in request interceptor', { error });
    return Promise.reject(error);
  }
);

apiClient.interceptors.response.use(
  response => {
    Logger.info(
      `Received response with status ${response.status} from ${response.config.url}`
    );
    return response;
  },
  error => {
    Logger.error('Error in response interceptor', { error });
    return Promise.reject(error);
  }
);

export default apiClient;
