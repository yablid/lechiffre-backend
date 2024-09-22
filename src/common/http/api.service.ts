// common/http/api.service.ts
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios, { AxiosInstance, AxiosError } from 'axios';

@Injectable()
export class ApiService {
  private apiClient: AxiosInstance;

  constructor(private configService: ConfigService) {
    const baseURL = this.configService.get<string>('LECHIFFRAI_API_URL');
    const apiKey = this.configService.get<string>('LECHIFFRAI_API_KEY');

    // Create the axios instance
    this.apiClient = axios.create({
      baseURL: baseURL,
      timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
      },
    });

    // todo: temp debug
    this.apiClient.interceptors.request.use((config) => {
        console.log('Sending request to:', config.baseURL + config.url);
        return config;
    });

    // Add request interceptor
    this.apiClient.interceptors.request.use(
      (config) => {
        // You can modify the request before sending it here
        console.log('Request Interceptor: ', config);
        return config;
      },
      (error) => {
        // Handle request error
        return Promise.reject(error);
      }
    );

    // Add response interceptor
    this.apiClient.interceptors.response.use(
      (response) => response,  // Pass successful responses through
      (error: AxiosError) => {
        // Centralized error handling
        if (error.response) {
          console.error(`AxiosError: ${error.message}`);
          console.error(`Status: ${error.response.status}`);
          console.error(`Response Data: ${error.response.data}`);
        } else if (error.request) {
          console.error('No response received:', error.request);
        } else {
          console.error('Error setting up the request:', error.message);
        }

        return Promise.reject(error);
      }
    );
  }

  // Method to get the axios instance
  getApiClient() {
    return this.apiClient;
  }
}
