import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  config => config,
  error => Promise.reject(error)
);

// Response interceptor
api.interceptors.response.use(
  response => response,
  error => {
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

// Scan API endpoints
export const scanApi = {
  startScan: (target, scanTypes, discover = false, ports = null) =>
    api.post('/api/v1/scan', {
      target,
      scan_types: scanTypes,
      discover,
      ports,
      depth: 'standard',
    }),

  getScanStatus: (scanId) =>
    api.get(`/api/v1/scan/${scanId}`),

  getScanResults: (scanId) =>
    api.get(`/api/v1/scan/${scanId}/results`),

  getCBOM: (scanId) =>
    api.get(`/api/v1/scan/${scanId}/cbom`),

  getHNDLRisk: (scanId, migrationYears = 3, dataLifeYears = 7) =>
    api.post('/api/v1/hndl-risk', {
      scan_id: scanId,
      migration_years: migrationYears,
      data_life_years: dataLifeYears,
    }),

  getHistory: () =>
    api.get('/api/v1/history'),

  deleteScan: (scanId) =>
    api.delete(`/api/v1/scan/${scanId}`),

  health: () =>
    api.get('/health'),  // Fixed: /health not /api/v1/health
};

export const mlApi = {
  analyze: (cbomId) =>
    api.post('/api/v1/ml/analyze', { cbom_id: cbomId }),
};

export default api;
