import axios from 'axios'
import Cookies from 'js-cookie'

const api = axios.create({
    // ?? (not ||) so NEXT_PUBLIC_API_URL="" is honored as "relative to
    // whatever origin served this page" — the same-origin nginx/Caddy
    // reverse-proxy deployments rely on that to avoid baking in a host IP.
    baseURL: process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:5000',
    // Send the HttpOnly auth cookie on every request (and store it from the
    // login response). No Authorization header is needed anymore.
    withCredentials: true,
})

export function apiErrorMessage(err: unknown, fallback = 'Something went wrong'): string {
    if (axios.isAxiosError(err)) {
        const data = err.response?.data as { error?: string } | undefined
        return data?.error ?? fallback
    }
    return fallback
}

api.interceptors.response.use(
    (r) => r,
    (err) => {
        // A 401 from the login endpoint itself just means "invalid credentials" —
        // let the login page show that inline instead of force-reloading /login.
        const isLoginRequest = err.config?.url === '/api/auth/login'
        if (err.response?.status === 401 && !isLoginRequest) {
            // token cookie is HttpOnly (cleared by the server); drop UI cookies
            Cookies.remove('role')
            Cookies.remove('username')
            if (typeof window !== 'undefined') {
                window.location.href = '/login'
            }
        }
        return Promise.reject(err)
    }
)

export const authApi = {
    login: (username: string, password: string) =>
        api.post('/api/auth/login', { username, password }),
    logout: () => api.post('/api/auth/logout'),
}

export const detectionsApi = {
    list: (params?: Record<string, unknown>) => api.get('/api/detections', { params }),
    get: (id: number | string) => api.get(`/api/detections/${id}`),
    resolve: (id: number | string) => api.patch(`/api/detections/${id}/resolve`),
    runDetection: () => api.post('/api/run-detection'),
    export: (params?: Record<string, unknown>) =>
        api.get('/api/detections/export', { params, responseType: 'blob' }),
}

export const statsApi = {
    get: () => api.get('/api/stats'),
    timeline: (days = 30) => api.get('/api/stats/timeline', { params: { days } }),
    alerts: () => api.get('/api/stats/alerts'),
    topOffenders: (limit = 10) => api.get('/api/stats/top-offenders', { params: { limit } }),
}

export const metricsApi = {
    get: () => api.get('/api/metrics'),
}

export const auditApi = {
    list: (params?: Record<string, unknown>) => api.get('/api/audit-logs', { params }),
    verify: () => api.get('/api/audit-logs/verify'),
}

export const reportApi = {
    generate: () => api.get('/api/report/generate', { responseType: 'blob' }),
}

export const scanApi = {
    interfaces: () => api.get('/api/scan/interfaces'),
    start: (iface?: string) => api.post('/api/scan/start', { iface }),
    stop: () => api.post('/api/scan/stop'),
    status: () => api.get('/api/scan/status'),
    detections: () => api.get('/api/scan/detections'),
    flush: () => api.post('/api/scan/flush'),
    newDevices: () => api.get('/api/scan/devices'),
}

export const devicesApi = {
    sightings: () => api.get('/api/devices/sightings'),
}

export const knownAssetsApi = {
    devices: () => api.get('/api/known-devices'),
    addDevice: (data: { src_ip?: string; src_mac?: string; name: string; notes?: string }) =>
        api.post('/api/known-devices', data),
    removeDevice: (id: number) => api.delete(`/api/known-devices/${id}`),
    applications: () => api.get('/api/known-applications'),
    addApplication: (data: { domain: string; name: string; notes?: string }) =>
        api.post('/api/known-applications', data),
    removeApplication: (id: number) => api.delete(`/api/known-applications/${id}`),
}

export default api
