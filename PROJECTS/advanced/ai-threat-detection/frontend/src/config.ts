// ===================
// © AngelaMos | 2026
// config.ts
// ===================

export const API_ENDPOINTS = {
  HEALTH: '/health',
  READY: '/ready',
  THREATS: {
    LIST: '/threats',
    BY_ID: (id: string) => `/threats/${id}`,
  },
  STATS: '/stats',
  MODELS: {
    STATUS: '/models/status',
    RETRAIN: '/models/retrain',
  },
} as const

export const WS_ENDPOINTS = {
  ALERTS: '/ws/alerts',
} as const

export const QUERY_KEYS = {
  THREATS: {
    ALL: ['threats'] as const,
    LIST: (params: Record<string, unknown>) =>
      [...QUERY_KEYS.THREATS.ALL, 'list', params] as const,
    BY_ID: (id: string) => [...QUERY_KEYS.THREATS.ALL, 'detail', id] as const,
  },
  STATS: {
    ALL: ['stats'] as const,
    BY_RANGE: (range: string) => [...QUERY_KEYS.STATS.ALL, range] as const,
  },
  MODELS: {
    ALL: ['models'] as const,
    STATUS: () => [...QUERY_KEYS.MODELS.ALL, 'status'] as const,
  },
} as const

export const ROUTES = {
  DASHBOARD: '/',
  THREATS: '/threats',
  MODELS: '/models',
} as const

export const STORAGE_KEYS = {
  UI: 'ui-storage',
} as const

export const QUERY_CONFIG = {
  STALE_TIME: {
    STANDARD: 1000 * 60 * 5,
    FREQUENT: 1000 * 30,
    STATIC: Infinity,
  },
  GC_TIME: {
    DEFAULT: 1000 * 60 * 30,
    LONG: 1000 * 60 * 60,
  },
  RETRY: {
    DEFAULT: 3,
    NONE: 0,
  },
} as const

export const PAGINATION = {
  DEFAULT_LIMIT: 50,
  MAX_LIMIT: 100,
} as const

export const ALERTS = {
  MAX_ITEMS: 50,
  RECONNECT_BASE_MS: 1000,
  RECONNECT_MAX_MS: 30000,
} as const
