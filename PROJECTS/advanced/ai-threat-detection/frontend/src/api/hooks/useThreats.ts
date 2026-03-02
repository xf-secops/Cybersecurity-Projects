// ===================
// © AngelaMos | 2026
// useThreats.ts
// ===================

import { useQuery } from '@tanstack/react-query'
import type { ThreatEvent, ThreatList } from '@/api/types'
import { ThreatEventSchema, ThreatListSchema } from '@/api/types'
import { API_ENDPOINTS, PAGINATION, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

interface ThreatParams {
  limit?: number
  offset?: number
  severity?: 'HIGH' | 'MEDIUM' | 'LOW'
  source_ip?: string
  since?: string
  until?: string
}

export function useThreats(params: ThreatParams = {}) {
  const queryParams = {
    limit: params.limit ?? PAGINATION.DEFAULT_LIMIT,
    offset: params.offset ?? 0,
    ...params,
  }

  return useQuery<ThreatList>({
    queryKey: QUERY_KEYS.THREATS.LIST(queryParams),
    queryFn: async () => {
      const { data } = await apiClient.get<unknown>(API_ENDPOINTS.THREATS.LIST, {
        params: queryParams,
      })
      return ThreatListSchema.parse(data)
    },
    ...QUERY_STRATEGIES.frequent,
  })
}

export function useThreat(id: string | null) {
  return useQuery<ThreatEvent>({
    queryKey: QUERY_KEYS.THREATS.BY_ID(id ?? ''),
    queryFn: async () => {
      const { data } = await apiClient.get<unknown>(
        API_ENDPOINTS.THREATS.BY_ID(id as string)
      )
      return ThreatEventSchema.parse(data)
    },
    enabled: id !== null,
    ...QUERY_STRATEGIES.standard,
  })
}
