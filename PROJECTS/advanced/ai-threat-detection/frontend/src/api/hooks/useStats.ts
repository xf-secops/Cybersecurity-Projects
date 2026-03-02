// ===================
// © AngelaMos | 2026
// useStats.ts
// ===================

import { useQuery } from '@tanstack/react-query'
import type { StatsResponse } from '@/api/types'
import { StatsResponseSchema } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export function useStats(range = '24h') {
  return useQuery<StatsResponse>({
    queryKey: QUERY_KEYS.STATS.BY_RANGE(range),
    queryFn: async () => {
      const { data } = await apiClient.get<unknown>(API_ENDPOINTS.STATS, {
        params: { range },
      })
      return StatsResponseSchema.parse(data)
    },
    ...QUERY_STRATEGIES.frequent,
  })
}
