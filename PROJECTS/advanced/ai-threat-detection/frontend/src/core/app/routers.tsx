// ===================
// © AngelaMos | 2026
// routers.tsx
// ===================

import { Navigate, createBrowserRouter, type RouteObject } from 'react-router-dom'
import { ROUTES } from '@/config'
import { Shell } from './shell'

const routes: RouteObject[] = [
  {
    element: <Shell />,
    children: [
      {
        path: ROUTES.DASHBOARD,
        lazy: () => import('@/pages/dashboard'),
      },
      {
        path: ROUTES.THREATS,
        lazy: () => import('@/pages/threats'),
      },
      {
        path: ROUTES.MODELS,
        lazy: () => import('@/pages/models'),
      },
    ],
  },
  {
    path: '*',
    element: <Navigate to={ROUTES.DASHBOARD} replace />,
  },
]

export const router = createBrowserRouter(routes)
