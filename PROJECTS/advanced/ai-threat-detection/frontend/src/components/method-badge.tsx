// ===================
// © AngelaMos | 2026
// method-badge.tsx
// ===================

import styles from './method-badge.module.scss'

const METHOD_STYLES: Record<string, string> = {
  GET: styles.get,
  POST: styles.post,
  PUT: styles.put,
  DELETE: styles.delete,
  PATCH: styles.patch,
  HEAD: styles.head,
  OPTIONS: styles.options,
}

interface MethodBadgeProps {
  method: string
}

export function MethodBadge({ method }: MethodBadgeProps): React.ReactElement {
  return (
    <span className={`${styles.badge} ${METHOD_STYLES[method] ?? ''}`}>
      {method}
    </span>
  )
}
