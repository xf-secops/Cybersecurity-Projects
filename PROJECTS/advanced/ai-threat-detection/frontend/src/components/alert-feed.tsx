// ===================
// © AngelaMos | 2026
// alert-feed.tsx
// ===================

import { useEffect, useRef } from 'react'
import type { WebSocketAlert } from '@/api/types'
import styles from './alert-feed.module.scss'
import { SeverityBadge } from './severity-badge'

interface AlertFeedProps {
  alerts: WebSocketAlert[]
  isConnected: boolean
  maxHeight?: string
}

function formatTime(timestamp: string): string {
  return new Date(timestamp).toLocaleTimeString()
}

const METHOD_STYLES: Record<string, string> = {
  GET: styles.methodGet,
  POST: styles.methodPost,
  PUT: styles.methodPut,
  DELETE: styles.methodDelete,
  PATCH: styles.methodPatch,
  HEAD: styles.methodHead,
  OPTIONS: styles.methodOptions,
}

export function AlertFeed({
  alerts,
  isConnected,
  maxHeight,
}: AlertFeedProps): React.ReactElement {
  const listRef = useRef<HTMLDivElement>(null)

  const alertCount = alerts.length
  // biome-ignore lint/correctness/useExhaustiveDependencies: scroll on new alerts
  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = 0
    }
  }, [alertCount])

  return (
    <div className={styles.feed}>
      <div className={styles.header}>
        <h3 className={styles.title}>Live Alerts</h3>
        <span
          className={`${styles.status} ${isConnected ? styles.connected : styles.disconnected}`}
        />
      </div>

      <div
        ref={listRef}
        className={styles.list}
        style={maxHeight ? { maxHeight } : undefined}
      >
        {alerts.length === 0 ? (
          <div className={styles.empty}>Waiting for alerts...</div>
        ) : (
          alerts.map((alert, i) => (
            <div
              key={alert.id ?? `${alert.timestamp}-${i}`}
              className={styles.row}
            >
              <span className={styles.time}>{formatTime(alert.timestamp)}</span>
              <span className={styles.ip}>{alert.source_ip}</span>
              <span
                className={`${styles.method} ${METHOD_STYLES[alert.request_method] ?? ''}`}
              >
                {alert.request_method}
              </span>
              <span className={styles.path}>{alert.request_path}</span>
              <SeverityBadge
                severity={alert.severity as 'HIGH' | 'MEDIUM' | 'LOW'}
              />
              <span className={styles.score}>
                {alert.threat_score.toFixed(2)}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
