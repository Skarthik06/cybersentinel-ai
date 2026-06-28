'use client'

import { type CSSProperties, type ReactNode } from 'react'

interface StarBorderProps {
  children: ReactNode
  color?: string
  /** seconds per orbit */
  speed?: number
  className?: string
  style?: CSSProperties
  radius?: number
}

/**
 * StarBorder — animated light streaks that orbit the top & bottom edges of a
 * rounded container (ReactBits-style). CSS only. Wrap a button/card with it.
 */
export function StarBorder({
  children,
  color = '#00E5FF',
  speed = 6,
  className = '',
  style,
  radius = 8,
}: StarBorderProps) {
  return (
    <div
      className={className}
      style={{ position: 'relative', display: 'block', padding: '1px', overflow: 'hidden', borderRadius: radius, ...style }}
    >
      <style>{`
        @keyframes star-move-bottom{0%{transform:translateX(0);opacity:0.9}100%{transform:translateX(-100%);opacity:0}}
        @keyframes star-move-top{0%{transform:translateX(0);opacity:0.9}100%{transform:translateX(100%);opacity:0}}
      `}</style>
      <div style={{ position: 'absolute', width: '300%', height: '60%', bottom: '-12px', right: '-250%', borderRadius: '50%', zIndex: 0, animation: `star-move-bottom ${speed}s linear infinite alternate`, background: `radial-gradient(circle, ${color}, transparent 12%)`, opacity: 0.7 }} />
      <div style={{ position: 'absolute', width: '300%', height: '60%', top: '-12px', left: '-250%', borderRadius: '50%', zIndex: 0, animation: `star-move-top ${speed}s linear infinite alternate`, background: `radial-gradient(circle, ${color}, transparent 12%)`, opacity: 0.7 }} />
      <div style={{ position: 'relative', zIndex: 1, borderRadius: radius - 1, overflow: 'hidden' }}>{children}</div>
    </div>
  )
}
