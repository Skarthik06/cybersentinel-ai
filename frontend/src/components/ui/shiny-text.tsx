'use client'

import { type CSSProperties } from 'react'

interface ShinyTextProps {
  text: string
  disabled?: boolean
  /** seconds per shine sweep */
  speed?: number
  className?: string
  style?: CSSProperties
  /** base text color the sheen sweeps across */
  baseColor?: string
  shineColor?: string
}

/**
 * ShinyText — a moving light sheen across text (ReactBits-style). CSS only.
 */
export function ShinyText({
  text,
  disabled = false,
  speed = 4,
  className = '',
  style,
  baseColor = '#4FC3F7',
  shineColor = '#FFFFFF',
}: ShinyTextProps) {
  return (
    <>
      <style>{`@keyframes shiny-text-sweep{0%{background-position:100% 0}100%{background-position:-100% 0}}`}</style>
      <span
        className={className}
        style={{
          background: `linear-gradient(120deg, ${baseColor} 35%, ${shineColor} 50%, ${baseColor} 65%)`,
          backgroundSize: '200% 100%',
          WebkitBackgroundClip: 'text',
          backgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          color: 'transparent',
          ...(disabled ? {} : { animation: `shiny-text-sweep ${speed}s linear infinite` }),
          ...style,
        }}
      >
        {text}
      </span>
    </>
  )
}
