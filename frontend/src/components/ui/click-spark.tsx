'use client'

import { useEffect, useRef } from 'react'

interface ClickSparkProps {
  sparkColor?: string
  sparkSize?: number
  sparkRadius?: number
  sparkCount?: number
  duration?: number
  zIndex?: number
}

interface Spark {
  x: number
  y: number
  start: number
}

/**
 * ClickSpark — emits a radial burst of light streaks wherever the user clicks
 * (ReactBits-style). Renders a fixed full-viewport canvas. Mount once.
 */
export function ClickSpark({
  sparkColor = '#00E5FF',
  sparkSize = 11,
  sparkRadius = 18,
  sparkCount = 8,
  duration = 420,
  zIndex = 9998,
}: ClickSparkProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const sparks = useRef<Spark[]>([])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const resize = () => {
      canvas.width = window.innerWidth
      canvas.height = window.innerHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const easeOut = (t: number) => t * (2 - t)
    let raf = 0

    const draw = (now: number) => {
      ctx.clearRect(0, 0, canvas.width, canvas.height)
      sparks.current = sparks.current.filter((s) => {
        const elapsed = now - s.start
        if (elapsed >= duration) return false
        const p = easeOut(elapsed / duration)
        const dist = p * sparkRadius
        const len = sparkSize * (1 - p)
        for (let i = 0; i < sparkCount; i++) {
          const a = (2 * Math.PI * i) / sparkCount
          const x1 = s.x + dist * Math.cos(a)
          const y1 = s.y + dist * Math.sin(a)
          const x2 = s.x + (dist + len) * Math.cos(a)
          const y2 = s.y + (dist + len) * Math.sin(a)
          ctx.strokeStyle = sparkColor
          ctx.lineWidth = 2
          ctx.globalAlpha = 1 - p
          ctx.beginPath()
          ctx.moveTo(x1, y1)
          ctx.lineTo(x2, y2)
          ctx.stroke()
        }
        return true
      })
      ctx.globalAlpha = 1
      raf = requestAnimationFrame(draw)
    }
    raf = requestAnimationFrame(draw)

    const onClick = (e: MouseEvent) => {
      sparks.current.push({ x: e.clientX, y: e.clientY, start: performance.now() })
    }
    window.addEventListener('click', onClick)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', resize)
      window.removeEventListener('click', onClick)
    }
  }, [sparkColor, sparkSize, sparkRadius, sparkCount, duration])

  return <canvas ref={canvasRef} style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex }} />
}
