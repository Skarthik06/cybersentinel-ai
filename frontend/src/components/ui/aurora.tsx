'use client'

import { type CSSProperties } from 'react'

interface AuroraProps {
  className?: string
  style?: CSSProperties
}

/**
 * Aurora — elegant animated aurora glow background (ReactBits-style).
 * Dependency-free CSS implementation: three slow-drifting blurred color blobs.
 */
export function Aurora({ className = '', style }: AuroraProps) {
  return (
    <div className={className} style={{ position: 'absolute', inset: 0, overflow: 'hidden', ...style }}>
      <style>{`
        @keyframes aurora-a{0%,100%{transform:translate(-15%,-10%) scale(1)}50%{transform:translate(15%,12%) scale(1.25)}}
        @keyframes aurora-b{0%,100%{transform:translate(12%,-6%) scale(1.1)}50%{transform:translate(-12%,16%) scale(0.9)}}
        @keyframes aurora-c{0%,100%{transform:translate(0%,12%) scale(1)}50%{transform:translate(-14%,-14%) scale(1.2)}}
      `}</style>
      <div style={{ position: 'absolute', top: '-20%', left: '8%', width: '60vw', height: '60vw', borderRadius: '50%', filter: 'blur(90px)', opacity: 0.5, background: 'radial-gradient(circle, rgba(0,176,255,0.45), transparent 60%)', animation: 'aurora-a 14s ease-in-out infinite' }} />
      <div style={{ position: 'absolute', top: '18%', right: '4%', width: '52vw', height: '52vw', borderRadius: '50%', filter: 'blur(100px)', opacity: 0.42, background: 'radial-gradient(circle, rgba(0,229,255,0.4), transparent 60%)', animation: 'aurora-b 18s ease-in-out infinite' }} />
      <div style={{ position: 'absolute', bottom: '-18%', left: '28%', width: '46vw', height: '46vw', borderRadius: '50%', filter: 'blur(100px)', opacity: 0.36, background: 'radial-gradient(circle, rgba(13,71,161,0.5), transparent 60%)', animation: 'aurora-c 16s ease-in-out infinite' }} />
    </div>
  )
}
