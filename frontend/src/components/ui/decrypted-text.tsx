'use client'

import { useEffect, useRef, useState, type CSSProperties } from 'react'

interface DecryptedTextProps {
  text: string
  speed?: number
  className?: string
  style?: CSSProperties
  characters?: string
  /** how many scramble frames each character passes through before locking */
  revealDelay?: number
}

/**
 * DecryptedText — scrambles characters then "decrypts" left-to-right (ReactBits-style).
 * Pure JS, no dependencies. Re-runs whenever `text` changes.
 */
export function DecryptedText({
  text,
  speed = 45,
  className = '',
  style,
  characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!<>-_\\/[]{}=+*^?#',
  revealDelay = 3,
}: DecryptedTextProps) {
  const [display, setDisplay] = useState(text)
  const frame = useRef(0)

  useEffect(() => {
    frame.current = 0
    const total = text.length * revealDelay
    const id = setInterval(() => {
      frame.current += 1
      const revealed = Math.floor(frame.current / revealDelay)
      setDisplay(
        text
          .split('')
          .map((ch, i) => {
            if (ch === ' ') return ' '
            if (i < revealed) return text[i]
            return characters[Math.floor(Math.random() * characters.length)]
          })
          .join('')
      )
      if (frame.current >= total) {
        setDisplay(text)
        clearInterval(id)
      }
    }, speed)
    return () => clearInterval(id)
  }, [text, speed, characters, revealDelay])

  return (
    <span className={className} style={style}>
      {display}
    </span>
  )
}
