import { useEffect, useState } from 'react';

/** True when the user asked the OS/browser for reduced motion. Safe in jsdom. */
export function useReducedMotion() {
  const [reduced, setReduced] = useState(() =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia('(prefers-reduced-motion: reduce)').matches
      : false
  );

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const onChange = () => setReduced(mq.matches);
    mq.addEventListener?.('change', onChange);
    return () => mq.removeEventListener?.('change', onChange);
  }, []);

  return reduced;
}

/**
 * Updates --mx / --my CSS variables on the element while the pointer moves over it.
 * Throttled with requestAnimationFrame; ignored for touch input and reduced motion.
 */
export function usePointerGlow(ref, enabled = true) {
  useEffect(() => {
    const el = ref.current;
    if (!el || !enabled) return undefined;
    let frame = 0;
    const onMove = (e) => {
      if (e.pointerType === 'touch') return;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const rect = el.getBoundingClientRect();
        el.style.setProperty('--mx', `${e.clientX - rect.left}px`);
        el.style.setProperty('--my', `${e.clientY - rect.top}px`);
      });
    };
    el.addEventListener('pointermove', onMove);
    return () => {
      cancelAnimationFrame(frame);
      el.removeEventListener('pointermove', onMove);
    };
  }, [ref, enabled]);
}
