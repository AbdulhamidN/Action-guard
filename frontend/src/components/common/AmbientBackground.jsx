import React from 'react';

/**
 * Reusable ambient animated background with deep navy atmosphere,
 * soft luminous blue and cyan orbs, and subtle geometric mesh.
 * Pure CSS/SVG, GPU-accelerated, zero layout shifts, and reduced-motion safe.
 *
 * @param {{
 *   variant?: 'hero' | 'section' | 'subtle' | 'admin',
 *   className?: string
 * }} props
 */
export function AmbientBackground({ variant = 'section', className = '' }) {
  if (variant === 'hero') {
    return (
      <div className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`} aria-hidden="true">
        {/* Deep navy atmosphere with radial sheen */}
        <div className="absolute inset-0 bg-gradient-to-b from-[#101C38] via-[#122345] to-[#101C38] opacity-90" />
        
        {/* Large Luminous Blue Orb 1 */}
        <div className="absolute -top-32 left-1/4 w-[600px] h-[600px] rounded-full bg-gradient-to-br from-[#174A91]/35 via-[#258DEB]/25 to-transparent blur-[120px] animate-ag-aurora" />

        {/* Luminous Cyan Accent Orb 2 */}
        <div className="absolute top-20 right-1/6 w-[450px] h-[450px] rounded-full bg-gradient-to-bl from-[#35C5E8]/20 via-[#258DEB]/15 to-transparent blur-[100px] animate-ag-float-reverse" />

        {/* Deep Center Ambient Glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[400px] rounded-full bg-[#174A91]/20 blur-[140px] animate-ag-glow" />

        {/* Subtle Cyber Grid Mesh with Radial Vignette */}
        <div 
          className="absolute inset-0 ag-mesh-pattern opacity-60" 
          style={{
            maskImage: 'radial-gradient(ellipse 70% 60% at 50% 35%, black 20%, transparent 80%)',
            WebkitMaskImage: 'radial-gradient(ellipse 70% 60% at 50% 35%, black 20%, transparent 80%)'
          }}
        />

        {/* Soft Linear Horizon Highlight */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-[#35C5E8]/30 to-transparent" />
      </div>
    );
  }

  if (variant === 'admin') {
    return (
      <div className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`} aria-hidden="true">
        <div className="absolute inset-0 bg-gradient-to-b from-[#101C38] via-[#15294D] to-[#101C38]" />
        {/* Subtle Red/Cyan Privilege Glow */}
        <div className="absolute -top-24 right-1/4 w-[500px] h-[500px] rounded-full bg-gradient-to-br from-red-600/15 via-[#258DEB]/15 to-transparent blur-[130px] animate-ag-float" />
        <div className="absolute bottom-10 left-10 w-[400px] h-[400px] rounded-full bg-[#174A91]/25 blur-[120px] animate-ag-glow" />
        <div className="absolute inset-0 ag-mesh-pattern opacity-30" />
      </div>
    );
  }

  // Default 'section' / 'subtle' variant
  return (
    <div className={`pointer-events-none absolute inset-0 overflow-hidden ${className}`} aria-hidden="true">
      <div className="absolute top-0 left-1/3 w-[500px] h-[500px] rounded-full bg-[#174A91]/20 blur-[130px] animate-ag-float" />
      <div className="absolute bottom-0 right-1/4 w-[400px] h-[400px] rounded-full bg-[#35C5E8]/12 blur-[110px] animate-ag-float-reverse" />
      <div className="absolute inset-0 ag-mesh-pattern opacity-35" />
    </div>
  );
}

export default AmbientBackground;