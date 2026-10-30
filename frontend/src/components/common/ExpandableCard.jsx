import React, { useState, useEffect, useRef } from 'react';

/**
 * Interactive, accessible expandable informational card.
 * Expands into a focused detail overlay modal with rich technical context,
 * keyboard trap/escape handling, and smooth transitions.
 *
 * @param {{
 *   title: string,
 *   badge?: string,
 *   badgeColor?: string,
 *   summary: string,
 *   details?: string | React.ReactNode,
 *   technicalNotes?: Array<string> | React.ReactNode,
 *   tags?: Array<string>,
 *   icon?: React.ReactNode,
 *   className?: string
 * }} props
 */
export function ExpandableCard({
  title,
  badge,
  badgeColor = 'bg-brand-luminous/15 text-brand-cyan border-brand-cyan/30',
  summary,
  details,
  technicalNotes,
  tags = [],
  icon,
  className = ''
}) {
  const [isOpen, setIsOpen] = useState(false);
  const cardRef = useRef(null);
  const closeBtnRef = useRef(null);

  // Close on Escape key & manage focus
  useEffect(() => {
    function handleKeyDown(e) {
      if (isOpen && e.key === 'Escape') {
        setIsOpen(false);
        if (cardRef.current) {
          cardRef.current.focus();
        }
      }
    }
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
      // Auto-focus close button on modal open
      setTimeout(() => {
        if (closeBtnRef.current) {
          closeBtnRef.current.focus();
        }
      }, 50);
    } else {
      document.body.style.overflow = '';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [isOpen]);

  const handleOpen = () => {
    setIsOpen(true);
  };

  const handleClose = (e) => {
    e.stopPropagation();
    setIsOpen(false);
    if (cardRef.current) {
      cardRef.current.focus();
    }
  };

  return (
    <>
      {/* Collapsed Card (Interactive Surface) */}
      <div
        ref={cardRef}
        role="button"
        tabIndex={0}
        onClick={handleOpen}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            handleOpen();
          }
        }}
        aria-haspopup="dialog"
        aria-expanded={isOpen}
        className={`group relative p-6 rounded-2xl bg-space-850/80 hover:bg-space-800 border border-white/10 hover:border-brand-luminous/50 transition-all duration-300 shadow-lg hover:shadow-[0_0_30px_-5px_rgba(37,141,235,0.35)] hover:-translate-y-1 cursor-pointer flex flex-col justify-between focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-cyan ${className}`}
      >
        <div>
          <div className="flex items-center justify-between gap-3 mb-3">
            {badge && (
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-mono uppercase tracking-wider font-semibold border ${badgeColor}`}>
                {badge}
              </span>
            )}
            <span className="text-xs text-ink-400 group-hover:text-brand-cyan transition-colors flex items-center gap-1 font-mono">
              <span>Explore</span>
              <svg className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M14 5l7 7m0 0l-7 7m7-7H3" />
              </svg>
            </span>
          </div>

          <div className="flex items-start gap-3">
            {icon && <div className="mt-0.5 text-brand-cyan shrink-0">{icon}</div>}
            <div>
              <h3 className="text-lg font-bold text-white group-hover:text-brand-cyan transition-colors leading-snug">
                {title}
              </h3>
              <p className="mt-2 text-sm text-ink-300 leading-relaxed line-clamp-3">
                {summary}
              </p>
            </div>
          </div>
        </div>

        {tags && tags.length > 0 && (
          <div className="mt-4 pt-3 border-t border-white/5 flex flex-wrap gap-1.5">
            {tags.slice(0, 3).map((tag) => (
              <span key={tag} className="px-2 py-0.5 rounded text-[10px] font-mono bg-white/[0.04] text-ink-400">
                {tag}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Expanded Modal Overlay */}
      {isOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby={`dialog-title-${title.replace(/\s+/g, '-').toLowerCase()}`}
          className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 lg:p-8 bg-space-950/80 backdrop-blur-md animate-ag-rise"
          onClick={handleClose}
        >
          <div
            className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-space-850 border border-brand-luminous/40 rounded-2xl p-6 sm:p-8 shadow-[0_0_60px_-10px_rgba(37,141,235,0.45)] ring-1 ring-white/10 text-ink-100"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="flex items-start justify-between gap-4 pb-4 border-b border-white/10">
              <div>
                {badge && (
                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-mono uppercase tracking-wider font-semibold border mb-2 ${badgeColor}`}>
                    {badge}
                  </span>
                )}
                <h2
                  id={`dialog-title-${title.replace(/\s+/g, '-').toLowerCase()}`}
                  className="text-2xl font-extrabold text-white tracking-tight"
                >
                  {title}
                </h2>
              </div>

              <button
                ref={closeBtnRef}
                type="button"
                onClick={handleClose}
                className="p-2 rounded-xl bg-white/[0.05] hover:bg-white/[0.1] text-ink-300 hover:text-white border border-white/10 transition-colors focus:outline-none focus:ring-2 focus:ring-brand-cyan"
                aria-label="Close detail modal"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Body */}
            <div className="py-6 space-y-5 text-sm sm:text-base leading-relaxed text-ink-200">
              <div className="p-4 rounded-xl bg-space-900/80 border border-brand-blue/30 text-ink-100 font-medium">
                {summary}
              </div>

              {details && (
                <div className="space-y-3">
                  <h4 className="text-xs uppercase tracking-wider font-bold text-brand-cyan font-mono">
                    Technical Architecture & Implementation
                  </h4>
                  <div className="text-sm text-ink-300 leading-relaxed space-y-2">
                    {typeof details === 'string' ? <p>{details}</p> : details}
                  </div>
                </div>
              )}

              {technicalNotes && (
                <div className="space-y-2 pt-2 border-t border-white/5">
                  <h4 className="text-xs uppercase tracking-wider font-bold text-ink-400 font-mono">
                    Security Controls & Verified Invariants
                  </h4>
                  {Array.isArray(technicalNotes) ? (
                    <ul className="space-y-1.5 text-xs text-ink-300">
                      {technicalNotes.map((note, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-brand-cyan font-bold">&check;</span>
                          <span>{note}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    technicalNotes
                  )}
                </div>
              )}

              {tags && tags.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-4 border-t border-white/5">
                  {tags.map((t) => (
                    <span key={t} className="px-2.5 py-1 rounded-md text-xs font-mono bg-white/[0.05] border border-white/10 text-ink-300">
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Footer Actions */}
            <div className="pt-4 border-t border-white/10 flex justify-end">
              <button
                type="button"
                onClick={handleClose}
                className="px-5 py-2 rounded-lg text-sm font-semibold text-white bg-white/[0.08] hover:bg-white/[0.14] border border-white/15 transition-colors focus:outline-none focus:ring-2 focus:ring-brand-cyan"
              >
                Done (Esc)
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default ExpandableCard;