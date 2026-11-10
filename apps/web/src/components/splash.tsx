/** Full-screen "Lock-in" splash: the core lights, two walls lock around it, then the name slides out. Styled in globals.css. */
export function Splash({ done }: { done: boolean }) {
  return (
    <div className={`splash${done ? ' done' : ''}`} role="status" aria-label="Loading Fortis" aria-hidden={done}>
      <span className="splash-mark" aria-hidden="true">
        <span className="side-l">
          <span>
            <i>f</i>
          </span>
        </span>
        <svg viewBox="0 0 56 56">
          <circle className="ring" cx="28" cy="28" r="5" />
          <g fill="none" stroke="currentColor">
            <g className="wall w1">
              <circle cx="28" cy="28" r="23" strokeWidth="8" strokeDasharray="132.5 12" transform="rotate(105 28 28)" />
            </g>
            <g className="wall w2">
              <circle cx="28" cy="28" r="11.5" strokeWidth="7" strokeDasharray="63.3 9" transform="rotate(-22.6 28 28)" />
            </g>
          </g>
          <circle className="core" cx="28" cy="28" r="4.5" />
        </svg>
        <span className="side-r">
          <span>
            <i>r</i>
            <i>t</i>
            <i>i</i>
            <i>s</i>
          </span>
        </span>
      </span>
    </div>
  );
}
