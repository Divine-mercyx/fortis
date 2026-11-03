'use client';

import { Children, isValidElement, useEffect, useRef, useState, type ReactNode } from 'react';

/** Word-by-word headline reveal, like the website's hero. Wrap plain text and <span>s. */
export function Words({ children, delay = 0 }: { children: ReactNode; delay?: number }) {
  let i = 0;
  const split = (node: ReactNode): ReactNode =>
    Children.map(node, (child) => {
      if (typeof child === 'string') {
        return child.split(/(\s+)/).map((part, k) =>
          /^\s+$/.test(part) || !part ? (
            part
          ) : (
            <span className="w" key={`${k}-${part}`}>
              <span style={{ ['--i' as string]: i++, ['--d' as string]: `${delay}ms` }}>{part}</span>
            </span>
          ),
        );
      }
      if (isValidElement<{ children?: ReactNode; className?: string }>(child)) {
        return <span className={child.props.className}>{split(child.props.children)}</span>;
      }
      return child;
    });
  return <span className="words">{split(children)}</span>;
}

/** Counts up from 0 when the value first appears or changes. */
export function CountUp({ value, duration = 1200 }: { value: number; duration?: number }) {
  const [shown, setShown] = useState(0);
  const from = useRef(0);
  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) {
      setShown(value);
      return;
    }
    const start = performance.now();
    const begin = from.current;
    let raf = 0;
    const tick = (now: number) => {
      const k = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - k, 3);
      setShown(Math.round(begin + (value - begin) * eased));
      if (k < 1) raf = requestAnimationFrame(tick);
      else from.current = value;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, duration]);
  return <>{shown.toLocaleString('en-US')}</>;
}

/** Terminal that types its lines in, then optionally loops. Lines may contain the c-* colour spans. */
export function TypedTerminal({ lines, loop = false, step = 420 }: { lines: string[]; loop?: boolean; step?: number }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) {
      setCount(lines.length);
      return;
    }
    let n = 0;
    let timer: ReturnType<typeof setTimeout>;
    const next = () => {
      n += 1;
      setCount(n);
      if (n < lines.length) timer = setTimeout(next, step);
      else if (loop)
        timer = setTimeout(() => {
          n = 0;
          setCount(0);
          timer = setTimeout(next, 600);
        }, 4200);
    };
    timer = setTimeout(next, 500);
    return () => clearTimeout(timer);
  }, [lines, loop, step]);
  return (
    <div className="term" aria-hidden="true">
      <div className="bar"><i /><i /><i /></div>
      <div className="body">
        {lines.map((l, i) => (
          <div key={i} className={`ln${i < count ? ' on' : ''}`} dangerouslySetInnerHTML={{ __html: l }} />
        ))}
      </div>
    </div>
  );
}
