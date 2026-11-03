'use client';

import { useEffect, useRef } from 'react';

/*
 * Realistic Earth rendered with a small WebGL shader (the same one as fortis.dev).
 * Textures in /public/earth: earth-day.jpg (colour) and earth-aux.jpg
 * (R = clouds, G = city lights, B = water mask). Falls back to a still image.
 */

const R = 0.78;
const DEG = Math.PI / 180;

const VERT = `attribute vec2 p; varying vec2 vUv; void main(){ vUv = p * .5 + .5; gl_Position = vec4(p, 0., 1.); }`;
const FRAG = `
precision highp float;
varying vec2 vUv;
uniform sampler2D uDay, uAux;
uniform float uLon, uLat, uCloud, uPx;
uniform vec3 uSun;
const float R = ${R.toFixed(3)};
const float PI = 3.14159265;
vec2 lonLatUv(vec3 v, float lonOff) {
  float cb = cos(uLat), sb = sin(uLat);
  float y = v.y * cb + v.z * sb;
  float z1 = -v.y * sb + v.z * cb;
  float cl = cos(uLon), sl = sin(uLon);
  float x = v.x * cl + z1 * sl;
  float z = -v.x * sl + z1 * cl;
  return vec2(fract(atan(x, z) / (2. * PI) + .5 + lonOff), .5 - asin(clamp(y, -1., 1.)) / PI);
}
void main() {
  vec2 p = vUv * 2. - 1.;
  float d = length(p) / R;
  float aa = uPx / R;
  float halo = exp(-max(d - 1., 0.) * 8.) * .7 * (1. - smoothstep(1.0, 1.32, d));
  vec3 haloCol = vec3(.30, .62, 1.) * halo;
  if (d > 1. + aa) { gl_FragColor = vec4(haloCol, halo); return; }
  float dz = sqrt(max(1. - d * d, 0.));
  vec3 n = vec3(p / R, dz);
  vec2 uv = lonLatUv(n, 0.);
  vec3 day = pow(texture2D(uDay, uv).rgb, vec3(.88)) * 1.12;
  vec4 aux = texture2D(uAux, uv);
  float cloud = texture2D(uAux, lonLatUv(n, uCloud)).r;
  float ndl = dot(n, uSun);
  float dayAmt = smoothstep(-.12, .28, ndl);
  float diff = max(ndl, 0.);
  vec3 col = day * (.10 + 1.05 * diff);
  col += vec3(1., .76, .42) * pow(aux.g, 1.6) * 1.8 * (1. - dayAmt);
  vec3 h = normalize(uSun + vec3(0., 0., 1.));
  col += vec3(.9, .95, 1.) * pow(max(dot(n, h), 0.), 70.) * aux.b * .55 * dayAmt;
  col = mix(col, vec3(1.) * (.08 + .95 * diff), smoothstep(.04, .95, cloud) * .7);
  float fres = pow(1. - dz, 2.6);
  col = mix(col, vec3(.48, .72, 1.) * (.25 + .9 * dayAmt), fres * .75);
  col += vec3(.05, .09, .16) * (1. - dz) * dayAmt;
  float a = 1. - smoothstep(1. - aa, 1. + aa, d);
  gl_FragColor = vec4(col * a + haloCol * (1. - a), a + halo * (1. - a));
}`;

type City = { name: string; lat: number; lon: number; hub?: boolean; dx?: number; dy?: number; anchor?: 'start' | 'middle' | 'end' };

const CITIES: City[] = [
  { name: 'Lagos', lat: 6.52, lon: 3.38, hub: true, dx: 0, dy: -16, anchor: 'middle' },
  { name: 'Accra', lat: 5.6, lon: -0.19, dx: -10, dy: 14, anchor: 'end' },
  { name: 'Nairobi', lat: -1.29, lon: 36.82 },
  { name: 'Kigali', lat: -1.95, lon: 30.06, dx: -10, dy: 12, anchor: 'end' },
  { name: 'Johannesburg', lat: -26.2, lon: 28.05 },
  { name: 'Cairo', lat: 30.04, lon: 31.24 },
];
const ARC_COLORS = ['#7DF2B2', '#3D7BFF', '#7DF2B2', '#3D7BFF', '#7DF2B2'];

const vec = (lat: number, lon: number): [number, number, number] => [
  Math.cos(lat * DEG) * Math.sin(lon * DEG),
  Math.sin(lat * DEG),
  Math.cos(lat * DEG) * Math.cos(lon * DEG),
];

function toView([x, y, z]: [number, number, number], L: number, B: number): [number, number, number] {
  const cl = Math.cos(L), sl = Math.sin(L);
  const x1 = x * cl - z * sl;
  const z1 = x * sl + z * cl;
  const cb = Math.cos(B), sb = Math.sin(B);
  return [x1, y * cb - z1 * sb, y * sb + z1 * cb];
}

function slerp(a: [number, number, number], b: [number, number, number], t: number): [number, number, number] {
  const dot = Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
  const om = Math.acos(dot);
  if (om < 1e-4) return a;
  const s = Math.sin(om);
  const ka = Math.sin((1 - t) * om) / s;
  const kb = Math.sin(t * om) / s;
  return [a[0] * ka + b[0] * kb, a[1] * ka + b[1] * kb, a[2] * ka + b[2] * kb];
}

export function Earth({ className = '', interactive = true }: { className?: string; interactive?: boolean }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const host = hostRef.current!;
    const canvas = canvasRef.current!;
    const svg = svgRef.current!;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const gl = canvas.getContext('webgl', { premultipliedAlpha: true, antialias: false, alpha: true });
    if (!gl) return;

    const compile = (type: number, src: string) => {
      const s = gl.createShader(type)!;
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s) ?? 'shader');
      return s;
    };
    let prog: WebGLProgram;
    try {
      prog = gl.createProgram()!;
      gl.attachShader(prog, compile(gl.VERTEX_SHADER, VERT));
      gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG));
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error('link');
    } catch {
      return;
    }
    gl.useProgram(prog);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    const loc = gl.getAttribLocation(prog, 'p');
    gl.enableVertexAttribArray(loc);
    gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
    const U = Object.fromEntries(['uDay', 'uAux', 'uLon', 'uLat', 'uCloud', 'uPx', 'uSun'].map((k) => [k, gl.getUniformLocation(prog, k)]));
    const sun = [-0.42, 0.36, 0.83];
    const sl = Math.hypot(...sun);
    gl.uniform3f(U.uSun!, sun[0]! / sl, sun[1]! / sl, sun[2]! / sl);
    gl.uniform1i(U.uDay!, 0);
    gl.uniform1i(U.uAux!, 1);

    const loadTex = (unit: number, url: string) =>
      new Promise<void>((resolve, reject) => {
        const img = new Image();
        img.decoding = 'async';
        img.onload = () => {
          try {
            const t = gl.createTexture();
            gl.activeTexture(gl.TEXTURE0 + unit);
            gl.bindTexture(gl.TEXTURE_2D, t);
            gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGB, gl.RGB, gl.UNSIGNED_BYTE, img);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
            gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
            resolve();
          } catch (e) {
            reject(e);
          }
        };
        img.onerror = reject;
        img.src = url;
      });

    // City markers and links, drawn in SVG on top of the canvas.
    const NS = 'http://www.w3.org/2000/svg';
    const el = (tag: string, attrs: Record<string, string | number>, parent: Element) => {
      const e = document.createElementNS(NS, tag);
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
      parent.appendChild(e);
      return e;
    };
    svg.replaceChildren();
    const cities = CITIES.map((c) => ({ ...c, v: vec(c.lat, c.lon) }));
    const hub = cities[0]!;
    const arcs = cities.slice(1).map((c, i) => ({ to: c, path: el('path', { class: 'earth-arc', stroke: ARC_COLORS[i % ARC_COLORS.length]!, fill: 'none' }, svg) }));
    const marks = cities.map((c) => {
      const g = el('g', { class: c.hub ? 'earth-city hub' : 'earth-city' }, svg);
      if (c.hub) el('circle', { r: 12, class: 'ring' }, g);
      el('circle', { r: c.hub ? 5.5 : 4, class: 'dot' }, g);
      const t = el('text', { x: c.dx ?? 12, y: c.dy ?? 4, 'text-anchor': c.anchor ?? 'start' }, g);
      t.textContent = c.name;
      return { c, g };
    });

    let size = 0;
    const resize = () => {
      size = host.clientWidth;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = canvas.height = Math.round(size * dpr);
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.uniform1f(U.uPx!, 2 / canvas.width);
      svg.setAttribute('viewBox', `0 0 ${size} ${size}`);
    };

    const BASE_LON = 17 * DEG;
    const BASE_LAT = 6 * DEG;
    let pointer = { x: 0, y: 0 };
    const eased = { x: 0, y: 0 };
    let raf = 0;
    let running = false;
    let visible = true;
    let ready = false;
    const t0 = performance.now();

    const draw = (now: number) => {
      const t = reduce ? 0 : (now - t0) / 1000;
      eased.x += (pointer.x - eased.x) * 0.05;
      eased.y += (pointer.y - eased.y) * 0.05;
      const L = BASE_LON + Math.sin(t * 0.07) * 16 * DEG + eased.x * 14 * DEG;
      const B = BASE_LAT - eased.y * 8 * DEG;
      gl.uniform1f(U.uLon!, L);
      gl.uniform1f(U.uLat!, B);
      gl.uniform1f(U.uCloud!, -t * 0.0035);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);

      const half = size / 2;
      const rad = R * half;
      const proj = (v: [number, number, number]) => [half + v[0] * rad, half - v[1] * rad, v[2]] as const;
      for (const { c, g } of marks) {
        const [x, y, z] = proj(toView(c.v, L, B));
        g.setAttribute('transform', `translate(${x.toFixed(1)} ${y.toFixed(1)})`);
        (g as SVGGElement).style.opacity = Math.max(0, Math.min(1, (z - 0.08) * 5)).toFixed(2);
      }
      for (const { to, path } of arcs) {
        let d = '';
        let minZ = 1;
        for (let i = 0; i <= 28; i++) {
          const k = i / 28;
          const s = slerp(hub.v, to.v, k);
          const lift = 1 + 0.16 * Math.sin(Math.PI * k);
          const [x, y, z] = proj(toView([s[0] * lift, s[1] * lift, s[2] * lift], L, B));
          minZ = Math.min(minZ, z);
          d += `${i ? 'L' : 'M'}${x.toFixed(1)} ${y.toFixed(1)}`;
        }
        path.setAttribute('d', d);
        (path as SVGPathElement).style.opacity = Math.max(0, Math.min(1, minZ * 4)).toFixed(2);
      }
      if (running && !reduce) raf = requestAnimationFrame(draw);
    };
    const start = () => {
      if (running || !ready || !visible) return;
      running = true;
      raf = requestAnimationFrame(draw);
    };
    const stop = () => {
      running = false;
      cancelAnimationFrame(raf);
    };

    const io = new IntersectionObserver(([e]) => {
      visible = Boolean(e?.isIntersecting);
      if (visible) start();
      else stop();
    });
    io.observe(host);
    const onVis = () => (document.hidden ? stop() : start());
    document.addEventListener('visibilitychange', onVis);
    const onResize = () => {
      resize();
      if (!running) requestAnimationFrame(draw);
    };
    window.addEventListener('resize', onResize);
    const stage = (host.closest('[data-earth-stage]') as HTMLElement | null) ?? host;
    const onMove = (e: PointerEvent) => {
      const r = stage.getBoundingClientRect();
      pointer = { x: (e.clientX - r.left) / r.width - 0.5, y: (e.clientY - r.top) / r.height - 0.5 };
    };
    const onLeave = () => {
      pointer = { x: 0, y: 0 };
    };
    if (interactive && !reduce && window.matchMedia('(pointer: fine)').matches) {
      stage.addEventListener('pointermove', onMove);
      stage.addEventListener('pointerleave', onLeave);
    }

    resize();
    Promise.all([loadTex(0, '/earth/earth-day.jpg'), loadTex(1, '/earth/earth-aux.jpg')])
      .then(() => {
        ready = true;
        host.classList.add('is-live');
        if (reduce) draw(performance.now());
        else start();
      })
      .catch(() => {});

    return () => {
      stop();
      io.disconnect();
      document.removeEventListener('visibilitychange', onVis);
      window.removeEventListener('resize', onResize);
      stage.removeEventListener('pointermove', onMove);
      stage.removeEventListener('pointerleave', onLeave);
      gl.getExtension('WEBGL_lose_context')?.loseContext();
    };
  }, [interactive]);

  return (
    <div ref={hostRef} className={`earth ${className}`} aria-hidden="true">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img className="earth-fallback" src="/earth/earth-fallback.webp" alt="" />
      <canvas ref={canvasRef} />
      <svg ref={svgRef} className="earth-overlay" />
    </div>
  );
}
