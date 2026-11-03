import Link from 'next/link';

export default function NotFound() {
  return (
    <main style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', textAlign: 'center', padding: 24 }}>
      <div>
        <p className="eyebrow">404</p>
        <h1 className="display">
          This route has <span className="it accent">no owner.</span>
        </h1>
        <p className="lead">The page you're after doesn't exist, or it moved.</p>
        <p style={{ marginTop: 24 }}>
          <Link href="/overview" className="btn btn-primary">Back to overview</Link>
        </p>
      </div>
    </main>
  );
}
