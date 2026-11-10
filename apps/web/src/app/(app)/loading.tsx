import { MarkSpinner } from '@/components/status';

/** Shown in the content area while the next page loads after an in-app click. The rail and top bar stay put. */
export default function Loading() {
  return (
    <div className="page-spin" role="status" aria-label="Loading">
      <MarkSpinner />
    </div>
  );
}
