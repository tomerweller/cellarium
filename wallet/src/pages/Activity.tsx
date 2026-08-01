import { useHistory } from '../api/queries';
import { entryView } from '../activity';
import { useKey } from '../keys/KeyContext';
import { CopyableHex, ErrorText, StatusBadge } from '../components/common';
import { Onboarding } from './Onboarding';

export function Activity() {
  const { wallet } = useKey();
  const { data, isLoading, error, refetch } = useHistory(wallet?.pkX);
  if (!wallet) return <Onboarding />;

  const entries = data?.entries ?? [];
  return (
    <div className="panel">
      <h2>Activity</h2>
      {isLoading && <p className="muted">Loading…</p>}
      {/* A failed query is an outage, not an empty ledger (issue #30). */}
      {error && (
        <div role="alert">
          <ErrorText error={error} />
          <button className="btn-inline" onClick={() => refetch()}>
            Retry
          </button>
          {data && <p className="muted">Showing the last loaded activity; it may be stale.</p>}
        </div>
      )}
      {!isLoading && !error && entries.length === 0 && <p className="muted">No activity yet.</p>}
      {entries.map((e) => {
        const v = entryView(e);
        return (
          <div className="list-row" key={`${e.status}-${e.id}`}>
            <div className="who">
              <span className="kind">{v.label}</span>
              {e.counterparty && (
                <span className="cp">
                  <CopyableHex value={e.counterparty} chars={6} />
                </span>
              )}
            </div>
            <div className="row" style={{ gap: '0.6rem' }}>
              <span className={v.sign === '−' ? 'amt-out' : 'amt-in'}>
                {v.sign}
                {v.amount} {v.unit}
              </span>
              <StatusBadge status={e.status} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
