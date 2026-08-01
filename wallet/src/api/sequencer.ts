// Typed client for the sequencer HTTP API (encodings frozen in DESIGN.md /
// the sequencer's api.rs). All field values are 0x+64 hex; amounts decimal
// strings of stroops; nonce a JSON number.
import { SEQUENCER_URL } from '../config';

export interface Params {
  contract_id: string;
  token_id: string;
  tust_id: string;
  oracle_id?: string;
  network_passphrase: string;
  rpc_url: string;
  batch: { deposits: number; txs: number };
}

export interface AccountInfo {
  pk_x: string;
  index: number;
  cash: string;
  coll: string;
  nonce: number;
  pending_nonce: number;
  pending_out_cash: string;
  pending_out_coll: string;
  /** Combined state root: P2(account_root, position_root). */
  root: string;
  /** Account-tree root — what `siblings` proves the leaf into. */
  account_root: string;
  /** Position-tree root; P2(account_root, position_root) must equal `root`. */
  position_root: string;
  batch_num: number;
  siblings: string[];
}

export interface Status {
  root: string;
  batch_num: number;
  pending_txs: number;
  pending_opens?: number;
  pending_deposits: number;
  contract_id: string;
  inflight_batch: { batch_num: number; status: string } | null;
  chain_synced: boolean;
}

export interface HistoryEntry {
  id: number;
  batch_num: number | null;
  /** e.g. deposit, transfer_in/out, withdraw, repo_open_borrower, … (see activity.ts). */
  kind: string;
  counterparty: string | null;
  asset: number;
  amount: string;
  nonce: number | null;
  status: 'pending' | 'batched' | 'rejected';
  ts: number;
}

export interface WireSig {
  r_x: string;
  r_y: string;
  s_lo: string;
  s_hi: string;
}

/** Signed read-auth for private listing endpoints (issue #1 L12). */
export interface IntentAuth {
  ts: number;
  pk_y: string;
  sig: WireSig;
}

export interface Intent {
  id: number;
  initiator: 'borrower' | 'lender';
  borrower_pk_x: string;
  borrower_pk_y: string;
  lender_pk_x: string;
  lender_pk_y: string;
  cash: string;
  coll: string;
  rate_bps: number;
  haircut_bps: number;
  open_ts: number;
  maturity_ts: number;
  borrower_nonce: number;
  lender_nonce: number;
  status: string;
  created_at: number;
}

export interface Position {
  slot: number;
  borrower_pk_x: string;
  lender_pk_x: string;
  cash: string;
  coll: string;
  rate_bps: number;
  haircut_bps: number;
  open_ts: number;
  maturity_ts: number;
}

export interface IntentRequest {
  initiator: 'borrower' | 'lender';
  borrower_pk_x: string;
  borrower_pk_y: string;
  lender_pk_x: string;
  lender_pk_y: string;
  cash: string;
  coll: string;
  rate_bps: number;
  haircut_bps: number;
  open_ts: number;
  maturity_ts: number;
  borrower_nonce: number;
  lender_nonce: number;
  sig: WireSig;
}

export interface CloseRequest {
  pos_index: number;
  borrower_pk_x: string;
  borrower_pk_y: string;
  nonce: number;
  sig: WireSig;
}

export interface TxRequest {
  from_pk_x: string;
  from_pk_y: string;
  to: string;
  asset: number;
  amount: string;
  nonce: number;
  is_withdraw: boolean;
  sig: WireSig;
}

/** An error carrying the sequencer's structured `{code, message}`. */
export class ApiError extends Error {
  constructor(public code: string, message: string, public httpStatus: number) {
    super(message);
  }
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${SEQUENCER_URL}${path}`, init);
  } catch {
    // fetch rejects with an unhelpful TypeError when the host is unreachable.
    throw new ApiError('SEQUENCER_UNREACHABLE', `could not reach the sequencer at ${SEQUENCER_URL}`, 0);
  }
  const text = await res.text();
  let body: { error?: { code?: string; message?: string } } | null = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      // A proxy/gateway error page, not the sequencer's JSON.
      throw new ApiError(
        res.ok ? 'BAD_RESPONSE' : 'HTTP_ERROR',
        `unexpected non-JSON response from ${path} (HTTP ${res.status})`,
        res.status,
      );
    }
  }
  if (!res.ok) {
    const err = body?.error;
    throw new ApiError(err?.code ?? 'HTTP_ERROR', err?.message ?? res.statusText, res.status);
  }
  return body as T;
}

export const api = {
  params: () => req<Params>('/params'),
  status: () => req<Status>('/status'),
  account: (pkX: string) => req<AccountInfo>(`/account/${pkX}`),
  history: (pkX: string) => req<{ entries: HistoryEntry[] }>(`/history/${pkX}`),
  batches: () => req<{ batches: unknown[] }>('/batches'),
  da: (n: number) => req<Record<string, unknown>>(`/da/${n}`),
  submitTx: (tx: TxRequest) =>
    req<{ id: number; status: string }>('/tx', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(tx),
    }),
  /**
   * Intent listings are private (issue #1 L12): the sequencer requires a
   * fresh signature by the queried key as query params. Use listIntents()
   * (api/repo.ts) which builds the auth from the wallet secret.
   */
  intents: (pkX: string, auth: IntentAuth) =>
    req<{ incoming: Intent[]; outgoing: Intent[] }>(
      `/intents/${pkX}?` +
        new URLSearchParams({
          ts: auth.ts.toString(),
          pk_y: auth.pk_y,
          r_x: auth.sig.r_x,
          r_y: auth.sig.r_y,
          s_lo: auth.sig.s_lo,
          s_hi: auth.sig.s_hi,
        }).toString(),
    ),
  positions: (pkX: string) => req<{ positions: Position[] }>(`/positions/${pkX}`),
  submitIntent: (intent: IntentRequest) =>
    req<{ id: number; status: string }>('/intent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(intent),
    }),
  acceptIntent: (id: number, sig: WireSig) =>
    req<{ id: number; status: string }>(`/intent/${id}/accept`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sig }),
    }),
  close: (close: CloseRequest) =>
    req<{ id: number; status: string }>('/close', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(close),
    }),
};

/** GET /account, returning null on a 404 (unknown/unfunded account). */
export async function accountOrNull(pkX: string): Promise<AccountInfo | null> {
  try {
    return await api.account(pkX);
  } catch (e) {
    if (e instanceof ApiError && e.httpStatus === 404) return null;
    throw e;
  }
}
