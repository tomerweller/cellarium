// Issue #27: financial inputs parse exactly — no Number round-trip.
import { describe, expect, it } from 'vitest';
import { parseScaled } from './format';

describe('parseScaled', () => {
  it('parses exact decimals at the boundary', () => {
    expect(parseScaled('1', 7, 'x')).toBe(10_000_000n);
    expect(parseScaled('1.5', 7, 'x')).toBe(15_000_000n);
    expect(parseScaled('0.0000001', 7, 'x')).toBe(1n);
    expect(parseScaled('4.30', 2, 'x')).toBe(430n);
    expect(parseScaled('0', 7, 'x')).toBe(0n);
  });

  it('keeps precision beyond Number for large values', () => {
    // 18-digit token amount: Number would round this.
    expect(parseScaled('922337203.6854775', 7, 'x')).toBe(9223372036854775n);
    expect(parseScaled('90071992547409.93', 2, 'x')).toBe(9007199254740993n);
  });

  it('rejects excess precision instead of silently rounding', () => {
    expect(() => parseScaled('1.00000001', 7, 'x')).toThrow(/decimal place/);
    expect(() => parseScaled('4.301', 2, 'x')).toThrow(/decimal place/);
  });

  it('rejects scientific notation, signs, and junk', () => {
    for (const bad of ['1e3', '-1', '+1', 'NaN', 'Infinity', '', ' ', '1.', '.5', '0x10']) {
      expect(() => parseScaled(bad, 7, 'x')).toThrow();
    }
  });
});
