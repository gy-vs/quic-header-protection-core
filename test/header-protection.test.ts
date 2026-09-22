import {describe, expect, it} from 'vitest';
import {
  SAMPLE_LENGTH,
  applyHeaderProtection,
  removeHeaderProtection,
  type HeaderLocation,
  type HeaderProtectionMasker,
  HeaderProtectionError,
  SampleTooShortError,
} from '../src/index.js';

/** Deterministic stand-in for the AES-ECB / ChaCha20 mask primitive. */
class SimulatedMasker implements HeaderProtectionMasker {
  readonly calls: Uint8Array[] = [];
  mask(sample: Uint8Array): Uint8Array {
    this.calls.push(Uint8Array.from(sample));
    const m = new Uint8Array(5);
    for (let i = 0; i < SAMPLE_LENGTH; i++) {
      m[i % 5] ^= (sample[i] * 7 + i * 13) & 0xff;
    }
    return m;
  }
}

type PnLength = 1 | 2 | 3 | 4;

function pnBytes(pn: number, len: PnLength): number[] {
  const out: number[] = [];
  for (let i = len - 1; i >= 0; i--) out.push((pn >>> (8 * i)) & 0xff);
  return out;
}

function payload(len: number): number[] {
  return Array.from({length: len}, (_, i) => (i * 31 + 7) & 0xff);
}

function encodeVarint(v: number): number[] {
  if (v < 64) return [v];
  if (v < 1 << 14) return [0x40 | (v >>> 8), v & 0xff];
  if (v < 1 << 30) {
    return [0x80 | (v >>> 24), (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
  }
  throw new Error('test varint too large');
}

interface BuiltPacket {
  packet: number[];
  pnOffset: number;
  dcidLength: number;
}

function buildShort(
  opts: {pnLen: PnLength; pn: number; payloadLen: number; reserved?: number; kp?: boolean; spin?: number; dcidLen?: number},
): BuiltPacket {
  const dcidLen = opts.dcidLen ?? 8;
  const first =
    0x40 |
    ((opts.spin ?? 0) << 5) |
    ((opts.reserved ?? 0) << 3) |
    ((opts.kp ?? false) ? 0x04 : 0) |
    (opts.pnLen - 1);
  const dcid = Array.from({length: dcidLen}, (_, i) => 0xa0 + i);
  return {
    packet: [first, ...dcid, ...pnBytes(opts.pn, opts.pnLen), ...payload(opts.payloadLen)],
    pnOffset: 1 + dcidLen,
    dcidLength: dcidLen,
  };
}

const LONG_TYPES = {initial: 0, 'zero-rtt': 1, handshake: 2} as const;
type LongTypeName = keyof typeof LONG_TYPES;

function buildLong(
  opts: {
    pnLen: PnLength;
    pn: number;
    payloadLen: number;
    type?: LongTypeName;
    reserved?: number;
    token?: number[];
    dcid?: number[];
    scid?: number[];
  },
): BuiltPacket & {type: LongTypeName} {
  const type = opts.type ?? 'initial';
  const dcid = opts.dcid ?? [0xd0, 0xd1, 0xd2, 0xd3];
  const scid = opts.scid ?? [0xc0, 0xc1];
  const token = type === 'initial' ? (opts.token ?? [0x74, 0x6f, 0x6b]) : [];
  const first = 0xc0 | (LONG_TYPES[type] << 4) | ((opts.reserved ?? 0) << 2) | (opts.pnLen - 1);

  const bytes = [
    first,
    0x00, 0x00, 0x00, 0x01, // version 1
    dcid.length, ...dcid,
    scid.length, ...scid,
  ];
  if (type === 'initial') bytes.push(...encodeVarint(token.length), ...token);
  bytes.push(...encodeVarint(opts.pnLen + opts.payloadLen));
  const pnOffset = bytes.length;
  bytes.push(...pnBytes(opts.pn, opts.pnLen), ...payload(opts.payloadLen));
  return {packet: bytes, pnOffset, dcidLength: dcid.length, type};
}

/** Produce an on-wire (protected) packet the way a peer would send it. */
function protect(clear: Uint8Array, location: HeaderLocation): Uint8Array {
  const wire = clear.slice();
  applyHeaderProtection(wire, new SimulatedMasker(), location);
  return wire;
}

const PN_VALUES: ReadonlyArray<[PnLength, number]> = [
  [1, 0xab],
  [2, 0x1234],
  [3, 0x123456],
  [4, 0x12345678],
];

describe('removeHeaderProtection / applyHeaderProtection', () => {
  for (const [pnLen, pn] of PN_VALUES) {
    for (const form of ['short', 'long'] as const) {
      it(`round-trips PN length ${pnLen} on a ${form} header`, () => {
        const built =
          form === 'short'
            ? buildShort({pnLen, pn, payloadLen: 24, reserved: 2, kp: true})
            : buildLong({pnLen, pn, payloadLen: 24, reserved: 2});
        const clear = Uint8Array.from(built.packet);
        const location: HeaderLocation = {headerForm: form, pnOffset: built.pnOffset, pnLength: pnLen};
        const wire = protect(clear, location);

        const received = wire.slice();
        const result = removeHeaderProtection(
          received,
          new SimulatedMasker(),
          form === 'short' ? {dcidLength: built.dcidLength} : {},
        );

        expect(result.headerForm).toBe(form);
        expect(result.pnLength).toBe(pnLen);
        expect(result.packetNumber).toBe(pn);
        expect(result.reservedBits).toBe(2);
        // Unprotection recovers the original cleartext packet.
        expect(received).toEqual(clear);

        // Re-applying protection restores the original on-wire header bytes.
        applyHeaderProtection(received, new SimulatedMasker(), result);
        expect(received).toEqual(wire);
      });
    }
  }

  it('derives the mask from the fixed pn_offset+4 sample before reading PN length (regression)', () => {
    const pnLen = 4;
    const built = buildShort({pnLen, pn: 0xdeadbeef, payloadLen: 32, dcidLen: 8});
    const clear = Uint8Array.from(built.packet);
    const masker = new SimulatedMasker();

    // The correct sample starts exactly 4 bytes after the PN offset...
    const correctSample = clear.subarray(built.pnOffset + 4, built.pnOffset + 4 + SAMPLE_LENGTH);
    const goodMask = masker.mask(correctSample);
    // ...not after the (protected) PN length was wrongly used as an offset.
    const staleSample = clear.subarray(
      built.pnOffset + pnLen + 4,
      built.pnOffset + pnLen + 4 + SAMPLE_LENGTH,
    );
    const staleMask = masker.mask(staleSample);
    expect(Array.from(goodMask)).not.toEqual(Array.from(staleMask));

    const wire = protect(clear, {headerForm: 'short', pnOffset: built.pnOffset, pnLength: pnLen});
    const received = wire.slice();
    const result = removeHeaderProtection(received, new SimulatedMasker(), {
      dcidLength: built.dcidLength,
    });
    expect(result.pnLength).toBe(pnLen);
    expect(result.packetNumber).toBe(0xdeadbeef);
    expect(received).toEqual(clear);
  });

  it('protects only the low nibble of a long-header first byte', () => {
    const built = buildLong({pnLen: 2, pn: 0x7fff, payloadLen: 24, reserved: 3});
    const clear = Uint8Array.from(built.packet);
    const masker = new SimulatedMasker();
    const mask = masker.mask(
      clear.subarray(built.pnOffset + 4, built.pnOffset + 4 + SAMPLE_LENGTH),
    );
    const wire = protect(clear, {headerForm: 'long', pnOffset: built.pnOffset, pnLength: 2});

    // High nibble (form/fixed/type) is untouched; low nibble follows mask & 0x0f.
    expect(wire[0] & 0xf0).toBe(clear[0] & 0xf0);
    expect(wire[0]).toBe(clear[0] ^ (mask[0] & 0x0f));
    if ((mask[0] & 0x0f) !== 0) {
      expect(wire[0] & 0x0f).not.toBe(clear[0] & 0x0f);
    }

    const received = wire.slice();
    const result = removeHeaderProtection(received, new SimulatedMasker());
    expect(result.headerForm).toBe('long');
    expect(result.packetType).toBe('initial');
    expect(result.keyPhase).toBeUndefined();
    expect(result.reservedBits).toBe(3);
    expect(result.packetNumber).toBe(0x7fff);
  });

  it('protects the low five bits (including key phase) of a short-header first byte', () => {
    const built = buildShort({pnLen: 1, pn: 0x42, payloadLen: 24, reserved: 1, kp: true, spin: 1});
    const clear = Uint8Array.from(built.packet);
    const masker = new SimulatedMasker();
    const mask = masker.mask(
      clear.subarray(built.pnOffset + 4, built.pnOffset + 4 + SAMPLE_LENGTH),
    );
    const wire = protect(clear, {headerForm: 'short', pnOffset: built.pnOffset, pnLength: 1});

    // Form/fixed/spin bits survive; the protected five bits follow mask & 0x1f.
    expect(wire[0] & 0xe0).toBe(clear[0] & 0xe0);
    expect(wire[0]).toBe(clear[0] ^ (mask[0] & 0x1f));
    if ((mask[0] & 0x1f) !== 0) {
      expect(wire[0] & 0x1f).not.toBe(clear[0] & 0x1f);
    }

    const result = removeHeaderProtection(wire.slice(), new SimulatedMasker(), {
      dcidLength: built.dcidLength,
    });
    expect(result.keyPhase).toBe(true);
    expect(result.reservedBits).toBe(1);
    expect(result.packetNumber).toBe(0x42);
  });

  it('reports key phase 0 when the bit is clear', () => {
    const built = buildShort({pnLen: 3, pn: 1, payloadLen: 24, kp: false});
    const wire = protect(Uint8Array.from(built.packet), {
      headerForm: 'short',
      pnOffset: built.pnOffset,
      pnLength: 3,
    });
    const result = removeHeaderProtection(wire, new SimulatedMasker(), {
      dcidLength: built.dcidLength,
    });
    expect(result.keyPhase).toBe(false);
  });

  it('accepts the shortest payload that still yields a full 16-byte sample', () => {
    for (const [pnLen, pn] of PN_VALUES) {
      const built = buildShort({pnLen, pn, payloadLen: 20 - pnLen});
      const wire = protect(Uint8Array.from(built.packet), {
        headerForm: 'short',
        pnOffset: built.pnOffset,
        pnLength: pnLen,
      });
      const result = removeHeaderProtection(wire, new SimulatedMasker(), {
        dcidLength: built.dcidLength,
      });
      expect(result.sampleOffset).toBe(built.pnOffset + 4);
      expect(result.packetNumber).toBe(pn);
    }
  });

  it('raises a dedicated error when the sample is truncated by one byte', () => {
    // Short headers carry no Length field, so the shortfall is detected
    // precisely while reading the 16-byte mask sample.
    const pnLen = 4;
    const built = buildShort({pnLen, pn: 1, payloadLen: 20 - pnLen});
    const full = Uint8Array.from(built.packet);
    applyHeaderProtection(full, new SimulatedMasker(), {
      headerForm: 'short',
      pnOffset: built.pnOffset,
      pnLength: pnLen,
    });
    const truncated = full.subarray(0, full.length - 1);

    try {
      removeHeaderProtection(truncated, new SimulatedMasker(), {
        dcidLength: built.dcidLength,
      });
      throw new Error('expected SampleTooShortError');
    } catch (err) {
      expect(err).toBeInstanceOf(SampleTooShortError);
      expect(err).toBeInstanceOf(HeaderProtectionError);
      const e = err as SampleTooShortError;
      expect(e.sampleOffset).toBe(built.pnOffset + 4);
      expect(e.packetLength).toBe(truncated.length);
      expect(e.required).toBe(SAMPLE_LENGTH);
    }
  });

  it('locates the PN in an Initial packet across the length-prefixed token', () => {
    // 200-byte token exercises the 2-byte QUIC varint form for token length.
    const token = Array.from({length: 200}, (_, i) => i & 0xff);
    const built = buildLong({pnLen: 3, pn: 0xabcdef, payloadLen: 24, token});
    const wire = protect(Uint8Array.from(built.packet), {
      headerForm: 'long',
      pnOffset: built.pnOffset,
      pnLength: 3,
    });
    const result = removeHeaderProtection(wire, new SimulatedMasker());
    expect(result.packetType).toBe('initial');
    expect(result.pnOffset).toBe(built.pnOffset);
    expect(result.packetNumber).toBe(0xabcdef);
  });

  it('handles Handshake and 0-RTT long headers (no token field)', () => {
    for (const type of ['handshake', 'zero-rtt'] as const) {
      const built = buildLong({pnLen: 2, pn: 0x9001, payloadLen: 24, type});
      const wire = protect(Uint8Array.from(built.packet), {
        headerForm: 'long',
        pnOffset: built.pnOffset,
        pnLength: 2,
      });
      const result = removeHeaderProtection(wire, new SimulatedMasker());
      expect(result.packetType).toBe(type);
      expect(result.packetNumber).toBe(0x9001);
    }
  });

  it('rejects Retry and Version Negotiation packets, which carry no PN', () => {
    const retry = Uint8Array.from([
      0xf0, 0, 0, 0, 1, 4, 0xd0, 0xd1, 0xd2, 0xd3, 0, 1, 2, 3, 4,
    ]);
    expect(() => removeHeaderProtection(retry, new SimulatedMasker())).toThrowError(/Retry/);

    const vn = Uint8Array.from([
      0x80, 0, 0, 0, 0, 4, 0xd0, 0xd1, 0xd2, 0xd3, 0,
    ]);
    expect(() => removeHeaderProtection(vn, new SimulatedMasker())).toThrowError(
      /Version Negotiation/,
    );
  });

  it('requires dcidLength for short headers', () => {
    const built = buildShort({pnLen: 1, pn: 1, payloadLen: 24});
    const wire = protect(Uint8Array.from(built.packet), {
      headerForm: 'short',
      pnOffset: built.pnOffset,
      pnLength: 1,
    });
    expect(() => removeHeaderProtection(wire, new SimulatedMasker())).toThrowError(/dcidLength/);
  });

  it('injects the exact fixed-offset payload bytes as the mask primitive input', () => {
    const built = buildShort({pnLen: 4, pn: 0x01020304, payloadLen: 28});
    const clear = Uint8Array.from(built.packet);
    const wire = protect(clear, {headerForm: 'short', pnOffset: built.pnOffset, pnLength: 4});

    const masker = new SimulatedMasker();
    removeHeaderProtection(wire, masker, {dcidLength: built.dcidLength});
    expect(masker.calls).toHaveLength(1);
    // Sample comes from the (unchanged) ciphertext at pn_offset + 4.
    expect(masker.calls[0]).toEqual(
      clear.subarray(built.pnOffset + 4, built.pnOffset + 4 + SAMPLE_LENGTH),
    );
  });

  it('errors when the injected primitive returns a mask shorter than 5 bytes', () => {
    const built = buildShort({pnLen: 1, pn: 1, payloadLen: 24});
    const shortMasker: HeaderProtectionMasker = {
      mask: () => Uint8Array.from([1, 2, 3]),
    };
    expect(() =>
      removeHeaderProtection(Uint8Array.from(built.packet), shortMasker, {
        dcidLength: built.dcidLength,
      }),
    ).toThrowError(HeaderProtectionError);
  });

  it('leaves the encrypted payload untouched through protect/unprotect cycles', () => {
    const built = buildLong({pnLen: 2, pn: 0x5555, payloadLen: 30});
    const clear = Uint8Array.from(built.packet);
    const payloadStart = built.pnOffset + 2;
    const payloadBefore = clear.slice(payloadStart);

    const wire = clear.slice();
    applyHeaderProtection(wire, new SimulatedMasker(), {
      headerForm: 'long',
      pnOffset: built.pnOffset,
      pnLength: 2,
    });
    expect(wire.slice(payloadStart)).toEqual(payloadBefore);

    removeHeaderProtection(wire, new SimulatedMasker());
    expect(wire.slice(payloadStart)).toEqual(payloadBefore);
  });
});
