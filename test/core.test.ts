import { expect, it, vi } from 'vitest';
import {
  applyHeaderProtection,
  decodeVarint,
  HEADER_PROTECTION_MASK_LENGTH,
  InvalidHeaderError,
  InvalidHeaderProtectionMaskError,
  removeHeaderProtection,
  SampleTooShortError,
  type HeaderProtectionMasker,
} from '../src/index.js';

const MASK = Uint8Array.from([0x1f, 0x2e, 0x3d, 0x4c, 0x5b]);
const SAMPLE = Uint8Array.from(Array.from({ length: 16 }, (_, i) => 0xa0 + i));

class FakeHeaderProtection implements HeaderProtectionMasker {
  mask = vi.fn((sample: Uint8Array) => {
    expect(sample).toEqual(SAMPLE);
    return MASK.slice();
  });
}

function payload(plainPacketNumber: number[], length: number = 20) {
  const result = new Uint8Array(length);
  result.fill(0x77);
  plainPacketNumber.forEach((byte, index) => {
    result[index] = byte;
  });
  SAMPLE.forEach((byte, index) => {
    if (index < length - 4) result[index + 4] = byte;
  });
  return result;
}

function xorPacketNumber(packet: Uint8Array, offset: number, length: number) {
  for (let i = 0; i < length; i++) packet[offset + i] ^= MASK[i + 1];
}

function makeShortPacket(
  firstByte: number,
  packetNumber: number[],
  payloadLength = 20,
  dcidLength = 3,
) {
  const packet = new Uint8Array(1 + dcidLength + payloadLength);
  packet[0] = firstByte;
  packet.fill(0x55, 1, 1 + dcidLength);
  packet.set(payload(packetNumber, payloadLength), 1 + dcidLength);
  return packet;
}

function protectShort(packet: Uint8Array, packetNumberOffset: number, length: number) {
  const protectedPacket = packet.slice();
  protectedPacket[0] ^= MASK[0] & 0x1f;
  xorPacketNumber(protectedPacket, packetNumberOffset, length);
  return protectedPacket;
}

function makeHandshakePacket(
  firstByte: number,
  packetNumber: number[],
  options: { physicalPayloadLength?: number; encodedPayloadLength?: number } = {},
) {
  const physicalPayloadLength = options.physicalPayloadLength ?? 20;
  const encodedPayloadLength = options.encodedPayloadLength ?? physicalPayloadLength;
  const packet = new Uint8Array(11 + physicalPayloadLength);
  packet[0] = firstByte;
  packet.set([0x00, 0x00, 0x00, 0x01], 1);
  packet[5] = 1;
  packet[6] = 0x11;
  packet[7] = 2;
  packet[8] = 0x22;
  packet[9] = 0x33;
  packet[10] = encodedPayloadLength;
  packet.set(payload(packetNumber, physicalPayloadLength), 11);
  return packet;
}

function protectLong(packet: Uint8Array, packetNumberOffset: number, length: number) {
  const protectedPacket = packet.slice();
  protectedPacket[0] ^= MASK[0] & 0x0f;
  xorPacketNumber(protectedPacket, packetNumberOffset, length);
  return protectedPacket;
}

function makeInitialPacket(firstByte: number, packetNumber: number[]) {
  const packet = new Uint8Array(13 + 20);
  packet[0] = firstByte;
  packet.set([0x00, 0x00, 0x00, 0x01], 1);
  packet[5] = 1;
  packet[6] = 0x11;
  packet[7] = 2;
  packet[8] = 0x22;
  packet[9] = 0x33;
  packet[10] = 1;
  packet[11] = 0xaa;
  packet[12] = 20;
  packet.set(payload(packetNumber), 13);
  return packet;
}

it('decodes', () =>
  expect(decodeVarint(Uint8Array.from([37]))?.value).toBe(37n));

it.each([
  [1, [0xde], 0x5c],
  [2, [0xde, 0xad], 0x5d],
  [3, [0xde, 0xad, 0xbe], 0x5e],
  [4, [0xde, 0xad, 0xbe, 0xef], 0x5f],
])('removes and reapplies short-header protection for PN length %d', (length, packetNumber, firstByte) => {
  const masker = new FakeHeaderProtection();
  const clearPacket = makeShortPacket(firstByte, packetNumber);
  const protectedPacket = protectShort(clearPacket, 4, length);

  const unprotected = removeHeaderProtection(protectedPacket, masker, {
    destinationConnectionIdLength: 3,
  });

  expect(unprotected).toEqual(clearPacket);
  expect(unprotected[0]).toBe(firstByte);
  expect(masker.mask).toHaveBeenCalledTimes(1);
  expect(applyHeaderProtection(unprotected, masker, {
    destinationConnectionIdLength: 3,
  })).toEqual(protectedPacket);
});

it.each([
  [1, [0xde], 0xec],
  [2, [0xde, 0xad], 0xed],
  [3, [0xde, 0xad, 0xbe], 0xee],
  [4, [0xde, 0xad, 0xbe, 0xef], 0xef],
])('removes and reapplies long-header protection for PN length %d', (length, packetNumber, firstByte) => {
  const masker = new FakeHeaderProtection();
  const clearPacket = makeHandshakePacket(firstByte, packetNumber);
  const protectedPacket = protectLong(clearPacket, 11, length);

  const unprotected = removeHeaderProtection(protectedPacket, masker);

  expect(unprotected).toEqual(clearPacket);
  expect(unprotected[0]).toBe(firstByte);
  expect(masker.mask).toHaveBeenCalledTimes(1);
  expect(applyHeaderProtection(unprotected, masker)).toEqual(protectedPacket);
});

it('skips the Initial token when locating the fixed long-header sample', () => {
  const masker = new FakeHeaderProtection();
  const clearPacket = makeInitialPacket(0xcc, [0xde]);
  const protectedPacket = protectLong(clearPacket, 13, 1);

  expect(removeHeaderProtection(protectedPacket, masker)).toEqual(clearPacket);
  expect(applyHeaderProtection(clearPacket, masker)).toEqual(protectedPacket);
});

it('uses five mask bits for short headers, including reserved and key-phase bits', () => {
  const masker = new FakeHeaderProtection();
  // Fixed + both reserved bits + key phase + PN length 1.
  const clearPacket = makeShortPacket(0x5c, [0x12]);
  const protectedPacket = protectShort(clearPacket, 4, 1);

  // The spin bit and fixed bit are outside the protected five bits.
  expect(protectedPacket[0]).toBe(0x43);
  const unprotected = removeHeaderProtection(protectedPacket, masker, {
    destinationConnectionIdLength: 3,
  });
  expect(unprotected[0]).toBe(0x5c);
  expect(unprotected[0] & 0x04).toBe(0x04);
  expect(unprotected[0] & 0x18).toBe(0x18);
});

it('uses four mask bits for long headers, leaving type bits unprotected', () => {
  const masker = new FakeHeaderProtection();
  // QUIC v1 Handshake, both reserved bits set, PN length 1.
  const clearPacket = makeHandshakePacket(0xec, [0x12]);
  const protectedPacket = protectLong(clearPacket, 11, 1);

  expect(protectedPacket[0]).toBe(0xe3);
  const unprotected = removeHeaderProtection(protectedPacket, masker);
  expect(unprotected[0]).toBe(0xec);
  expect(unprotected[0] & 0xf0).toBe(0xe0);
});

it('accepts the shortest payload that can contain a 16-byte sample', () => {
  const masker = new FakeHeaderProtection();

  const shortPacket = protectShort(makeShortPacket(0x40, [0x01], 20, 0), 1, 1);
  expect(removeHeaderProtection(shortPacket, masker, {
    destinationConnectionIdLength: 0,
  })).toEqual(makeShortPacket(0x40, [0x01], 20, 0));

  const longPacket = protectLong(makeHandshakePacket(0xe0, [0x01]), 11, 1);
  expect(removeHeaderProtection(longPacket, masker)).toEqual(
    makeHandshakePacket(0xe0, [0x01]),
  );
});

it('returns a specialized error when a short-header sample is truncated', () => {
  const masker = new FakeHeaderProtection();
  const packet = protectShort(makeShortPacket(0x40, [0x01], 19), 4, 1);

  expect(() => removeHeaderProtection(packet, masker, {
    destinationConnectionIdLength: 3,
  })).toThrowError(new SampleTooShortError(8, 15));
});

it('returns a specialized error when the long-header encoded payload truncates the sample', () => {
  const masker = new FakeHeaderProtection();
  const clearPacket = makeHandshakePacket(0xe0, [0x01], {
    physicalPayloadLength: 19,
    encodedPayloadLength: 19,
  });
  const packet = protectLong(clearPacket, 11, 1);

  expect(() => removeHeaderProtection(packet, masker)).toThrowError(
    new SampleTooShortError(15, 15),
  );
});

it('returns a specialized error when packet bytes physically truncate the sample', () => {
  const masker = new FakeHeaderProtection();
  const clearPacket = makeHandshakePacket(0xe0, [0x01], {
    physicalPayloadLength: 19,
    encodedPayloadLength: 20,
  });
  const packet = protectLong(clearPacket, 11, 1);

  expect(() => removeHeaderProtection(packet, masker)).toThrowError(
    new SampleTooShortError(15, 15),
  );
});

it('does not mutate the input packet', () => {
  const masker = new FakeHeaderProtection();
  const clearPacket = makeShortPacket(0x40, [0x01]);
  const protectedPacket = protectShort(clearPacket, 4, 1);
  const protectedCopy = protectedPacket.slice();
  const clearCopy = clearPacket.slice();

  removeHeaderProtection(protectedPacket, masker, {
    destinationConnectionIdLength: 3,
  });
  applyHeaderProtection(clearPacket, masker, {
    destinationConnectionIdLength: 3,
  });

  expect(protectedPacket).toEqual(protectedCopy);
  expect(clearPacket).toEqual(clearCopy);
});

it('reports an invalid injected mask', () => {
  const masker = {
    mask: () => new Uint8Array(HEADER_PROTECTION_MASK_LENGTH - 1),
  };
  const packet = makeShortPacket(0x40, [0x01]);

  expect(() => removeHeaderProtection(packet, masker, {
    destinationConnectionIdLength: 3,
  })).toThrowError(new InvalidHeaderProtectionMaskError(4));
});

it('rejects a retry packet because it has no packet number', () => {
  const packet = new Uint8Array(30);
  packet.set([0xf0, 0, 0, 0, 1, 0, 0]);
  expect(() => removeHeaderProtection(packet, new FakeHeaderProtection()))
    .toThrowError(InvalidHeaderError);
});
