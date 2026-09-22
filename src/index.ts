export function decodeVarint(data: Uint8Array, offset = 0) {
  if (offset < 0 || offset >= data.length) return null;
  const size = 1 << (data[offset] >> 6);
  if (data.length < offset + size) return null;

  let value = BigInt(data[offset] & 63);
  for (let i = 1; i < size; i++) {
    value = (value << 8n) | BigInt(data[offset + i]);
  }
  return { value, size };
}

export type Range = { start: bigint; end: bigint };

export function addPacket(ranges: Range[], packet: bigint) {
  return [...ranges, { start: packet, end: packet }].sort((a, b) =>
    a.start > b.start ? -1 : 1,
  );
}

export const HEADER_PROTECTION_SAMPLE_LENGTH = 16;
export const HEADER_PROTECTION_MASK_LENGTH = 5;
/** RFC 9001: the sample starts four bytes after the start of the packet number. */
export const PACKET_NUMBER_SAMPLE_OFFSET = 4;

const LONG_HEADER_BIT = 0x80;
const FIXED_BIT = 0x40;
const LONG_HEADER_PROTECTED_BITS = 0x0f;
const SHORT_HEADER_PROTECTED_BITS = 0x1f;
const PACKET_NUMBER_LENGTH_BITS = 0x03;
const QUIC_V1 = 0x00000001;
const QUIC_V2 = 0x6b3343cf;

export class InvalidHeaderError extends Error {
  constructor(
    message: string,
    readonly offset?: number,
  ) {
    super(message);
    this.name = 'InvalidHeaderError';
  }
}

export class SampleTooShortError extends Error {
  constructor(
    readonly sampleOffset: number,
    readonly available: number,
    readonly required: number = HEADER_PROTECTION_SAMPLE_LENGTH,
  ) {
    super(
      `QUIC header protection sample needs ${required} bytes at offset ${sampleOffset}, but ${available} are available`,
    );
    this.name = 'SampleTooShortError';
  }
}

export class InvalidHeaderProtectionMaskError extends Error {
  constructor(readonly length: number) {
    super(
      `Header protection mask must contain at least ${HEADER_PROTECTION_MASK_LENGTH} bytes, received ${length}`,
    );
    this.name = 'InvalidHeaderProtectionMaskError';
  }
}

/** Injected cryptographic primitive. AES-ECB or ChaCha20 implementations supply this. */
export interface HeaderProtectionMasker {
  mask(sample: Uint8Array): Uint8Array;
}

export interface HeaderProtectionOptions {
  /**
   * Length of the short-header destination connection ID. The length is not
   * encoded in a short header, so it must be supplied by the caller.
   */
  destinationConnectionIdLength?: number;
}

type HeaderLayout = {
  isLongHeader: boolean;
  packetNumberOffset: number;
  /** Payload length as encoded in a long header, or remaining bytes for a short header. */
  payloadLength: bigint;
};

function readVarint(data: Uint8Array, offset: number, field: string) {
  const result = decodeVarint(data, offset);
  if (result === null) {
    throw new InvalidHeaderError(`truncated ${field}`, offset);
  }
  return result;
}

function requireBytes(length: number, end: number, packet: Uint8Array, field: string) {
  if (length < 0 || end > packet.length) {
    throw new InvalidHeaderError(`truncated ${field}`, Math.min(end, packet.length));
  }
}

function inspectShortHeader(
  packet: Uint8Array,
  options: HeaderProtectionOptions = {},
): HeaderLayout {
  const dcidLength = options.destinationConnectionIdLength;
  if (
    dcidLength === undefined ||
    !Number.isInteger(dcidLength) ||
    dcidLength < 0 ||
    dcidLength > 20
  ) {
    throw new InvalidHeaderError(
      'a destination connection ID length from 0 through 20 is required for short headers',
    );
  }

  // The fixed bit is not covered by header protection.
  if ((packet[0] & FIXED_BIT) === 0) {
    throw new InvalidHeaderError('short header fixed bit must be set', 0);
  }

  const packetNumberOffset = 1 + dcidLength;
  if (packetNumberOffset > packet.length) {
    throw new InvalidHeaderError('truncated destination connection ID', 1);
  }

  return {
    isLongHeader: false,
    packetNumberOffset,
    payloadLength: BigInt(packet.length - packetNumberOffset),
  };
}

function inspectLongHeader(packet: Uint8Array): HeaderLayout {
  if (packet.length < 5 || (packet[0] & FIXED_BIT) === 0) {
    throw new InvalidHeaderError('invalid long header', 0);
  }

  const version =
    (packet[1] << 24) | (packet[2] << 16) | (packet[3] << 8) | packet[4];
  if (version === 0) {
    throw new InvalidHeaderError('version negotiation is not a protected packet', 1);
  }
  if (version !== QUIC_V1 && version !== QUIC_V2) {
    throw new InvalidHeaderError(`unsupported QUIC version 0x${version.toString(16)}`, 1);
  }

  let offset = 5;
  const dcidLength = packet[offset++];
  if (dcidLength > 20) throw new InvalidHeaderError('destination connection ID is too long', offset - 1);
  requireBytes(dcidLength, offset + dcidLength, packet, 'destination connection ID');
  offset += dcidLength;

  if (offset >= packet.length) throw new InvalidHeaderError('missing source connection ID length', offset);
  const scidLength = packet[offset++];
  if (scidLength > 20) throw new InvalidHeaderError('source connection ID is too long', offset - 1);
  requireBytes(scidLength, offset + scidLength, packet, 'source connection ID');
  offset += scidLength;

  // Type bits are not protected. Retry packets do not have a packet number.
  const packetType = (packet[0] >>> 4) & 0x03;
  if (packetType === 3) {
    throw new InvalidHeaderError('retry packets do not use packet number protection', offset);
  }

  // Initial packets (both QUIC v1 and v2) contain a variable-length token.
  if (packetType === 0) {
    const tokenLength = readVarint(packet, offset, 'token length');
    offset += tokenLength.size;
    requireBytes(Number(tokenLength.value), offset + Number(tokenLength.value), packet, 'token');
    offset += Number(tokenLength.value);
  }

  const payloadLength = readVarint(packet, offset, 'payload length');
  offset += payloadLength.size;

  return {
    isLongHeader: true,
    packetNumberOffset: offset,
    payloadLength: payloadLength.value,
  };
}

function inspectHeader(packet: Uint8Array, options?: HeaderProtectionOptions): HeaderLayout {
  if (!(packet instanceof Uint8Array) || packet.length === 0) {
    throw new InvalidHeaderError('packet must be a non-empty Uint8Array');
  }
  return (packet[0] & LONG_HEADER_BIT) !== 0
    ? inspectLongHeader(packet)
    : inspectShortHeader(packet, options);
}

function readSample(packet: Uint8Array, layout: HeaderLayout): Uint8Array {
  const sampleOffset = layout.packetNumberOffset + PACKET_NUMBER_SAMPLE_OFFSET;
  const sampleEnd = sampleOffset + HEADER_PROTECTION_SAMPLE_LENGTH;

  // Do not use bytes from a following coalesced packet.
  if (layout.payloadLength < BigInt(HEADER_PROTECTION_SAMPLE_LENGTH + PACKET_NUMBER_SAMPLE_OFFSET)) {
    const available = Math.max(
      0,
      Number(layout.payloadLength) - PACKET_NUMBER_SAMPLE_OFFSET,
    );
    throw new SampleTooShortError(sampleOffset, available);
  }
  if (sampleEnd > packet.length) {
    throw new SampleTooShortError(sampleOffset, Math.max(0, packet.length - sampleOffset));
  }

  return packet.subarray(sampleOffset, sampleEnd);
}

function getMask(masker: HeaderProtectionMasker, sample: Uint8Array): Uint8Array {
  const mask = masker.mask(sample);
  if (!(mask instanceof Uint8Array) || mask.length < HEADER_PROTECTION_MASK_LENGTH) {
    throw new InvalidHeaderProtectionMaskError(mask instanceof Uint8Array ? mask.length : -1);
  }
  return mask;
}

function xorPacketNumber(packet: Uint8Array, offset: number, length: number, mask: Uint8Array) {
  for (let i = 0; i < length; i++) {
    packet[offset + i] ^= mask[i + 1];
  }
}

/**
 * Removes QUIC header protection. The mask is obtained from the fixed sample
 * before the first byte is deprotected, so the encoded PN length does not affect
 * its offset.
 */
export function removeHeaderProtection(
  packet: Uint8Array,
  masker: HeaderProtectionMasker,
  options?: HeaderProtectionOptions,
): Uint8Array {
  const layout = inspectHeader(packet, options);
  const sample = readSample(packet, layout);
  const mask = getMask(masker, sample);
  const result = packet.slice();

  result[0] ^= mask[0] & (
    layout.isLongHeader
      ? LONG_HEADER_PROTECTED_BITS
      : SHORT_HEADER_PROTECTED_BITS
  );

  // Only after unprotecting the first byte can the PN length be read.
  const packetNumberLength = (result[0] & PACKET_NUMBER_LENGTH_BITS) + 1;
  xorPacketNumber(result, layout.packetNumberOffset, packetNumberLength, mask);
  return result;
}

/** Applies QUIC header protection to a packet with a cleartext header. */
export function applyHeaderProtection(
  packet: Uint8Array,
  masker: HeaderProtectionMasker,
  options?: HeaderProtectionOptions,
): Uint8Array {
  const layout = inspectHeader(packet, options);
  const sample = readSample(packet, layout);
  const mask = getMask(masker, sample);
  const result = packet.slice();

  const packetNumberLength = (result[0] & PACKET_NUMBER_LENGTH_BITS) + 1;
  xorPacketNumber(result, layout.packetNumberOffset, packetNumberLength, mask);
  result[0] ^= mask[0] & (
    layout.isLongHeader
      ? LONG_HEADER_PROTECTED_BITS
      : SHORT_HEADER_PROTECTED_BITS
  );
  return result;
}
