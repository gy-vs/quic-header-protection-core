export function decodeVarint(data:Uint8Array,offset=0){const size=1<<(data[offset]>>6);if(data.length<offset+size)return null;let value=BigInt(data[offset]&63);for(let i=1;i<size;i++)value=(value<<8n)|BigInt(data[offset+i]);return{value,size}}export type Range={start:bigint;end:bigint};export function addPacket(ranges:Range[],packet:bigint){return[...ranges,{start:packet,end:packet}].sort((a,b)=>a.start>b.start?-1:1)}

// QUIC header protection (RFC 9001, Section 5.4).
//
// The 16-byte mask sample is ALWAYS taken from the ciphertext at
// pn_offset + 4, regardless of the packet number length. Because the low
// bits of the first byte (which encode the PN length) are themselves
// protected, they must not be read until the first byte has been
// unprotected. Processing order is therefore:
//
//   1. locate the packet number offset (from cleartext header fields)
//   2. take the sample at the fixed offset and derive the 5-byte mask
//   3. unprotect the first byte (mask 0x0f long / 0x1f short)
//   4. read the PN length, then unprotect exactly that many PN bytes

export const SAMPLE_LENGTH = 16;
const SAMPLE_RELATIVE_OFFSET = 4;
const MASK_LENGTH = 5;

/** Bits of the first byte covered by header protection. */
const FIRST_BYTE_MASK_LONG = 0x0f;  // reserved(2) + packet number length(2)
const FIRST_BYTE_MASK_SHORT = 0x1f; // reserved(2) + key phase(1) + PN length(2)

/**
 * Crypto primitive behind header protection. Implementations derive the
 * mask from the 16-byte sample:
 *   - AES-128/256-ECB encryption of the sample (for AEAD_AES_128/256_GCM
 *     and AEAD_AES_128_CCM cipher suites);
 *   - the first 5 bytes of the ChaCha20 block with the sample as nonce and
 *     block counter 0 (for CHACHA20_POLY1305).
 */
export interface HeaderProtectionMasker {
  mask(sample: Uint8Array): Uint8Array;
}

export type HeaderForm = 'long' | 'short';
export type LongPacketType = 'initial' | 'zero-rtt' | 'handshake';

/** Everything needed to (re)apply protection to a located packet number. */
export interface HeaderLocation {
  headerForm: HeaderForm;
  /** Offset of the first packet number byte. */
  pnOffset: number;
  pnLength: 1 | 2 | 3 | 4;
}

export interface RemovedProtection extends HeaderLocation {
  packetType?: LongPacketType;
  /** Decoded packet number (big-endian, at most 32 bits). */
  packetNumber: number;
  /** Value of the two reserved bits after unprotection (must be 0). */
  reservedBits: number;
  /** Key phase bit; only present on short-header (1-RTT) packets. */
  keyPhase?: boolean;
  /** Offset at which the 16-byte mask sample starts. */
  sampleOffset: number;
}

export interface RemoveProtectionOptions {
  /**
   * Length of the destination connection ID. Required for short-header
   * packets, whose DCID is not length-prefixed; ignored for long headers.
   */
  dcidLength?: number;
}

export class HeaderProtectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HeaderProtectionError';
  }
}

/** Raised when fewer than 16 ciphertext bytes are available for the sample. */
export class SampleTooShortError extends HeaderProtectionError {
  constructor(
    readonly sampleOffset: number,
    readonly packetLength: number,
    readonly required: number = SAMPLE_LENGTH,
  ) {
    super(
      `header protection sample needs ${required} bytes at offset ${sampleOffset}, ` +
      `but the packet is only ${packetLength} bytes long`,
    );
    this.name = 'SampleTooShortError';
  }
}

/**
 * Remove QUIC header protection from `packet`, mutating it in place, and
 * return the decoded packet number fields.
 *
 * The mask is derived from the fixed sample offset before any protected
 * bit (in particular the PN length) is inspected.
 */
export function removeHeaderProtection(
  packet: Uint8Array,
  masker: HeaderProtectionMasker,
  options: RemoveProtectionOptions = {},
): RemovedProtection {
  const location = locatePacketNumber(packet, options);

  // Fixed sample offset; does not depend on the packet number length.
  const sample = takeSample(packet, location.pnOffset);
  const mask = requireMask(masker, sample);

  // 1. Unprotect the first byte, then read the PN length it carries.
  const firstByteMask =
    location.headerForm === 'long' ? FIRST_BYTE_MASK_LONG : FIRST_BYTE_MASK_SHORT;
  packet[0] ^= mask[0] & firstByteMask;
  const pnLength = ((packet[0] & 0x03) + 1) as 1 | 2 | 3 | 4;
  location.pnLength = pnLength;

  // 2. Unprotect only the actual packet number bytes.
  let packetNumber = 0;
  for (let i = 0; i < pnLength; i++) {
    const byte = packet[location.pnOffset + i] ^ mask[1 + i];
    packet[location.pnOffset + i] = byte;
    packetNumber = ((packetNumber << 8) | byte) >>> 0;
  }

  const first = packet[0];
  const reservedBits =
    location.headerForm === 'long'
      ? (first >> 2) & 0x03 // long: low nibble is RR + PN-length
      : (first >> 3) & 0x03; // short: low five bits are RR + KP + PN-length

  const result: RemovedProtection = {
    headerForm: location.headerForm,
    packetType: location.packetType,
    pnOffset: location.pnOffset,
    pnLength,
    packetNumber,
    reservedBits,
    sampleOffset: location.pnOffset + SAMPLE_RELATIVE_OFFSET,
  };
  if (location.headerForm === 'short') {
    result.keyPhase = ((first >> 2) & 0x01) === 1;
  }
  return result;
}

/**
 * Re-apply header protection to `packet` in place using the same masker.
 * The packet number and payload bytes must sit at `location.pnOffset`;
 * the encrypted payload (and therefore the sample) is untouched by header
 * protection, so removing and re-applying protection round-trips exactly.
 */
export function applyHeaderProtection(
  packet: Uint8Array,
  masker: HeaderProtectionMasker,
  location: HeaderLocation,
): void {
  const sample = takeSample(packet, location.pnOffset);
  const mask = requireMask(masker, sample);

  // Packet number bytes first, then the first byte (RFC 9001 A.4/A.5).
  for (let i = 0; i < location.pnLength; i++) {
    packet[location.pnOffset + i] ^= mask[1 + i];
  }
  const firstByteMask =
    location.headerForm === 'long' ? FIRST_BYTE_MASK_LONG : FIRST_BYTE_MASK_SHORT;
  packet[0] ^= mask[0] & firstByteMask;
}

/** Read the fixed-offset 16-byte sample or raise the dedicated error. */
function takeSample(packet: Uint8Array, pnOffset: number): Uint8Array {
  const sampleOffset = pnOffset + SAMPLE_RELATIVE_OFFSET;
  if (packet.length - sampleOffset < SAMPLE_LENGTH) {
    throw new SampleTooShortError(sampleOffset, packet.length);
  }
  return packet.subarray(sampleOffset, sampleOffset + SAMPLE_LENGTH);
}

function requireMask(masker: HeaderProtectionMasker, sample: Uint8Array): Uint8Array {
  const mask = masker.mask(sample);
  if (!mask || mask.length < MASK_LENGTH) {
    throw new HeaderProtectionError(
      `header protection masker returned ${mask ? mask.length : 0} bytes, need ${MASK_LENGTH}`,
    );
  }
  return mask;
}

interface LocatedHeader {
  headerForm: HeaderForm;
  packetType?: LongPacketType;
  pnOffset: number;
  pnLength?: 1 | 2 | 3 | 4;
}

/** Find the packet number offset using only cleartext header fields. */
function locatePacketNumber(
  packet: Uint8Array,
  options: RemoveProtectionOptions,
): LocatedHeader {
  if (packet.length < 1) {
    throw new HeaderProtectionError('empty packet');
  }
  if ((packet[0] & 0x80) === 0) {
    // Short header: first byte followed by the (unframed) destination CID.
    if (options.dcidLength === undefined) {
      throw new HeaderProtectionError(
        'dcidLength is required to locate the packet number in a short header',
      );
    }
    const pnOffset = 1 + options.dcidLength;
    if (packet.length < pnOffset) {
      throw new HeaderProtectionError('short header is truncated before the packet number');
    }
    return {headerForm: 'short', pnOffset};
  }

  // Long header: version (4), DCID (len-prefixed), SCID (len-prefixed),
  // then type-specific fields.
  if (packet.length < 7) {
    throw new HeaderProtectionError('long header is truncated');
  }
  if (packet.subarray(1, 5).every((b) => b === 0)) {
    throw new HeaderProtectionError('Version Negotiation packets have no packet number');
  }
  const typeCode = (packet[0] >> 4) & 0x03;
  if (typeCode === 3) {
    throw new HeaderProtectionError('Retry packets have no packet number');
  }
  const packetType: LongPacketType =
    typeCode === 0 ? 'initial' : typeCode === 1 ? 'zero-rtt' : 'handshake';

  let offset = 5;
  offset = skipConnectionId(packet, offset, 'destination');
  offset = skipConnectionId(packet, offset, 'source');

  // Initial packets carry a length-prefixed token before the Length field.
  if (packetType === 'initial') {
    const tokenLength = readVarint(packet, offset, 'token length');
    offset += tokenLength.size + Number(tokenLength.value);
    if (packet.length < offset) {
      throw new HeaderProtectionError('Initial packet token is truncated');
    }
  }

  const restLength = readVarint(packet, offset, 'payload length');
  offset += restLength.size;
  if (packet.length < offset + Number(restLength.value)) {
    throw new HeaderProtectionError('long header payload is truncated');
  }

  return {headerForm: 'long', packetType, pnOffset: offset};
}

function skipConnectionId(packet: Uint8Array, offset: number, label: string): number {
  if (packet.length <= offset) {
    throw new HeaderProtectionError(`long header is truncated before the ${label} CID length`);
  }
  const next = offset + 1 + packet[offset];
  if (packet.length < next) {
    throw new HeaderProtectionError(`long header is truncated in the ${label} connection ID`);
  }
  return next;
}

function readVarint(packet: Uint8Array, offset: number, label: string) {
  const decoded = decodeVarint(packet, offset);
  if (decoded === null) {
    throw new HeaderProtectionError(`long header is truncated before the ${label}`);
  }
  return decoded;
}
