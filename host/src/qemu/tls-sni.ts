/**
 * SNI extraction from a buffered TLS ClientHello record.
 *
 * Used by TLS-MITM under Bun: Bun does not support SNICallback, so the SNI
 * must be read directly from the ClientHello bytes before the MITM socket is
 * created.
 */

/** max ClientHello bytes buffered while waiting for a complete first record in `bytes` */
export const MAX_SNI_PREPARSE_BYTES = 16 * 1024;

/**
 * Extracts the SNI hostname from a buffered ClientHello TLS record.
 * Returns the hostname, `null` when more bytes are needed to complete the
 * first record, or `undefined` when the hello carries no server_name
 * extension (callers fall back to the destination IP).
 */
export function parseSniFromClientHello(
  buf: Buffer,
): string | null | undefined {
  if (buf.length < 5) return null;
  if (buf[0] !== 0x16) return undefined; // not a TLS handshake record
  const recordLen = buf.readUInt16BE(3);
  if (buf.length < 5 + recordLen) return null; // wait for the full record
  if (buf[5] !== 0x01) return undefined; // first handshake msg is not ClientHello
  const hsLen = buf.readUIntBE(6, 3);
  let p = 9;
  // A ClientHello always fits a single record in practice. If the handshake
  // message is fragmented, stop parsing: the caller will fall back to the
  // destination IP.
  const hsEnd = Math.min(5 + recordLen, 9 + hsLen);
  if (hsEnd - p < 2 + 32 + 1) return null;
  p += 2 + 32; // client version + random
  const sidLen = buf[p];
  p += 1;
  if (p + sidLen + 2 > hsEnd) return null;
  p += sidLen;
  const csLen = buf.readUInt16BE(p);
  p += 2;
  if (p + csLen + 1 > hsEnd) return null;
  p += csLen;
  const compLen = buf[p];
  p += 1;
  if (p + compLen + 2 > hsEnd) return null;
  p += compLen;
  const extLen = buf.readUInt16BE(p);
  p += 2;
  const extEnd = Math.min(p + extLen, hsEnd);
  while (p + 4 <= extEnd) {
    const extType = buf.readUInt16BE(p);
    const extLen2 = buf.readUInt16BE(p + 2);
    const bodyStart = p + 4;
    if (extType === 0x0000) {
      // server_name extension
      if (extLen2 < 5 || bodyStart + extLen2 > extEnd) return undefined;
      let q = bodyStart;
      const listLen = buf.readUInt16BE(q);
      q += 2;
      const listEnd = Math.min(q + listLen, bodyStart + extLen2);
      while (q + 3 <= listEnd) {
        const nameType = buf[q];
        q += 1;
        const nameLen = buf.readUInt16BE(q);
        q += 2;
        if (q + nameLen > listEnd) return undefined;
        if (nameType === 0 && nameLen > 0) {
          return buf.toString("latin1", q, q + nameLen);
        }
        q += nameLen;
      }
      return undefined;
    }
    p = bodyStart + extLen2;
  }
  return undefined; // no SNI extension
}
