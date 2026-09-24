import assert from "node:assert/strict";
import net from "node:net";
import tls from "node:tls";

import { test } from "node:test";

import {
  MAX_SNI_PREPARSE_BYTES,
  parseSniFromClientHello,
} from "../src/qemu/tls-sni.ts";

/** capture a real ClientHello from node's TLS client (no VM required) */
function captureClientHello(servername: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const server = net.createServer((sock) => {
      sock.on("data", (d) => {
        chunks.push(Buffer.from(d));
        sock.destroy();
        server.close();
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as { port: number };
      const client = tls.connect({
        host: "127.0.0.1",
        port,
        servername,
        ALPNProtocols: ["h2", "http/1.1"],
        rejectUnauthorized: false,
      });
      client.on("error", () => {});
      // fall back to resolving after a short delay in case data never arrives
      const timer = setTimeout(() => {
        server.close();
        resolve(Buffer.concat(chunks));
      }, 2000);
      server.on("close", () => {
        clearTimeout(timer);
        resolve(Buffer.concat(chunks));
      });
    });
  });
}

test("tls-sni: parses SNI from a real ClientHello", async () => {
  const hello = await captureClientHello("example.com");
  assert.ok(hello.length > 0, "no ClientHello captured");
  assert.equal(parseSniFromClientHello(hello), "example.com");
});

test("tls-sni: null while the first record is incomplete", async () => {
  const hello = await captureClientHello("example.com");
  assert.equal(parseSniFromClientHello(hello.subarray(0, 10)), null);
  // every strict prefix must report "need more bytes"
  for (let i = 1; i < hello.length - 1; i++) {
    assert.equal(parseSniFromClientHello(hello.subarray(0, i)), null);
  }
  // and the complete buffer yields the hostname
  assert.equal(parseSniFromClientHello(hello), "example.com");
});

test("tls-sni: undefined for non-TLS payload", () => {
  assert.equal(
    parseSniFromClientHello(Buffer.from("GET / HTTP/1.1\r\n\r\n")),
    undefined,
  );
  assert.equal(
    parseSniFromClientHello(Buffer.from("\x15\x03\x01\x00\x05hello")),
    undefined,
  );
});

test("tls-sni: null for empty/truncated buffers", () => {
  assert.equal(parseSniFromClientHello(Buffer.alloc(0)), null);
  assert.equal(parseSniFromClientHello(Buffer.from([0x16, 0x03])), null);
});

test("tls-sni: undefined when no server_name extension is present", () => {
  // Hand-rolled minimal ClientHello without extensions:
  // record(5) + handshake header(4) + version(2) + random(32) + sid(0) + ciphers(2) + comp(1)
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), // client version
    Buffer.alloc(32, 0xab), // random
    Buffer.from([0x00]), // session id len
    Buffer.from([0x00, 0x02, 0x13, 0x01]), // cipher suites len + TLS_AES_128_GCM_SHA256
    Buffer.from([0x01, 0x00]), // compression methods
    Buffer.from([0x00, 0x00]), // extensions len = 0
  ]);
  // handshake header: msg type (1 byte) + length (3 bytes)
  const hsHeader = Buffer.alloc(4);
  hsHeader[0] = 0x01;
  hsHeader.writeUIntBE(body.length, 1, 3);
  const recordBody = Buffer.concat([hsHeader, body]);
  const record = Buffer.concat([
    Buffer.from([0x16, 0x03, 0x01]),
    (() => {
      const b = Buffer.alloc(2);
      b.writeUInt16BE(recordBody.length);
      return b;
    })(),
    recordBody,
  ]);
  assert.equal(parseSniFromClientHello(record), undefined);
});

test("tls-sni: MAX_SNI_PREPARSE_BYTES is generous", () => {
  assert.ok(MAX_SNI_PREPARSE_BYTES >= 8 * 1024);
});
