import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// ============================================================
//  HARDCODED CONFIG — edit these values before deploying
// ============================================================

const UUID      = "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const DOMAIN    = "denod.santanudhibar.deno.dev";
const WS_PATH   = "ws";
const SSH_PATH  = "ssh";
const SUB_PATH  = "sub";

const SSH_USER    = "admin";
const SSH_PASS    = "SuperSecret123!";
const SSH_PAYLOAD = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

const SSH_TARGET_HOST = "127.0.0.1";
const SSH_TARGET_PORT = 22;

// ============================================================

function parseUUID(uuid: string): Uint8Array {
  uuid = uuid.replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(uuid.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uuidEqual(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < 16; i++) if (a[i] !== b[i]) return false;
  return true;
}

async function parseVLESSHeader(data: Uint8Array) {
  const version = data[0];
  const id = data.slice(1, 17);
  if (!uuidEqual(id, parseUUID(UUID))) throw new Error("Invalid UUID");

  const optLen    = data[17];
  const cmd       = data[18 + optLen];
  if (cmd !== 1) throw new Error("Only TCP supported");

  const portIndex = 19 + optLen;
  const port      = (data[portIndex] << 8) + data[portIndex + 1];
  const addrType  = data[portIndex + 2];

  let host      = "";
  let addrIndex = portIndex + 3;

  if (addrType === 1) {
    host = `${data[addrIndex]}.${data[addrIndex+1]}.${data[addrIndex+2]}.${data[addrIndex+3]}`;
    addrIndex += 4;
  } else if (addrType === 2) {
    const len = data[addrIndex++];
    host = new TextDecoder().decode(data.slice(addrIndex, addrIndex + len));
    addrIndex += len;
  } else if (addrType === 3) {
    const parts: string[] = [];
    for (let i = 0; i < 8; i++)
      parts.push(((data[addrIndex + i*2] << 8) + data[addrIndex + i*2 + 1]).toString(16));
    host = parts.join(":");
    addrIndex += 16;
  }

  return { version, host, port, rest: data.slice(addrIndex) };
}

// ----------------------------------------------------------------
//  VLESS WebSocket handler
// ----------------------------------------------------------------

async function handleVLESSWS(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);

  socket.onmessage = async (event) => {
    try {
      const data  = new Uint8Array(event.data);
      const vless = await parseVLESSHeader(data);

      const conn = await Deno.connect({ hostname: vless.host, port: vless.port });

      socket.send(new Uint8Array([vless.version, 0]));
      if (vless.rest.length > 0) await conn.write(vless.rest);

      // remote → ws
      (async () => {
        const buf = new Uint8Array(4096);
        try {
          while (true) {
            const n = await conn.read(buf);
            if (n === null) break;
            socket.send(buf.slice(0, n));
          }
        } catch { /**/ } finally {
          try { socket.close(); } catch { /**/ }
          try { conn.close();   } catch { /**/ }
        }
      })();

      // ws → remote
      socket.onmessage = async (ev) => {
        try { await conn.write(new Uint8Array(ev.data)); }
        catch { socket.close(); }
      };
      socket.onclose = () => { try { conn.close(); } catch { /**/ } };

    } catch (err) {
      console.error("VLESS error:", err);
      try { socket.close(); } catch { /**/ }
    }
  };

  return response;
}

// ----------------------------------------------------------------
//  SSH WebSocket handler  (auth → payload → raw pipe)
//
//  Handshake (text frames):
//    S→C  "AUTH_REQUIRED"
//    C→S  "USER:<username>"
//    S→C  "PASS_REQUIRED"
//    C→S  "PASS:<password>"
//    S→C  SSH_PAYLOAD   (then switches to binary tunnel)
// ----------------------------------------------------------------

async function handleSSHWS(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  let step: "wait_user" | "wait_pass" | "tunnel" = "wait_user";
  let username = "";
  let conn: Deno.TcpConn | null = null;

  socket.onopen = () => socket.send("AUTH_REQUIRED");

  socket.onmessage = async (event) => {
    try {
      // ---------- auth phase ----------
      if (step === "wait_user") {
        const msg = typeof event.data === "string"
          ? event.data : dec.decode(new Uint8Array(event.data));
        if (msg.startsWith("USER:")) {
          username = msg.slice(5).trim();
          step = "wait_pass";
          socket.send("PASS_REQUIRED");
        } else {
          socket.send("AUTH_FAILED"); socket.close();
        }
        return;
      }

      if (step === "wait_pass") {
        const msg = typeof event.data === "string"
          ? event.data : dec.decode(new Uint8Array(event.data));
        if (msg.startsWith("PASS:")) {
          const pass = msg.slice(5).trim();
          if (username !== SSH_USER || pass !== SSH_PASS) {
            socket.send("AUTH_FAILED"); socket.close(); return;
          }
          // connect to SSH server
          try {
            conn = await Deno.connect({ hostname: SSH_TARGET_HOST, port: SSH_TARGET_PORT });
          } catch {
            socket.send("CONNECT_FAILED"); socket.close(); return;
          }
          step = "tunnel";
          socket.send(SSH_PAYLOAD);   // custom payload after successful auth

          // SSH server → WebSocket
          (async () => {
            const buf = new Uint8Array(4096);
            try {
              while (true) {
                const n = await conn!.read(buf);
                if (n === null) break;
                socket.send(buf.slice(0, n));
              }
            } catch { /**/ } finally {
              try { socket.close(); } catch { /**/ }
              try { conn!.close();  } catch { /**/ }
            }
          })();

        } else {
          socket.send("AUTH_FAILED"); socket.close();
        }
        return;
      }

      // ---------- tunnel phase (binary) ----------
      if (step === "tunnel" && conn) {
        const bytes = event.data instanceof ArrayBuffer
          ? new Uint8Array(event.data)
          : typeof event.data === "string"
            ? enc.encode(event.data)
            : new Uint8Array(event.data);
        try { await conn.write(bytes); }
        catch { socket.close(); }
      }

    } catch (err) {
      console.error("SSH WS error:", err);
      try { socket.close(); } catch { /**/ }
    }
  };

  socket.onclose = () => { try { conn?.close(); } catch { /**/ } };
  socket.onerror = () => { try { conn?.close(); } catch { /**/ } };

  return response;
}

// ----------------------------------------------------------------
//  Subscription  /sub  → base64 of both configs
// ----------------------------------------------------------------

function buildSubscription(): string {
  const vless =
    `vless://${UUID}@${DOMAIN}:443` +
    `?encryption=none&security=tls&type=ws` +
    `&host=${DOMAIN}&path=/${WS_PATH}&sni=${DOMAIN}` +
    `#Deno-VLESS-WS`;

  const ssh =
    `ssh-ws://${SSH_USER}:${SSH_PASS}@${DOMAIN}:443` +
    `?path=/${SSH_PATH}&tls=1` +
    `#Deno-SSH-WS`;

  return btoa([vless, ssh].join("\n"));
}

// ----------------------------------------------------------------
//  Router
// ----------------------------------------------------------------

serve(async (req: Request): Promise<Response> => {
  const { pathname } = new URL(req.url);
  const isWS = req.headers.get("upgrade") === "websocket";

  if (pathname === "/") {
    return new Response(
      "VLESS + SSH WebSocket Server\n" +
      `  VLESS : wss://${DOMAIN}/${WS_PATH}\n` +
      `  SSH   : wss://${DOMAIN}/${SSH_PATH}\n` +
      `  Sub   : https://${DOMAIN}/${SUB_PATH}\n`
    );
  }

  if (pathname === `/${SUB_PATH}`) {
    return new Response(buildSubscription(), {
      headers: { "Content-Type": "text/plain" },
    });
  }

  if (pathname === `/${WS_PATH}`) {
    if (!isWS) return new Response("Expected WebSocket", { status: 400 });
    return handleVLESSWS(req);
  }

  if (pathname === `/${SSH_PATH}`) {
    if (!isWS) return new Response("Expected WebSocket", { status: 400 });
    return handleSSHWS(req);
  }

  return new Response("Not Found", { status: 404 });
});

console.log(`Ready → VLESS:/${WS_PATH}  SSH:/${SSH_PATH}  Sub:/${SUB_PATH}`);
    
