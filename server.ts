import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// ---------------- VLESS Configuration ----------------
const UUID = Deno.env.get("UUID") || "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const DOMAIN = Deno.env.get("DOMAIN") || "acute-warthog-31.deno.dev";
const WS_PATH = Deno.env.get("WS_PATH") || "ws";
const SUB_PATH = Deno.env.get("SUB_PATH") || "sub";
const PORT = parseInt(Deno.env.get("PORT") || "3000");

// ---------------- SSH Configuration ----------------
const SSH_USER = Deno.env.get("SSH_USER") || "sub";
const SSH_PASS = Deno.env.get("SSH_PASS") || "sub";
const SSH_HOST = Deno.env.get("SSH_HOST") || "localhost";
const SSH_PORT = parseInt(Deno.env.get("SSH_PORT") || "22");
const SSH_WS_PATH = Deno.env.get("SSH_WS_PATH") || "ssh";

// Validate SSH credentials if SSH feature is used (optional)
if (SSH_USER && SSH_PASS && !SSH_HOST) {
  console.warn("SSH_HOST not set, SSH WebSocket may not work correctly");
}

// ---------------- UUID utils (VLESS) ----------------
function parseUUID(uuid: string): Uint8Array {
  uuid = uuid.replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = parseInt(uuid.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function uuidEqual(a: Uint8Array, b: Uint8Array): boolean {
  for (let i = 0; i < 16; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

// ---------------- VLESS header parser ----------------
async function parseVLESSHeader(data: Uint8Array) {
  const version = data[0];
  const id = data.slice(1, 17);

  if (!uuidEqual(id, parseUUID(UUID))) {
    throw new Error("Invalid UUID");
  }

  const optLen = data[17];
  const cmd = data[18 + optLen];

  if (cmd !== 1) throw new Error("Only TCP supported");

  const portIndex = 19 + optLen;
  const port = (data[portIndex] << 8) + data[portIndex + 1];
  const addrType = data[portIndex + 2];

  let host = "";
  let addrIndex = portIndex + 3;

  if (addrType === 1) {
    // IPv4
    host = `${data[addrIndex]}.${data[addrIndex + 1]}.${data[addrIndex + 2]}.${data[addrIndex + 3]}`;
    addrIndex += 4;
  } else if (addrType === 2) {
    // Domain name
    const len = data[addrIndex];
    addrIndex++;
    host = new TextDecoder().decode(data.slice(addrIndex, addrIndex + len));
    addrIndex += len;
  } else if (addrType === 3) {
    // IPv6
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(
        ((data[addrIndex + i * 2] << 8) + data[addrIndex + i * 2 + 1]).toString(16)
      );
    }
    host = parts.join(":");
    addrIndex += 16;
  }

  const rest = data.slice(addrIndex);

  return {
    version,
    host,
    port,
    rest,
  };
}

// ---------------- VLESS WebSocket handler ----------------
async function handleVLESSWebSocket(req: Request): Promise<Response> {
  const { socket, response } = Deno.upgradeWebSocket(req);

  socket.onmessage = async (event) => {
    try {
      const data = new Uint8Array(event.data);
      const vless = await parseVLESSHeader(data);

      const conn = await Deno.connect({
        hostname: vless.host,
        port: vless.port,
      });

      // send response header
      socket.send(new Uint8Array([vless.version, 0]));

      // send remaining payload
      if (vless.rest.length > 0) {
        await conn.write(vless.rest);
      }

      // pipe remote → ws
      (async () => {
        const buffer = new Uint8Array(4096);
        while (true) {
          const n = await conn.read(buffer);
          if (!n) break;
          socket.send(buffer.slice(0, n));
        }
        socket.close();
        conn.close();
      })();

      // pipe ws → remote
      socket.onmessage = async (ev) => {
        await conn.write(new Uint8Array(ev.data));
      };

      socket.onclose = () => {
        conn.close();
      };
    } catch (err) {
      socket.close();
    }
  };

  return response;
}

// ---------------- SSH WebSocket handler (with username/password auth) ----------------
async function handleSSHWebSocket(req: Request): Promise<Response> {
  // Check if SSH credentials are configured
  if (!SSH_USER || !SSH_PASS) {
    return new Response("SSH WebSocket not configured (missing SSH_USER/SSH_PASS)", { status: 500 });
  }

  const { socket, response } = Deno.upgradeWebSocket(req);
  let authenticated = false;
  let tcpConn: Deno.Conn | null = null;

  // Function to start bidirectional proxy after authentication
  async function startProxy(sshConn: Deno.Conn) {
    tcpConn = sshConn;

    // Forward data from SSH server to WebSocket client
    (async () => {
      const buffer = new Uint8Array(4096);
      try {
        while (true) {
          const n = await sshConn.read(buffer);
          if (n === null) break; // connection closed
          socket.send(buffer.slice(0, n));
        }
      } catch (err) {
        // socket may be closed, ignore errors
      } finally {
        socket.close();
        sshConn.close();
      }
    })();

    // Forward data from WebSocket client to SSH server
    socket.onmessage = async (ev) => {
      if (!tcpConn) return;
      try {
        const data = ev.data instanceof Uint8Array ? ev.data : new TextEncoder().encode(ev.data);
        await tcpConn.write(data);
      } catch (err) {
        socket.close();
      }
    };

    // Clean up when WebSocket closes
    socket.onclose = () => {
      if (tcpConn && !tcpConn.closed) tcpConn.close();
    };
  }

  // Handle incoming WebSocket messages
  socket.onmessage = async (event) => {
    if (!authenticated) {
      // First message must be authentication JSON
      let authText: string;
      if (typeof event.data === "string") {
        authText = event.data;
      } else if (event.data instanceof Uint8Array) {
        authText = new TextDecoder().decode(event.data);
      } else {
        socket.close(1008, "Invalid auth format");
        return;
      }

      try {
        const { username, password } = JSON.parse(authText);
        if (username === SSH_USER && password === SSH_PASS) {
          authenticated = true;
          socket.send("authenticated");

          // Now connect to the SSH server
          try {
            const sshConn = await Deno.connect({ hostname: SSH_HOST, port: SSH_PORT });
            await startProxy(sshConn);
          } catch (err) {
            socket.send(`SSH connection failed: ${err.message}`);
            socket.close();
          }
        } else {
          socket.close(1008, "Authentication failed");
        }
      } catch {
        socket.close(1008, "Invalid JSON format");
      }
    }
    // After authentication, the socket.onmessage handler is replaced by startProxy's handler,
    // so no further messages will reach this block.
  };

  return response;
}

// ---------------- Main HTTP server ----------------
serve(
  async (req: Request) => {
    const url = new URL(req.url);

    // Root path
    if (url.pathname === "/") {
      return new Response("VLESS WS + SSH WS Server Running\n", {
        headers: { "Content-Type": "text/plain" },
      });
    }

    // VLESS subscription endpoint (base64 encoded vless:// link)
    if (url.pathname === `/${SUB_PATH}`) {
      const vless =
        `vless://${UUID}@${DOMAIN}:443` +
        `?encryption=none` +
        `&security=tls` +
        `&type=ws` +
        `&host=${DOMAIN}` +
        `&path=/${WS_PATH}` +
        `&sni=${DOMAIN}` +
        `#Deno-WS`;

      return new Response(btoa(vless), {
        headers: { "Content-Type": "text/plain" },
      });
    }

    // VLESS WebSocket endpoint
    if (url.pathname === `/${WS_PATH}`) {
      if (req.headers.get("upgrade") !== "websocket") {
        return new Response("Expected WebSocket", { status: 400 });
      }
      return handleVLESSWebSocket(req);
    }

    // SSH WebSocket endpoint (with username/password auth)
    if (url.pathname === `/${SSH_WS_PATH}`) {
      if (req.headers.get("upgrade") !== "websocket") {
        return new Response("Expected WebSocket", { status: 400 });
      }
      return handleSSHWebSocket(req);
    }

    return new Response("Not Found", { status: 404 });
  },
  { port: PORT },
);

console.log(`Server running on port ${PORT}`);
console.log(`VLESS WebSocket endpoint: /${WS_PATH}`);
console.log(`SSH WebSocket endpoint: /${SSH_WS_PATH} (auth required)`);
