import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

// ---------------- CONFIG ----------------

const UUID = "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const DOMAIN = "denod.santanudhibar.deno.dev";

const WS_PATH = "ws";
const SUB_PATH = "sub";

const PORT = 3000;

// ---------------- UUID utils ----------------

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

// ---------------- VLESS parser ----------------

async function parseVLESSHeader(data: Uint8Array) {
  const version = data[0];
  const id = data.slice(1, 17);

  if (!uuidEqual(id, parseUUID(UUID))) {
    throw new Error("Invalid UUID");
  }

  const optLen = data[17];
  const cmd = data[18 + optLen];

  if (cmd !== 1) {
    throw new Error("Only TCP supported");
  }

  const portIndex = 19 + optLen;

  const port =
    (data[portIndex] << 8) +
    data[portIndex + 1];

  const addrType = data[portIndex + 2];

  let host = "";
  let addrIndex = portIndex + 3;

  // IPv4
  if (addrType === 1) {
    host =
      `${data[addrIndex]}.` +
      `${data[addrIndex + 1]}.` +
      `${data[addrIndex + 2]}.` +
      `${data[addrIndex + 3]}`;

    addrIndex += 4;
  }

  // Domain
  else if (addrType === 2) {
    const len = data[addrIndex];

    addrIndex++;

    host = new TextDecoder().decode(
      data.slice(addrIndex, addrIndex + len),
    );

    addrIndex += len;
  }

  // IPv6
  else if (addrType === 3) {
    const parts = [];

    for (let i = 0; i < 8; i++) {
      parts.push(
        (
          (data[addrIndex + i * 2] << 8) +
          data[addrIndex + i * 2 + 1]
        ).toString(16),
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

// ---------------- WebSocket ----------------

async function handleWS(req: Request): Promise<Response> {
  const { socket, response } =
    Deno.upgradeWebSocket(req);

  let conn: Deno.Conn | null = null;

  socket.onmessage = async (event) => {
    try {
      const data = new Uint8Array(event.data);

      // First packet
      if (!conn) {
        const vless =
          await parseVLESSHeader(data);

        conn = await Deno.connect({
          hostname: vless.host,
          port: vless.port,
        });

        // VLESS response header
        socket.send(
          new Uint8Array([
            vless.version,
            0,
          ]),
        );

        // Send payload
        if (vless.rest.length > 0) {
          await conn.write(vless.rest);
        }

        // Remote -> WS
        (async () => {
          try {
            const buffer =
              new Uint8Array(4096);

            while (true) {
              const n =
                await conn!.read(buffer);

              if (!n) break;

              socket.send(
                buffer.slice(0, n),
              );
            }
          } catch (_) {
          } finally {
            socket.close();
            conn?.close();
          }
        })();
      }

      // Next packets
      else {
        await conn.write(
          new Uint8Array(event.data),
        );
      }
    } catch (err) {
      console.error(err);

      socket.close();

      conn?.close();
    }
  };

  socket.onclose = () => {
    conn?.close();
  };

  return response;
}

// ---------------- Server ----------------

serve(
  async (req: Request) => {
    const url = new URL(req.url);

    // Root
    if (url.pathname === "/") {
      return new Response(
        "VLESS WS Server Running\n",
      );
    }

    // Subscription
    if (
      url.pathname === `/${SUB_PATH}`
    ) {
      const vless =
        `vless://${UUID}@${DOMAIN}:443` +
        `?encryption=none` +
        `&security=tls` +
        `&type=ws` +
        `&host=${DOMAIN}` +
        `&path=/${WS_PATH}` +
        `&sni=${DOMAIN}` +
        `#Deno-WS`;

      return new Response(
        btoa(vless),
        {
          headers: {
            "Content-Type":
              "text/plain",
          },
        },
      );
    }

    // WebSocket
    if (
      url.pathname === `/${WS_PATH}`
    ) {
      if (
        req.headers.get("upgrade") !==
        "websocket"
      ) {
        return new Response(
          "Expected WebSocket",
          { status: 400 },
        );
      }

      return handleWS(req);
    }

    return new Response(
      "Not Found",
      { status: 404 },
    );
  },

  {
    port: PORT,
  },
);

console.log(
  `Server running on port ${PORT}`,
);
