import { serve } from "https://deno.land/std@0.224.0/http/server.ts";

const UUID = Deno.env.get("UUID") || "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const DOMAIN = Deno.env.get("DOMAIN") || "denod.santanudhibar.deno.dev";
const WS_PATH = Deno.env.get("WS_PATH") || "ws";
const SUB_PATH = Deno.env.get("SUB_PATH") || "sub";
const PORT = parseInt(Deno.env.get("PORT") || "3000");

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
    host = `${data[addrIndex]}.${data[addrIndex + 1]}.${data[addrIndex + 2]}.${data[addrIndex + 3]}`;
    addrIndex += 4;
  } else if (addrType === 2) {
    const len = data[addrIndex];
    addrIndex++;
    host = new TextDecoder().decode(data.slice(addrIndex, addrIndex + len));
    addrIndex += len;
  } else if (addrType === 3) {
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

// ---------------- WebSocket handler ----------------

async function handleWS(req: Request): Promise<Response> {
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

// ---------------- Server ----------------

serve(
  async (req: Request) => {
    const url = new URL(req.url);

    if (url.pathname === "/") {
      return new Response("VLESS WS Server Running\n");
    }

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

    if (url.pathname === `/${WS_PATH}`) {
      if (req.headers.get("upgrade") !== "websocket") {
        return new Response("Expected WebSocket", { status: 400 });
      }
      return handleWS(req);
    }

    return new Response("Not Found", { status: 404 });
  },
  { port: PORT },
);

console.log(`Server running on port ${PORT}`);

async function fetchIp(url: string, timeoutMs: number): Promise<string> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) {
    throw new Error(`Failed to fetch IP from ${url}: status ${response.status}`);
  }
  return (await response.text()).trim();
}

const handler = async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const path = url.pathname;

    const responseHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST",
      "Cache-Control": "no-store",
      "X-Accel-Buffering": "no",
      "X-Padding": generatePadding(100, 1000),
    };

    if (path === "/") { 
      return new Response("Hello, World\n", 
      { status: 200, 
        headers: { "Content-Type": "text/plain" }, }); 
    } 

    if (path === `/${SUB_PATH}`) {
      const vlessURL = `vless://${UUID}@${IP}:443?encryption=none&security=tls&sni=${IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${IP}&path=${SETTINGS.XPATH}&mode=packet-up#${NAME}-${ISP}`;
      const base64Content = btoa(vlessURL);
      return new Response(base64Content + "\n", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    }

    const isProxyPath = path.startsWith(`/${XPATH}/`);
    if (isProxyPath && !HAS_TCP) {
      if (req.body) {
        await req.arrayBuffer();
      }
      return new Response("TCP proxying is not supported in this runtime.", { status: 501, headers: responseHeaders });
    }

    const pathMatch = path.match(new RegExp(`/${XPATH}/([^/]+)(?:/([0-9]+))?$`));
    if (!pathMatch) {
      return new Response("Not Found", { status: 404 });
    }

    const uuid = pathMatch[1];
    const seq = pathMatch[2] ? parseInt(pathMatch[2]) : null;

    if (req.method === "GET" && !seq) {
      let session = sessions.get(uuid);
      if (!session) {
        session = new Session(uuid);
        sessions.set(uuid, session);
      }

      session.downstreamStarted = true;
      const { readable, writable } = new TransformStream();
      session.startDownstream({ writable });

      return new Response(readable, {
        status: 200,
        headers: {
          ...responseHeaders,
          "Content-Type": "application/octet-stream",
          "Transfer-Encoding": "chunked",
        },
      });
    }

    if (req.method === "POST" && seq !== null) {
      let session = sessions.get(uuid);
      if (!session) {
        session = new Session(uuid);
        sessions.set(uuid, session);

        setTimeout(() => {
          const currentSession = sessions.get(uuid);
          if (currentSession && !currentSession.downstreamStarted) {
            currentSession.cleanup();
            sessions.delete(uuid);
          }
        }, SETTINGS.SESSION_TIMEOUT);
      }

      const data = await req.arrayBuffer();
      const buffer = new Uint8Array(data);

      try {
        await session.processPacket(seq, buffer);
        return new Response(null, { status: 200, headers: responseHeaders });
      } catch (err) {
        session.cleanup();
        sessions.delete(uuid);
        return new Response(null, { status: 500 });
      }
    }
    return new Response("Not Found", { status: 404 });
  };

const serveOptions: Deno.ServeOptions = {
  ...(IS_DENO_DEPLOY ? {} : { port: PORT }),
  onListen: ({ port }) => {
    const deployLabel = IS_DENO_DEPLOY ? " (Deno Deploy)" : "";
    const portLabel = port ? ` on port ${port}` : "";
    console.log(`Server is running${portLabel}${deployLabel}`);
  },
};

Deno.serve(serveOptions, handler);
