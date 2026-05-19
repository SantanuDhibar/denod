const UUID: string = Deno.env.get("UUID") || "f9a1ba12-7187-4b25-a5d5-7bafd82ffb4d";
const SUB_PATH: string = Deno.env.get("SUB_PATH") || "sub";
const XPATH: string = Deno.env.get("XPATH") || "xhttp";
const DOMAIN: string = Deno.env.get("DOMAIN") || "nxhack.deno.dev";
const NAME: string = Deno.env.get("NAME") || "Deno";
const PORT: number = parseInt(Deno.env.get("PORT") || "3000");

const VLESS_WS_PATH = "vless";
const SSH_WS_PATH = "ssh";
const SSH_HOST = "127.0.0.1";
const SSH_PORT = 22;
const WS_AUTH_USER = "admin";
const WS_AUTH_PASS = "1234";
const WS_AUTH_HEADER = `Basic ${btoa(`${WS_AUTH_USER}:${WS_AUTH_PASS}`)}`;
const TCP_PROXY_ENABLED = !Deno.env.get("DENO_DEPLOYMENT_ID");

interface Settings {
  UUID: string;
  LOG_LEVEL: "none" | "debug" | "info" | "warn" | "error";
  BUFFER_SIZE: number;
  XPATH: string;
  MAX_BUFFERED_POSTS: number;
  MAX_POST_SIZE: number;
  SESSION_TIMEOUT: number;
  CHUNK_SIZE: number;
  TCP_NODELAY: boolean;
  TCP_KEEPALIVE: boolean;
}

const SETTINGS: Settings = {
  UUID,
  LOG_LEVEL: "none",
  BUFFER_SIZE: 2048,
  XPATH: `%2F${XPATH}`,
  MAX_BUFFERED_POSTS: 30,
  MAX_POST_SIZE: 1000000,
  SESSION_TIMEOUT: 30000,
  CHUNK_SIZE: 1024 * 1024,
  TCP_NODELAY: true,
  TCP_KEEPALIVE: true,
};

function validate_uuid(left: Uint8Array, right: Uint8Array): boolean {
  for (let i = 0; i < 16; i++) {
    if (left[i] !== right[i]) return false;
  }
  return true;
}

function concat_typed_arrays(...args: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const a of args) len += a.length;
  const r = new Uint8Array(len);
  let offset = 0;
  for (const a of args) {
    r.set(a, offset);
    offset += a.length;
  }
  return r;
}

function to_uint8_array(data: string | ArrayBuffer | Uint8Array): Uint8Array {
  if (typeof data === "string") {
    return new TextEncoder().encode(data);
  }
  if (data instanceof Uint8Array) {
    return data;
  }
  return new Uint8Array(data);
}

function is_websocket_request(req: Request): boolean {
  return req.headers.get("upgrade")?.toLowerCase() === "websocket";
}

function is_ws_authorized(req: Request): boolean {
  const auth = req.headers.get("authorization");
  return auth === WS_AUTH_HEADER;
}

function unauthorized_response(): Response {
  return new Response("Unauthorized", {
    status: 401,
    headers: { "WWW-Authenticate": "Basic realm=\"denod\"" },
  });
}

function parse_uuid(uuid: string): Uint8Array {
  uuid = uuid.replaceAll("-", "");
  const r = new Uint8Array(16);
  for (let index = 0; index < 16; index++) {
    r[index] = parseInt(uuid.substr(index * 2, 2), 16);
  }
  return r;
}

function try_parse_vless_header_from_buffer(
  buffer: Uint8Array,
  cfg_uuid_str: string
): {
  hostname: string;
  port: number;
  data: Uint8Array;
  resp: Uint8Array;
} | null {
  const min_len = 1 + 16 + 1;
  if (buffer.length < min_len) {
    return null;
  }
  const version = buffer[0];
  const uuid = buffer.slice(1, 1 + 16);
  const cfg_uuid = parse_uuid(cfg_uuid_str);
  if (!validate_uuid(uuid, cfg_uuid)) {
    throw new Error("invalid UUID");
  }
  const pb_len = buffer[1 + 16];
  const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;
  if (buffer.length < addr_plus1 + 1) {
    return null;
  }

  const cmd = buffer[1 + 16 + 1 + pb_len];
  const COMMAND_TYPE_TCP = 1;
  if (cmd !== COMMAND_TYPE_TCP) {
    throw new Error(`unsupported command: ${cmd}`);
  }

  const port = (buffer[addr_plus1 - 1 - 2] << 8) + buffer[addr_plus1 - 1 - 1];
  const atype = buffer[addr_plus1 - 1];

  const ADDRESS_TYPE_IPV4 = 1;
  const ADDRESS_TYPE_STRING = 2;
  const ADDRESS_TYPE_IPV6 = 3;
  let header_len = -1;
  if (atype === ADDRESS_TYPE_IPV4) {
    header_len = addr_plus1 + 4;
  } else if (atype === ADDRESS_TYPE_IPV6) {
    header_len = addr_plus1 + 16;
  } else if (atype === ADDRESS_TYPE_STRING) {
    header_len = addr_plus1 + 1 + buffer[addr_plus1];
  }
  if (header_len < 0) {
    throw new Error("read address type failed");
  }
  if (buffer.length < header_len) {
    return null;
  }

  const idx = addr_plus1;
  let hostname = "";
  if (atype === ADDRESS_TYPE_IPV4) {
    hostname = Array.from(buffer.slice(idx, idx + 4))
      .map((b) => b.toString())
      .join(".");
  } else if (atype === ADDRESS_TYPE_STRING) {
    hostname = new TextDecoder().decode(buffer.slice(idx + 1, idx + 1 + buffer[idx]));
  } else if (atype === ADDRESS_TYPE_IPV6) {
    hostname = Array.from({ length: 8 }, (_, i) =>
      ((buffer[idx + i * 2] << 8) + buffer[idx + i * 2 + 1]).toString(16)
    ).join(":");
  }

  if (!hostname) {
    throw new Error("parse hostname failed");
  }

  return {
    hostname,
    port,
    data: buffer.slice(header_len),
    resp: new Uint8Array([version, 0]),
  };
}

async function read_vless_header(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  cfg_uuid_str: string
): Promise<{
  hostname: string;
  port: number;
  data: Uint8Array;
  resp: Uint8Array;
}> {
  let readed_len = 0;
  let header = new Uint8Array();

  async function inner_read_until(offset: number): Promise<void> {
    while (readed_len < offset) {
      const { value, done } = await reader.read();
      if (done) throw new Error("header length too short");
      header = concat_typed_arrays(header, value!);
      readed_len += value!.length;
    }
  }

  await inner_read_until(1 + 16 + 1);

  const version = header[0];
  const uuid = header.slice(1, 1 + 16);
  const cfg_uuid = parse_uuid(cfg_uuid_str);
  if (!validate_uuid(uuid, cfg_uuid)) {
    throw new Error("invalid UUID");
  }
  const pb_len = header[1 + 16];
  const addr_plus1 = 1 + 16 + 1 + pb_len + 1 + 2 + 1;
  await inner_read_until(addr_plus1 + 1);

  const cmd = header[1 + 16 + 1 + pb_len];
  const COMMAND_TYPE_TCP = 1;
  if (cmd !== COMMAND_TYPE_TCP) {
    throw new Error(`unsupported command: ${cmd}`);
  }

  const port = (header[addr_plus1 - 1 - 2] << 8) + header[addr_plus1 - 1 - 1];
  const atype = header[addr_plus1 - 1];

  const ADDRESS_TYPE_IPV4 = 1;
  const ADDRESS_TYPE_STRING = 2;
  const ADDRESS_TYPE_IPV6 = 3;
  let header_len = -1;
  if (atype === ADDRESS_TYPE_IPV4) {
    header_len = addr_plus1 + 4;
  } else if (atype === ADDRESS_TYPE_IPV6) {
    header_len = addr_plus1 + 16;
  } else if (atype === ADDRESS_TYPE_STRING) {
    header_len = addr_plus1 + 1 + header[addr_plus1];
  }
  if (header_len < 0) {
    throw new Error("read address type failed");
  }
  await inner_read_until(header_len);

  const idx = addr_plus1;
  let hostname = "";
  if (atype === ADDRESS_TYPE_IPV4) {
    hostname = Array.from(header.slice(idx, idx + 4))
      .map((b) => b.toString())
      .join(".");
  } else if (atype === ADDRESS_TYPE_STRING) {
    hostname = new TextDecoder().decode(header.slice(idx + 1, idx + 1 + header[idx]));
  } else if (atype === ADDRESS_TYPE_IPV6) {
    hostname = Array.from({ length: 8 }, (_, i) =>
      ((header[idx + i * 2] << 8) + header[idx + i * 2 + 1]).toString(16)
    ).join(":");
  }

  if (!hostname) {
    throw new Error("parse hostname failed");
  }

  return {
    hostname,
    port,
    data: header.slice(header_len),
    resp: new Uint8Array([version, 0]),
  };
}

async function parse_header(
  uuid_str: string,
  client: { readable: ReadableStream<Uint8Array> }
): Promise<any> {
  const reader = client.readable.getReader();
  try {
    const vless = await read_vless_header(reader, uuid_str);
    return vless;
  } catch (err) {
    throw new Error(`read vless header error: ${err.message}`);
  } finally {
    reader.releaseLock();
  }
}

async function connect_remote(hostname: string, port: number): Promise<Deno.Conn> {
  const timeout = 8000;
  try {
    const conn = await Deno.connect({ hostname, port });
    return conn;
  } catch (err) {
    throw err;
  }
}

function handle_vless_websocket(req: Request): Response {
  if (req.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (!is_websocket_request(req)) {
    return new Response("Upgrade Required", { status: 426 });
  }
  if (!is_ws_authorized(req)) {
    return unauthorized_response();
  }
  if (!TCP_PROXY_ENABLED) {
    return new Response("Not supported on Deno Deploy", { status: 501 });
  }

  const { socket, response } = Deno.upgradeWebSocket(req);
  socket.binaryType = "arraybuffer";

  let remote: Deno.Conn | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let initialized = false;
  let buffer = new Uint8Array();
  let closed = false;
  let write_chain = Promise.resolve();

  const cleanup = () => {
    if (remote) {
      try {
        remote.close();
      } catch (err) {
      }
      remote = null;
    }
  };

  const close_with_error = (reason: string) => {
    if (closed) return;
    closed = true;
    try {
      socket.close(1011, reason);
    } catch (err) {
    }
    cleanup();
  };

  const start_remote_pump = async () => {
    if (!remote) return;
    try {
      for await (const chunk of remote.readable) {
        socket.send(chunk);
      }
    } catch (err) {
    } finally {
      cleanup();
      try {
        socket.close();
      } catch (err) {
      }
    }
  };

  const handle_message = async (event: MessageEvent) => {
    const data = to_uint8_array(event.data);
    if (!initialized) {
      buffer = concat_typed_arrays(buffer, data);
      let vless;
      try {
        vless = try_parse_vless_header_from_buffer(buffer, SETTINGS.UUID);
      } catch (err) {
        close_with_error("Invalid VLESS header");
        return;
      }
      if (!vless) {
        return;
      }
      buffer = new Uint8Array();
      try {
        remote = await connect_remote(vless.hostname, vless.port);
      } catch (err) {
        close_with_error("Remote connect failed");
        return;
      }
      writer = remote.writable.getWriter();
      initialized = true;
      socket.send(vless.resp);
      if (vless.data.length > 0) {
        try {
          await writer.write(vless.data);
        } catch (err) {
          close_with_error("Remote write failed");
          return;
        }
      }
      start_remote_pump();
      return;
    }

    if (!writer) return;
    write_chain = write_chain.then(() => writer!.write(data)).catch(() => {
      close_with_error("Remote write failed");
    });
    await write_chain;
  };

  socket.onmessage = (event) => {
    handle_message(event).catch(() => {
      close_with_error("Processing error");
    });
  };
  socket.onclose = () => cleanup();
  socket.onerror = () => cleanup();

  return response;
}

function handle_ssh_websocket(req: Request): Response {
  if (req.method !== "GET") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  if (!is_websocket_request(req)) {
    return new Response("Upgrade Required", { status: 426 });
  }
  if (!is_ws_authorized(req)) {
    return unauthorized_response();
  }
  if (!TCP_PROXY_ENABLED) {
    return new Response("Not supported on Deno Deploy", { status: 501 });
  }

  const { socket, response } = Deno.upgradeWebSocket(req);
  socket.binaryType = "arraybuffer";

  let remote: Deno.Conn | null = null;
  let writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  let write_chain = Promise.resolve();

  const cleanup = () => {
    if (remote) {
      try {
        remote.close();
      } catch (err) {
      }
      remote = null;
    }
  };

  const close_with_error = (reason: string) => {
    try {
      socket.close(1011, reason);
    } catch (err) {
    }
    cleanup();
  };

  const start_remote_pump = async () => {
    if (!remote) return;
    try {
      for await (const chunk of remote.readable) {
        socket.send(chunk);
      }
    } catch (err) {
    } finally {
      cleanup();
      try {
        socket.close();
      } catch (err) {
      }
    }
  };

  socket.onopen = async () => {
    try {
      remote = await connect_remote(SSH_HOST, SSH_PORT);
      writer = remote.writable.getWriter();
      start_remote_pump();
    } catch (err) {
      close_with_error("Remote connect failed");
    }
  };

  socket.onmessage = (event) => {
    if (!writer) return;
    const data = to_uint8_array(event.data);
    write_chain = write_chain.then(() => writer!.write(data)).catch(() => {
      close_with_error("Remote write failed");
    });
  };
  socket.onclose = () => cleanup();
  socket.onerror = () => cleanup();

  return response;
}

function pipe_relay() {
  async function pump(
    src: ReadableStream<Uint8Array>,
    dest: WritableStream<Uint8Array>,
    first_packet: Uint8Array
  ): Promise<void> {
    if (first_packet.length > 0) {
      const writer = dest.getWriter();
      await writer.write(first_packet);
      writer.releaseLock();
    }

    try {
      await src.pipeTo(dest, {
        preventClose: false,
        preventAbort: false,
        preventCancel: false,
        signal: AbortSignal.timeout(SETTINGS.SESSION_TIMEOUT),
      });
    } catch (err) {
      throw err;
    }
  }
  return pump;
}

function relay(
  cfg: Settings,
  client: { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> },
  remote: Deno.Conn,
  vless: { data: Uint8Array; resp: Uint8Array }
): void {
  const pump = pipe_relay();
  let isClosing = false;

  const remoteStream = {
    readable: remote.readable,
    writable: remote.writable,
  };

  function cleanup(): void {
    if (!isClosing) {
      isClosing = true;
      try {
        remote.close();
      } catch (err) {
      }
    }
  }

  const uploader = pump(client.readable, remoteStream.writable, vless.data)
    .catch((err) => {
    })
    .finally(cleanup);

  const downloader = pump(remoteStream.readable, client.writable, vless.resp)
    .catch((err) => {
    });

  downloader.finally(() => uploader).finally(cleanup);
}

const sessions = new Map<string, Session>();

class Session {
  uuid: string;
  nextSeq: number = 0;
  downstreamStarted: boolean = false;
  lastActivity: number = Date.now();
  vlessHeader: any = null;
  remote: Deno.Conn | null = null;
  initialized: boolean = false;
  responseHeader: Uint8Array | null = null;
  headerSent: boolean = false;
  bufferedData: Map<number, Uint8Array> = new Map();
  cleaned: boolean = false;
  pendingPackets: Uint8Array[] = [];
  currentStreamRes: { writable: WritableStream<Uint8Array> } | null = null;
  pendingBuffers: Map<number, Uint8Array> = new Map();

  constructor(uuid: string) {
    this.uuid = uuid;
  }

  async initializeVLESS(firstPacket: Uint8Array): Promise<boolean> {
    if (this.initialized) return true;

    try {
      const readable = new ReadableStream({
        start(controller) {
          controller.enqueue(firstPacket);
          controller.close();
        },
      });

      const client = {
        readable,
        writable: new WritableStream(),
      };

      this.vlessHeader = await parse_header(SETTINGS.UUID, client);
      this.remote = await connect_remote(this.vlessHeader.hostname, this.vlessHeader.port);
      this.initialized = true;
      return true;
    } catch (err) {
      return false;
    }
  }

  async processPacket(seq: number, data: Uint8Array): Promise<boolean> {
    try {
      this.pendingBuffers.set(seq, data);

      while (this.pendingBuffers.has(this.nextSeq)) {
        const nextData = this.pendingBuffers.get(this.nextSeq)!;
        this.pendingBuffers.delete(this.nextSeq);

        if (!this.initialized && this.nextSeq === 0) {
          if (!await this.initializeVLESS(nextData)) {
            throw new Error("Failed to initialize VLESS connection");
          }
          this.responseHeader = this.vlessHeader.resp;
          await this._writeToRemote(this.vlessHeader.data);

          if (this.currentStreamRes) {
            this._startDownstreamResponse();
          }
        } else {
          if (!this.initialized) {
            continue;
          }
          await this._writeToRemote(nextData);
        }

        this.nextSeq++;
      }

      if (this.pendingBuffers.size > SETTINGS.MAX_BUFFERED_POSTS) {
        throw new Error("Too many buffered packets");
      }

      return true;
    } catch (err) {
      throw err;
    }
  }

  startDownstream(res: { writable: WritableStream<Uint8Array> }): boolean {
    this.currentStreamRes = res;
    if (this.initialized && this.responseHeader) {
      this._startDownstreamResponse();
    }
    return true;
  }

  async _writeToRemote(data: Uint8Array): Promise<void> {
    if (!this.remote) {
      throw new Error("Remote connection not available");
    }
    const writer = this.remote.writable.getWriter();
    await writer.write(data);
    writer.releaseLock();
  }

  _startDownstreamResponse(): void {
    if (!this.currentStreamRes || !this.responseHeader) return;

    try {
      const writer = this.currentStreamRes.writable.getWriter();
      writer.write(this.responseHeader);
      this.headerSent = true;
      writer.releaseLock();

      this.remote!.readable.pipeTo(this.currentStreamRes.writable).catch((err) => {
      });
    } catch (err) {
      this.cleanup();
    }
  }

  cleanup(): void {
    if (!this.cleaned) {
      this.cleaned = true;
      if (this.remote) {
        this.remote.close();
        this.remote = null;
      }
      this.initialized = false;
      this.headerSent = false;
    }
  }
}

let ISP = "";

try {
  const response = await fetch("https://speed.cloudflare.com/meta");
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const data = await response.json() as {
    country: string; 
    asOrganization: string;
  };
  ISP = `${data.country}-${data.asOrganization}`.replace(/ /g, "_");
} catch (err) {
  ISP = "unknown";
}

let IP = DOMAIN;
if (!DOMAIN) {
  try {
    const response = await fetch("https://ipv4.ip.sb", { method: "GET" });
    if (!response.ok) {
      throw new Error("ipv4 lookup failed");
    }
    IP = (await response.text()).trim();
  } catch (err) {
    try {
      const response = await fetch("https://ipv6.ip.sb", { method: "GET" });
      if (!response.ok) {
        throw new Error("ipv6 lookup failed");
      }
      IP = `[${(await response.text()).trim()}]`;
    } catch (ipv6Err) {
      IP = "localhost";
    }
  }
}

function generatePadding(min: number, max: number): string {
  const length = min + Math.floor(Math.random() * (max - min));
  return btoa(Array(length).fill("X").join(""));
}

Deno.serve(
  { port: PORT, onListen: ({ port }) => {
    console.log(`Server is running on port ${port}`);
  } },
  async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const path = url.pathname;

    const headers = {
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

    if (path === `/${VLESS_WS_PATH}`) {
      return handle_vless_websocket(req);
    }

    if (path === `/${SSH_WS_PATH}`) {
      return handle_ssh_websocket(req);
    }

    if (path === `/${SUB_PATH}`) {
      const vlessURL = `vless://${UUID}@${IP}:443?encryption=none&security=tls&sni=${IP}&fp=chrome&allowInsecure=1&type=xhttp&host=${IP}&path=${SETTINGS.XPATH}&mode=packet-up#${NAME}-${ISP}`;
      const vlessWsPath = encodeURIComponent(`/${VLESS_WS_PATH}`);
      const vlessWsURL = `vless://${UUID}@${IP}:443?encryption=none&security=tls&sni=${IP}&fp=chrome&allowInsecure=1&type=ws&host=${IP}&path=${vlessWsPath}#${NAME}-WS-${ISP}`;
      const base64Content = btoa([vlessURL, vlessWsURL].join("\n"));
      return new Response(base64Content + "\n", {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      });
    }

    if (!TCP_PROXY_ENABLED && path.startsWith(`/${XPATH}/`)) {
      return new Response("Not supported on Deno Deploy", { status: 501 });
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
          ...headers,
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
        return new Response(null, { status: 200, headers });
      } catch (err) {
        session.cleanup();
        sessions.delete(uuid);
        return new Response(null, { status: 500 });
      }
    }
    return new Response("Not Found", { status: 404 });
  }
);
  
