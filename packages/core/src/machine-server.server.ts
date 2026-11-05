import {
  createServer as createHttpServer,
  type RequestListener,
  type ServerResponse,
} from "node:http";
import type { Socket } from "node:net";
import {
  createServer as createTlsServer,
  connect,
  type TlsOptions,
  type ConnectionOptions,
} from "node:tls";

const signatureAlgorithms = [
  "ed25519",
  "ecdsa_secp256r1_sha256",
  "ecdsa_secp384r1_sha384",
  "ecdsa_secp521r1_sha512",
  "rsa_pss_rsae_sha256",
  "rsa_pss_rsae_sha384",
  "rsa_pss_rsae_sha512",
  "rsa_pkcs1_sha256",
  "rsa_pkcs1_sha384",
  "rsa_pkcs1_sha512",
].join(":");

export const MACHINE_TIMEOUTS = Object.freeze({
  handshake: 10000,
  headers: 10000,
  body: 15000,
  idle: 10000,
  drain: 10000,
});

type Connection = {
  authenticated: boolean;
  deadline: NodeJS.Timeout | null;
  bodies: Set<NodeJS.Timeout>;
  responses: Set<ServerResponse>;
};

// Bun's HTTPS bridge exposes a synthetic Socket without the peer certificate.
// Deliver the real authenticated TLSSocket to the HTTP parser instead.
export function createMachineServer(
  options: TlsOptions,
  handler: RequestListener,
) {
  const connections = new Map<Socket, Connection>();
  let closing: Promise<void> | null = null;
  let finishDrain: (() => void) | null = null;

  const deadline = (
    socket: Socket,
    connection: Connection,
    milliseconds: number,
  ) => {
    if (connection.deadline) clearTimeout(connection.deadline);
    connection.deadline = setTimeout(() => socket.destroy(), milliseconds);
    connection.deadline.unref();
  };

  const http = createHttpServer(
    {
      requestTimeout: MACHINE_TIMEOUTS.body,
      headersTimeout: MACHINE_TIMEOUTS.headers,
    },
    (request, response) => {
      const socket = request.socket;
      const connection = connections.get(socket);

      if (!connection?.authenticated) {
        socket.destroy();

        return;
      }

      if (closing) {
        // A close response for a pipelined request can end Bun's socket before
        // the accepted response finishes. Drain that response, then close.
        request.resume();

        if (!connection.responses.size) socket.destroy();

        return;
      }

      if (connection.deadline) clearTimeout(connection.deadline);
      connection.deadline = null;
      connection.responses.add(response);
      const body = setTimeout(() => socket.destroy(), MACHINE_TIMEOUTS.body);
      body.unref();
      connection.bodies.add(body);

      const bodyComplete = () => {
        clearTimeout(body);
        connection.bodies.delete(body);

        if (closing && !connection.bodies.size) socket.pause();
      };

      request.once("end", bodyComplete);
      request.once("close", bodyComplete);

      const finished = () => {
        connection.responses.delete(response);

        if (request.complete) bodyComplete();

        if (connection.responses.size || socket.destroyed) return;

        if (closing) socket.end(() => socket.destroy());
        else deadline(socket, connection, MACHINE_TIMEOUTS.idle);
      };

      response.once("finish", finished);
      response.once("close", finished);

      handler(request, response);
    },
  );

  const server = createTlsServer(
    {
      ...options,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: "TLSv1.3",
      handshakeTimeout: MACHINE_TIMEOUTS.handshake,
      sigalgs: signatureAlgorithms,
    },
    (socket) => {
      const connection = connections.get(socket);

      if (!connection)
        throw new Error("Machine TLS connection was not tracked");
      connection.authenticated = true;
      deadline(socket, connection, MACHINE_TIMEOUTS.headers);
      http.emit("connection", socket);
    },
  );

  // Bun exposes the same TLSSocket at TCP acceptance and secureConnection.
  // These timers enforce total phase deadlines even when bytes keep arriving.
  server.on("connection", (socket) => {
    const connection: Connection = {
      authenticated: false,
      deadline: null,
      bodies: new Set(),
      responses: new Set(),
    };

    connections.set(socket, connection);
    deadline(socket, connection, MACHINE_TIMEOUTS.handshake);
    socket.once("close", () => {
      if (connection.deadline) clearTimeout(connection.deadline);

      for (const body of connection.bodies) clearTimeout(body);
      connections.delete(socket);
      finishDrain?.();
    });

    if (closing) socket.destroy();
  });

  const close = () => {
    if (closing) return closing;

    // Defer close until the promise is assigned, so request handlers see drain.
    closing = Promise.resolve().then(
      () =>
        new Promise<void>((resolve, reject) => {
          let listenerClosing = false;

          const stopListener = () => {
            if (listenerClosing) return;
            listenerClosing = true;
            server.close((error) => {
              clearTimeout(drain);
              finishDrain = null;

              if (error) reject(error);
              else resolve();
            });
          };

          const drain = setTimeout(() => {
            for (const socket of connections.keys()) socket.destroy();
            stopListener();
          }, MACHINE_TIMEOUTS.drain);

          drain.unref();
          // Bun's listener close can abort later reads on accepted sockets.
          // Reject new connections while accepted bodies/responses drain.
          finishDrain = () => {
            if (!connections.size) stopListener();
          };

          for (const [socket, connection] of connections) {
            if (!connection.responses.size) socket.destroy();
            else if (!connection.bodies.size) socket.pause();
          }

          finishDrain();
        }),
    );

    return closing;
  };

  return { server, close };
}

export function createMachineConnection(url: URL, options: ConnectionOptions) {
  const socket = connect({
    ...options,
    host: url.hostname,
    port: url.port ? Number(url.port) : 443,
    rejectUnauthorized: true,
    minVersion: "TLSv1.3",
    sigalgs: signatureAlgorithms,
  });

  const handshake = setTimeout(() => {
    socket.destroy(new Error("Machine TLS handshake timed out"));
  }, MACHINE_TIMEOUTS.handshake);

  handshake.unref();
  const clearHandshake = () => clearTimeout(handshake);
  socket.once("secureConnect", clearHandshake);
  socket.once("error", clearHandshake);
  socket.once("close", clearHandshake);

  return socket;
}
