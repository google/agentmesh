// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The Node side of the /libp2p-http ingress: an A2A endpoint answered by a
// Node request listener (an Express app with the A2A SDK's handlers mounted)
// is served by Node's own HTTP server over the libp2p stream, so the
// listener sees a real IncomingMessage and ServerResponse. Admission is the
// same as for a handler or url target; only who parses the request differs.

import type { Connection, Stream, StreamHandler } from "@libp2p/interface";
import http from "node:http";
import { Duplex } from "node:stream";
import { AUTH_HANDSHAKE_TIMEOUT_MS } from "./auth.ts";
import {
  HEADER_PEER_ID,
  HEADER_SAM_BISCUIT,
  HEADER_SAM_NO_TRAILING_SLASH,
  admitIngress,
  httpIngressHandler,
  type A2AEndpoint,
  type NodeRequestListener,
  type ProviderOptions,
} from "./libp2p-http.ts";

interface StreamSocket extends Duplex {
  remotePeer: string;
}

/**
 * Bridges a libp2p stream to a Node Duplex so Node's own HTTP parser and
 * client can run over it.
 */
export function streamToNodeDuplex(stream: Stream, remotePeer: string): StreamSocket {
  const duplex = new Duplex({
    read() {
      stream.resume();
    },
    write(chunk: Uint8Array, _encoding, callback) {
      if (stream.send(chunk)) {
        callback();
      } else {
        stream.addEventListener("drain", () => callback(), { once: true });
      }
    },
    final(callback) {
      stream.close().then(
        () => callback(),
        (err: Error) => callback(err),
      );
    },
    destroy(err, callback) {
      if (err !== null) {
        stream.abort(err);
      } else {
        void stream.close().catch(() => {});
      }
      callback(err);
    },
  }) as StreamSocket;
  duplex.remotePeer = remotePeer;
  stream.addEventListener("message", (evt) => {
    if (!duplex.push(Buffer.from(evt.data.subarray()))) {
      stream.pause();
    }
  });
  const end = () => {
    if (!duplex.readableEnded) {
      duplex.push(null);
    }
  };
  stream.addEventListener("remoteCloseWrite", end);
  stream.addEventListener("close", end);
  return duplex;
}

function nodeHeaders(req: http.IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    for (const v of Array.isArray(value) ? value : value === undefined ? [] : [value]) {
      headers.append(name, v);
    }
  }
  return headers;
}

async function serveListener(req: http.IncomingMessage, res: http.ServerResponse, endpoint: A2AEndpoint, listener: NodeRequestListener, options: ProviderOptions): Promise<void> {
  const remotePeer = (req.socket as unknown as StreamSocket).remotePeer;
  const admission = await admitIngress({ method: req.method ?? "GET", target: req.url ?? "/", headers: nodeHeaders(req), remotePeer }, endpoint, options);
  if ("status" in admission) {
    res.writeHead(admission.status, { "content-type": "text/plain; charset=utf-8" });
    res.end(admission.text + "\n");
    return;
  }
  // The listener sees the request as a backend behind sam-node would: the
  // path relative to the service, the verified caller, never the biscuit.
  // X-Peer-Id is set, not added, so an inbound value cannot pose as the
  // verified peer.
  req.url = admission.path;
  delete req.headers[HEADER_SAM_BISCUIT];
  req.headers[HEADER_PEER_ID] = remotePeer;
  if (admission.noTrailingSlash) {
    req.headers[HEADER_SAM_NO_TRAILING_SLASH] = "true";
  } else {
    delete req.headers[HEADER_SAM_NO_TRAILING_SLASH];
  }
  listener(req, res);
}

/**
 * Server side of /libp2p-http on Node: a listener target is served by Node's
 * HTTP server on the stream, any other by the runtime-neutral ingress.
 */
export function nodeIngressHandler(endpoint: A2AEndpoint, options: ProviderOptions): StreamHandler {
  if (!("listener" in endpoint.target)) {
    return httpIngressHandler(endpoint, options);
  }
  const listener = endpoint.target.listener;
  const server = http.createServer({ keepAlive: false }, (req, res) => {
    void serveListener(req, res, endpoint, listener, options).catch((err: unknown) => {
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "text/plain" });
      }
      res.end(`ingress error: ${err instanceof Error ? err.message : String(err)}\n`);
    });
  });
  server.headersTimeout = AUTH_HANDSHAKE_TIMEOUT_MS;
  return (stream: Stream, connection: Connection) => {
    server.emit("connection", streamToNodeDuplex(stream, connection.remotePeer.toString()));
  };
}
