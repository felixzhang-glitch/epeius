import { connect } from "cloudflare:sockets";

let sha224Password = "";
let proxyIP = "";

// Utility function to validate SHA-224 hash format
function isValidSHA224(hash) {
    const sha224Regex = /^[0-9a-f]{56}$/i;
    return sha224Regex.test(hash);
}

// Entry point for the Worker
const worker_default = {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{SHA224PASS: string, PROXYIP: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        const startTime = Date.now();

        try {
            // Ensure required environment variables are present
            if (!env.SHA224PASS || !env.PROXYIP) {
                throw new Error("Missing required environment variables: SHA224PASS or PROXYIP");
            }

            sha224Password = env.SHA224PASS;
            proxyIP = env.PROXYIP;

            if (!isValidSHA224(sha224Password)) {
                throw new Error("SHA224PASS is not a valid SHA-224 hash");
            }

            const upgradeHeader = request.headers.get("Upgrade");

            // Handle non-WebSocket requests
            if (!upgradeHeader || upgradeHeader !== "websocket") {
                const url = new URL(request.url);

                switch (url.pathname) {
                    case "/link": {
                        // Remove password protection
                        const host = request.headers.get('Host');
                        return new Response(
                            `trojan://ca110us@${host}:443/?type=ws&host=${host}&security=tls`,
                            {
                                status: 200,
                                headers: { "Content-Type": "text/plain;charset=utf-8" },
                            }
                        );
                    }
                    default:
                        return new Response("404 Not Found", { status: 404 });
                }
            }

            // Handle WebSocket upgrade requests
            return await trojanOverWSHandler(request);

        } catch (err) {
            console.error("Error occurred:", err.stack || err.message || err);
            return new Response("Internal Server Error", { status: 500 });
        } finally {
            console.log("Request processed in", Date.now() - startTime, "ms");
        }
    }
};

// WebSocket handler for Trojan protocol
async function trojanOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";

    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWapper = { value: null };
    let udpStreamWrite = null;

    readableWebSocketStream.pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                if (udpStreamWrite) {
                    return udpStreamWrite(chunk);
                }

                if (remoteSocketWapper.value) {
                    const writer = remoteSocketWapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }

                const { hasError, message, portRemote = 443, addressRemote = "", rawClientData } = await parseTrojanHeader(chunk);
                address = addressRemote;
                portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

                if (hasError) {
                    throw new Error(message);
                }

                handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, log);
            },
            close() {
                log(`readableWebSocketStream is closed`);
            },
            abort(reason) {
                log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
            }
        })
    ).catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

// Parse Trojan protocol headers
async function parseTrojanHeader(buffer) {
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "invalid data" };
    }

    const password = new TextDecoder().decode(buffer.slice(0, 56));
    if (password !== sha224Password) {
        return { hasError: true, message: "invalid password" };
    }

    const socks5DataBuffer = buffer.slice(58);
    if (socks5DataBuffer.byteLength < 6) {
        return { hasError: true, message: "invalid SOCKS5 request data" };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return { hasError: true, message: "unsupported command, only TCP (CONNECT) is allowed" };
    }

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";

    switch (atype) {
        case 1: // IPv4
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            address = Array.from(new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)))
                .map((byte) => byte.toString(16))
                .join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType: ${atype}` };
    }

    const portIndex = addressIndex + addressLength;
    const portRemote = new DataView(socks5DataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 2),
    };
}

// Create readable WebSocket stream
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;

    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (!readableStreamCancel) controller.enqueue(event.data);
            });

            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
            });

            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer error");
                controller.error(err);
            });
        },
        cancel(reason) {
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
}

// Safely close WebSocket
function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === 1 || socket.readyState === 2) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

// Export the Worker
export { worker_default as default };
