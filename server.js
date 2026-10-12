
import net from "node:net";
import { timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 443);
const SECRET = String(process.env.RELAY_SECRET || "");
const MAX_SECRET_LENGTH = 256;

if (!SECRET) {
  console.error("RELAY_SECRET is required");
  process.exit(1);
}

const expectedSecret = Buffer.from(SECRET, "utf8");

if (
  expectedSecret.length < 16 ||
  expectedSecret.length > MAX_SECRET_LENGTH
) {
  console.error("Invalid RELAY_SECRET length");
  process.exit(1);
}

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error("Invalid PORT");
  process.exit(1);
}

const server = net.createServer(client => {
  client.setNoDelay(true);

  let remote = null;
  let buffer = Buffer.alloc(0);
  let stage = "secretLength";
  let secretLength = 0;
  let hostLength = 0;
  let finished = false;
  let connectTimer = null;

  const timer = setTimeout(() => {
    if (stage !== "connected") {
      reject("Handshake timeout");
    }
  }, 10000);

  function reject(reason) {
    if (finished) return;

    finished = true;
    clearTimeout(timer);
    clearTimeout(connectTimer);

    console.log("REJECT:", reason);

    client.destroy();
    remote?.destroy();
  }

  function onData(chunk) {
    if (finished) return;

    buffer = Buffer.concat([buffer, chunk]);

    while (true) {
      if (stage === "secretLength") {
        if (buffer.length < 2) return;

        secretLength = buffer.readUInt16BE(0);
        buffer = buffer.subarray(2);

        if (
          secretLength < 16 ||
          secretLength > MAX_SECRET_LENGTH
        ) {
          return reject("Invalid secret length");
        }

        stage = "secret";
      }

      if (stage === "secret") {
        if (buffer.length < secretLength) return;

        const received = buffer.subarray(0, secretLength);
        buffer = buffer.subarray(secretLength);

        if (
          received.length !== expectedSecret.length ||
          !timingSafeEqual(received, expectedSecret)
        ) {
          return reject("Authentication failed");
        }

        stage = "hostLength";
      }

      if (stage === "hostLength") {
        if (buffer.length < 2) return;

        hostLength = buffer.readUInt16BE(0);
        buffer = buffer.subarray(2);

        if (hostLength < 1 || hostLength > 255) {
          return reject("Invalid host length");
        }

        stage = "target";
      }

      if (stage === "target") {
        if (buffer.length < hostLength + 2) return;

        const host = buffer
          .subarray(0, hostLength)
          .toString("utf8");

        const port = buffer.readUInt16BE(hostLength);
        const payload = buffer.subarray(hostLength + 2);

        buffer = Buffer.alloc(0);
        stage = "connecting";

        if (
          !host ||
          /[\0\r\n]/.test(host) ||
          !Number.isInteger(port) ||
          port < 1 ||
          port > 65535
        ) {
          return reject("Invalid destination");
        }

        clearTimeout(timer);

        client.pause();
        client.removeListener("data", onData);

        try {
          remote = net.connect({ host, port });
          remote.setNoDelay(true);

          let acknowledged = false;

          connectTimer = setTimeout(() => {
            if (!acknowledged) {
              console.log("REMOTE CONNECT TIMEOUT:", host, port);

              if (!client.destroyed) {
                client.end(Buffer.from([1]));
              }

              remote.destroy();
            }
          }, 10000);

          remote.once("connect", () => {
            if (finished) {
              clearTimeout(connectTimer);
              return remote.destroy();
            }

            acknowledged = true;
            clearTimeout(connectTimer);

            stage = "connected";

            console.log("CONNECTED:", host, port);

            // Gateway expects 0 for success.
            client.write(Buffer.from([0]));

            if (payload.length) {
              remote.write(payload);
            }

            client.pipe(remote);
            remote.pipe(client);
            client.resume();
          });

          remote.on("error", err => {
            console.log("REMOTE ERROR:", err.message);
            clearTimeout(connectTimer);

            if (!acknowledged && !client.destroyed) {
              client.end(Buffer.from([1]));
            } else {
              client.destroy();
            }
          });

          remote.on("close", () => {
            clearTimeout(connectTimer);

            if (!acknowledged && !client.destroyed) {
              client.end(Buffer.from([1]));
            } else if (!client.destroyed) {
              client.destroy();
            }
          });
        } catch (err) {
          reject(err.message);
        }

        return;
      }

      return;
    }
  }

  client.on("data", onData);

  client.on("error", err => {
    console.log("CLIENT ERROR:", err.message);
    remote?.destroy();
  });

  client.on("close", () => {
    finished = true;
    clearTimeout(timer);
    clearTimeout(connectTimer);
    remote?.destroy();
  });
});

server.on("error", err => {
  console.error("SERVER ERROR:", err);
  process.exitCode = 1;
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("Authenticated TCP Relay listening on", PORT);
});
