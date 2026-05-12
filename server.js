// server.js
import express from 'express';

// --- Configuration ---
// IMPORTANT: Change this to a truly strong, random secret!
const PSK = "sfjwejfiwoefjfuefiuw3826FGEYUG232"; 

// Headers to strip for security
const STRIP_HEADERS = new Set([
  "host", "connection", "content-length", "transfer-encoding",
  "proxy-connection", "proxy-authorization", "x-forwarded-for",
  "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
  "x-real-ip", "forwarded", "via",
]);

// Helper functions
function sanitizeHeaders(h) {
  const out = {};
  if (!h || typeof h !== "object") return out;
  for (const [k, v] of Object.entries(h)) {
    if (!k) continue;
    if (STRIP_HEADERS.has(k.toLowerCase())) continue;
    out[k] = String(v ?? "");
  }
  return out;
}

function decodeBase64ToBytes(input) {
  const bin = atob(input);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function encodeBytesToBase64(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// --- Main Application Logic ---
const app = express();
app.use(express.json({ limit: '10mb' }));

app.post('/relay', async (req, res) => {
  try {
    const { k, u, m = "GET", h = {}, b } = req.body;

    if (k !== PSK) {
      return res.status(401).json({ e: "unauthorized" });
    }
    if (!/^https?:\/\//i.test(u)) {
      return res.status(400).json({ e: "bad url" });
    }

    const fetchOptions = {
      method: m.toUpperCase(),
      headers: sanitizeHeaders(h),
      redirect: "manual",
    };
    if (typeof b === "string" && b.length > 0) {
      fetchOptions.body = decodeBase64ToBytes(b);
    }

    const resp = await fetch(u, fetchOptions);
    const data = new Uint8Array(await resp.arrayBuffer());

    const respHeaders = {};
    resp.headers.forEach((value, key) => { respHeaders[key] = value; });

    res.json({
      s: resp.status,
      h: respHeaders,
      b: encodeBytesToBase64(data),
    });
  } catch (err) {
    res.status(500).json({ e: err.message });
  }
});

// Keep the root path healthy for Render's checks
app.get('/', (req, res) => {
  res.send('Proxy is running.');
});

// --- Start the Server ---
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Proxy server listening on port ${port}`);
});
