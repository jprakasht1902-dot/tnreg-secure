import crypto from "crypto";

// ================= CONFIG =================
const BIN_ID = process.env.JSONBIN_BIN_ID;
const JSONBIN_KEY = process.env.JSONBIN_KEY;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; 
const IV_LENGTH = 16;
const ALGORITHM = "aes-256-cbc";

const API_SECRET_READ = `Bearer ${process.env.API_SECRET_READ}`;
const API_SECRET_WRITE = `Bearer ${process.env.API_SECRET_WRITE}`;

const SENSITIVE_FIELDS = [
  "aad1", "aad2", "aad3",
  "ph1", "ph2",
  "name", "parent", "husband", "father", "guardianName",
  "dist", "taluk", "village", "street", "door"
];

// ================= SECURITY HELPERS (UPDATED) =================
// 1. Phone: Mask first 6 digits, show last 4
const maskPhone = p => p ? "******" + p.slice(-4) : "";

// 2. Aadhaar: Mask first 8 digits, show last 4
const maskAadhaar = a => a ? "XXXX XXXX " + a.slice(-4) : "";

// 3. Name/Text: SHOW ALPHABETS, MASK NUMBERS (As requested)
// "John Doe" -> "John Doe"
// "Door 24" -> "Door **"
const maskTextPreserveAlpha = n => n ? n.replace(/[0-9]/g, "*") : ""; 

// ================= ENCRYPTION ENGINE =================
function getKey() {
  const keyBuffer = Buffer.from(ENCRYPTION_KEY);
  if (keyBuffer.length !== 32) throw new Error("ENCRYPTION_KEY must be 32 bytes");
  return keyBuffer;
}

function encrypt(text) {
  if (!text) return text;
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, getKey(), iv);
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return iv.toString("hex") + ":" + encrypted;
  } catch (e) { console.error("Encrypt Error:", e); return text; }
}

function decrypt(text) {
  if (!text || !text.includes(":")) return text;
  try {
    const [ivHex, encrypted] = text.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const decipher = crypto.createDecipheriv(ALGORITHM, getKey(), iv);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (e) { console.error("Decrypt Error:", e); return text; }
}

function encryptObject(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const result = Array.isArray(obj) ? [] : {};
  for (const key in obj) {
    const value = obj[key];
    if (SENSITIVE_FIELDS.includes(key) && typeof value === "string") {
      result[key] = encrypt(value);
    } else if (typeof value === "object" && value !== null) {
      result[key] = encryptObject(value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

function decryptObject(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const result = Array.isArray(obj) ? [] : {};
  for (const key in obj) {
    const value = obj[key];
    if (SENSITIVE_FIELDS.includes(key) && typeof value === "string") {
      result[key] = decrypt(value);
    } else if (typeof value === "object" && value !== null) {
      result[key] = decryptObject(value);
    } else {
      result[key] = value;
    }
  }
  return result;
}

// ================= MASKING LOGIC (UPDATED) =================
function maskRecord(record) {
  if (!Array.isArray(record)) return record;
  return record.map(r => ({
    ...r, 
    partyData: r.partyData ? {
      ...r.partyData, 
      // Apply "Alpha Visible / Numeric Hidden" rule to Name
      buyers: (r.partyData.buyers || []).map(b => ({
        ...b,
        name: maskTextPreserveAlpha(b.name), 
        ph1: maskPhone(b.ph1),
        aad3: maskAadhaar(b.aad3)
      })),
      sellers: (r.partyData.sellers || []).map(s => ({
        ...s,
        name: maskTextPreserveAlpha(s.name),
        ph1: maskPhone(s.ph1),
        aad3: maskAadhaar(s.aad3)
      }))
    } : r.partyData
  }));
}

// ================= MAIN HANDLER =================
export default async function handler(req, res) {
  const allowedOrigins = ["https://tnreg.wapka.site", "http://localhost:3000", "http://127.0.0.1:5500"];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin) || !origin) {
    res.setHeader("Access-Control-Allow-Origin", origin || "*");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,PUT,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");

  if (req.method === "OPTIONS") return res.status(200).end();

  if (!BIN_ID || !JSONBIN_KEY || !ENCRYPTION_KEY) {
    return res.status(500).json({ error: "Server Misconfigured" });
  }

  const authHeader = req.headers.authorization;

  try {
    if (req.method === "GET") {
      if (authHeader !== API_SECRET_READ && authHeader !== API_SECRET_WRITE) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const response = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
        headers: { "X-Master-Key": JSONBIN_KEY }
      });
      if (!response.ok) throw new Error("DB Error");
      
      const bin = await response.json();
      const rawData = bin.record || []; 

      const decryptedData = decryptObject(rawData);

      // If ?unmask=true is sent, show everything (Edit Mode)
      // If NOT sent, use the new mask logic (Dashboard Mode)
      const isUnmaskRequested = req.query.unmask === "true";
      const finalData = isUnmaskRequested ? decryptedData : maskRecord(decryptedData);

      return res.status(200).json({ record: finalData });
    }

    if (req.method === "PUT") {
      if (authHeader !== API_SECRET_WRITE) return res.status(401).json({ error: "Denied" });
      const encryptedData = encryptObject(req.body);
      const response = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Master-Key": JSONBIN_KEY },
        body: JSON.stringify(encryptedData)
      });
      if (!response.ok) throw new Error("Update Failed");
      return res.status(200).json({ success: true });
    }

    return res.status(405).json({ error: "Method not allowed" });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server Error", details: err.message });
  }
}
