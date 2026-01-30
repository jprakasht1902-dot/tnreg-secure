import crypto from "crypto";

// ================= CONFIG =================
const BIN_ID = process.env.JSONBIN_BIN_ID;
const JSONBIN_KEY = process.env.JSONBIN_KEY;
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY; // MUST be exactly 32 bytes
const IV_LENGTH = 16;
const ALGORITHM = "aes-256-cbc";

// Add "Bearer " prefix to match client headers
const API_SECRET_READ = `Bearer ${process.env.API_SECRET_READ}`;
const API_SECRET_WRITE = `Bearer ${process.env.API_SECRET_WRITE}`;

// Fields to Encrypt/Decrypt
const SENSITIVE_FIELDS = [
  "aad1", "aad2", "aad3",
  "ph1", "ph2",
  "name", "parent", "husband", "father", "guardianName",
  "dist", "taluk", "village", "street", "door"
];

// ================= SECURITY HELPERS =================
const maskPhone = p => p ? "******" + p.slice(-4) : "";
const maskAadhaar = a => a ? "XXXX XXXX " + a.slice(-4) : "";
const maskName = n => n ? n[0] + "*".repeat(n.length - 1) : "";

// ================= ENCRYPTION ENGINE =================
function getKey() {
  // Ensure key is buffer
  const keyBuffer = Buffer.from(ENCRYPTION_KEY);
  if (keyBuffer.length !== 32) {
    throw new Error("ENCRYPTION_KEY must be exactly 32 bytes");
  }
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
  } catch (e) {
    console.error("Encrypt Error:", e);
    return text;
  }
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
  } catch (e) {
    console.error("Decrypt Error:", e);
    return text; // Return original if fail
  }
}

// ================= OBJECT RECURSION =================
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

// Mask data for frontend display
function maskRecord(record) {
  if (!Array.isArray(record)) return record;
  return record.map(r => ({
    ...r,
    partyData: r.partyData ? {
      ...r.partyData,
      buyers: (r.partyData.buyers || []).map(b => ({
        ...b,
        name: maskName(b.name),
        ph1: maskPhone(b.ph1),
        aad3: maskAadhaar(b.aad3)
      })),
      sellers: (r.partyData.sellers || []).map(s => ({
        ...s,
        name: maskName(s.name),
        ph1: maskPhone(s.ph1),
        aad3: maskAadhaar(s.aad3)
      }))
    } : r.partyData
  }));
}

// ================= MAIN HANDLER =================
export default async function handler(req, res) {
  // CORS Configuration
  const allowedOrigins = [
    "https://tnreg.wapka.site",
    "http://localhost:3000",
    "http://127.0.0.1:5500" // Added for local testing
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else {
    // Optional: Allow all during development, restrict in production
    res.setHeader("Access-Control-Allow-Origin", "*"); 
  }
  
  res.setHeader("Access-Control-Allow-Methods", "GET,PUT,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");

  // Handle Preflight
  if (req.method === "OPTIONS") return res.status(200).end();

  // Validate Env Vars
  if (!BIN_ID || !JSONBIN_KEY || !ENCRYPTION_KEY) {
    return res.status(500).json({ error: "Server Misconfigured (Missing ENVs)" });
  }

  const authHeader = req.headers.authorization;

  try {
    // ================= GET REQUEST =================
    if (req.method === "GET") {
      // 1. Auth Check
      if (authHeader !== API_SECRET_READ && authHeader !== API_SECRET_WRITE) {
        return res.status(401).json({ error: "Unauthorized Access" });
      }

      // 2. Fetch from Database (JSONBin)
      const response = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
        headers: { "X-Master-Key": JSONBIN_KEY }
      });

      if (!response.ok) throw new Error("Database Fetch Failed");

      const bin = await response.json();
      const rawData = bin.record || []; // Handle case where record is wrapper

      // 3. Decrypt Data (Server Side)
      const decryptedData = decryptObject(rawData);

      // 4. Mask Data (For Security)
      // Note: If users need to EDIT data, you might need a query param (e.g., ?edit=true)
      // to skip masking, provided they have WRITE permission.
      const safeData = maskRecord(decryptedData);

      return res.status(200).json({ record: safeData });
    }

    // ================= PUT REQUEST =================
    if (req.method === "PUT") {
      // 1. Strict Auth Check (Write Access Only)
      if (authHeader !== API_SECRET_WRITE) {
        return res.status(401).json({ error: "Write Access Denied" });
      }

      // 2. Encrypt Incoming Data
      // IMPORTANT: Ensure frontend sends unmasked data, or existing data will be lost!
      const encryptedData = encryptObject(req.body);

      // 3. Save to Database
      const response = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Master-Key": JSONBIN_KEY
        },
        body: JSON.stringify(encryptedData)
      });

      if (!response.ok) throw new Error("Database Update Failed");

      const result = await response.json();
      return res.status(200).json({ success: true, metadata: result.metadata });
    }

    // Method Not Allowed
    return res.status(405).json({ error: "Method not allowed" });

  } catch (err) {
    console.error("API Error:", err);
    return res.status(500).json({ error: "Internal Server Error", details: err.message });
  }
}
