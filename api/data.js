export default async function handler(req, res) {
  // --- 1. ADD CORS HEADERS (CRITICAL FOR CONNECTION) ---
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*'); // Allows Login Repo to talk to Secure Repo
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  // Handle browser pre-flight checks
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // --- 2. YOUR ORIGINAL LOGIC ---
  const BIN_ID = "6976c3a5d0ea881f40858480";
  const KEY = process.env.JSONBIN_KEY;

  try {
    if (req.method === "GET") {
      const r = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
        headers: { "X-Master-Key": KEY }
      });
      const data = await r.json();
      return res.status(200).json(data);
    }

    if (req.method === "PUT") {
      const r = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "X-Master-Key": KEY
        },
        body: JSON.stringify(req.body)
      });
      const data = await r.json();
      return res.status(200).json(data);
    }

    res.status(405).json({ error: "Method not allowed" });

  } catch (err) {
    res.status(500).json({ error: "Server error", details: err.message });
  }
}
