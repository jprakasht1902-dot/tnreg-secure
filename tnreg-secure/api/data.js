export default async function handler(req, res) {
  const BIN_ID = "6976c3a5d0ea881f40858480";
  const KEY = process.env.JSONBIN_KEY;

  try {
    // 🔹 GET data
    if (req.method === "GET") {
      const r = await fetch(`https://api.jsonbin.io/v3/b/${BIN_ID}/latest`, {
        headers: { "X-Master-Key": KEY }
      });
      const data = await r.json();
      return res.status(200).json(data);
    }

    // 🔹 SAVE data
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
