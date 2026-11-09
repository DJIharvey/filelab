const { getStore } = require("@netlify/blobs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const SECRET = process.env.APP_SECRET || "filelab-secret-change-me-please";

function json(status, data) {
  return {
    statusCode: status,
    headers: {
      "content-type": "application/json",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type, authorization"
    },
    body: JSON.stringify(data)
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: { "access-control-allow-origin": "*", "access-control-allow-headers": "content-type, authorization" } };
  }

  try {
    const store = getStore("filelab");
    let path = event.path || "/";
    path = path.replace(/^\/\.netlify\/functions\/filelab/, "") || "/";
    if (!path.startsWith("/")) path = "/" + path;
    const method = event.httpMethod;

    function getUser() {
      const h = event.headers.authorization || event.headers.Authorization || "";
      const token = h.replace(/^Bearer\s+/i, "");
      if (!token) return null;
      try { return jwt.verify(token, SECRET); } catch { return null; }
    }

    if (path.startsWith("/s/")) {
      const parts = path.slice(3).split("/").filter(Boolean);
      const slug = parts[0];
      let filePath = parts.slice(1).join("/") || "index.html";
      if (filePath.endsWith("/")) filePath += "index.html";
      const data = await store.get(`site:${slug}:${filePath}`, { type: "arrayBuffer" });
      if (!data) {
        const idx = await store.get(`site:${slug}:index.html`, { type: "arrayBuffer" });
        if (idx && !filePath.includes(".")) {
          return { statusCode: 200, headers: { "content-type": "text/html" }, body: Buffer.from(idx).toString("utf8") };
        }
        return { statusCode: 404, headers: { "content-type": "text/html" }, body: "<h1>Not found</h1>" };
      }
      const buf = Buffer.from(data);
      const ext = (filePath.split(".").pop() || "").toLowerCase();
      const types = { html: "text/html", css: "text/css", js: "application/javascript", json: "application/json", png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", svg: "image/svg+xml", txt: "text/plain" };
      return {
        statusCode: 200,
        headers: { "content-type": types[ext] || "application/octet-stream" },
        body: buf.toString("base64"),
        isBase64Encoded: true
      };
    }

    if (path === "/api/signup" && method === "POST") {
      const body = JSON.parse(event.body || "{}");
      const email = (body.email || "").toLowerCase().trim();
      const password = body.password || "";
      const name = body.name || email.split("@")[0];
      if (!email || !password || password.length < 8) return json(400, { error: "Email and password (8+ characters) required" });
      const users = (await store.get("users", { type: "json" })) || [];
      if (users.some(u => u.email === email)) return json(409, { error: "Email already used" });
      const user = { id: crypto.randomUUID(), email, name, hash: await bcrypt.hash(password, 10) };
      users.push(user);
      await store.setJSON("users", users);
      const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "30d" });
      return json(200, { token, user: { id: user.id, email: user.email, name: user.name } });
    }

    if (path === "/api/login" && method === "POST") {
      const body = JSON.parse(event.body || "{}");
      const email = (body.email || "").toLowerCase().trim();
      const password = body.password || "";
      const users = (await store.get("users", { type: "json" })) || [];
      const user = users.find(u => u.email === email);
      if (!user || !(await bcrypt.compare(password, user.hash))) return json(401, { error: "Wrong email or password" });
      const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "30d" });
      return json(200, { token, user: { id: user.id, email: user.email, name: user.name } });
    }

    const user = getUser();
    if (path.startsWith("/api/") && !user) return json(401, { error: "Sign in required" });

    if (path === "/api/me" && method === "GET") {
      const users = (await store.get("users", { type: "json" })) || [];
      const u = users.find(x => x.id === user.id);
      return u ? json(200, { id: u.id, email: u.email, name: u.name }) : json(404, { error: "Not found" });
    }

    if (path === "/api/sites" && method === "GET") {
      const sites = (await store.get("sites", { type: "json" })) || [];
      return json(200, { sites: sites.filter(s => s.userId === user.id).map(s => ({ ...s, url: `/s/${s.slug}/` })) });
    }

    if (path === "/api/sites" && method === "POST") {
      const { name } = JSON.parse(event.body || "{}");
      if (!name) return json(400, { error: "Name required" });
      const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40);
      if (slug.length < 2) return json(400, { error: "Name too short" });
      const sites = (await store.get("sites", { type: "json" })) || [];
      if (sites.some(s => s.slug === slug)) return json(409, { error: "That name is taken" });
      const site = { id: crypto.randomUUID(), userId: user.id, name, slug, created: Date.now() };
      sites.push(site);
      await store.setJSON("sites", sites);
      await store.set(`site:${slug}:index.html`, `<!doctype html><meta charset=utf-8><title>${name}</title><body style="font-family:system-ui;background:#111;color:#eee;display:grid;place-items:center;height:100vh;margin:0"><div><h1>${name}</h1><p>Live on FileLab</p></div>`);
      return json(201, { site: { ...site, url: `/s/${slug}/` } });
    }

    if (path.startsWith("/api/sites/") && path.endsWith("/deploy") && method === "POST") {
      return json(400, { error: "File upload needs the full version. Create the site first — a starter page is already live." });
    }

    if (path.startsWith("/api/sites/") && method === "DELETE") {
      const id = path.split("/")[3];
      let sites = (await store.get("sites", { type: "json" })) || [];
      sites = sites.filter(s => !(s.id === id && s.userId === user.id));
      await store.setJSON("sites", sites);
      return json(200, { ok: true });
    }

    return json(404, { error: "Not found", path, method });
  } catch (err) {
    console.error(err);
    return json(500, { error: err.message || "Server error" });
  }
};
