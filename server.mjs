#!/usr/bin/env node
/**
 * Drop — 局域网文件速传
 *
 * 设计原则：
 * - 零 npm 依赖：node:http + node:fs 原生实现，安装即用，无供应链风险。
 * - 安全边界：写操作（上传/删除）要求 PIN；回环地址（本机访问）免验。
 * - 上传用 multipart/form-data 流式解析（自实现，无第三方），文件落盘 UPLOAD_DIR。
 * - 供 Toolbelt 托管：PORT 由环境变量注入；传文件页展示局域网地址 + 二维码（前端生成）。
 */

import http from "node:http";
import { execFile } from "node:child_process";
import fs from "node:fs";
import { createReadStream } from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

const PORT = Number(process.env.PORT) || 4210;
const HOST = "0.0.0.0"; // 局域网可达；回环访问免 PIN
const UPLOAD_DIR = process.env.DROP_UPLOAD_DIR || path.join(os.homedir(), "Downloads", "Drop");
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024; // 2GB

// PIN：持久化到配置文件，重启不变
const CONFIG_FILE = path.join(UPLOAD_DIR, ".drop-config.json");
async function loadOrCreatePin() {
  try {
    const cfg = JSON.parse(await fsp.readFile(CONFIG_FILE, "utf-8"));
    if (typeof cfg.pin === "string" && /^\d{6}$/.test(cfg.pin)) return cfg.pin;
  } catch {
    // 首次运行
  }
  const pin = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
  await fsp.mkdir(UPLOAD_DIR, { recursive: true });
  await fsp.writeFile(CONFIG_FILE, JSON.stringify({ pin }, null, 2));
  return pin;
}
let PIN = await loadOrCreatePin();

// 回环会话签名：本机验证通过一次后，用 HMAC cookie 免验后续请求
const SESSION_SECRET = crypto.randomBytes(32);
function loopbackSessionToken() {
  return crypto.createHmac("sha256", SESSION_SECRET).update("loopback-session").digest("hex");
}

function isLoopback(address) {
  return address === "127.0.0.1" || address === "::1" || address?.startsWith("::ffff:127.");
}

// ---------------------------------------------------------------------------
// multipart/form-data 流式解析（自实现）
// ---------------------------------------------------------------------------

function parseBoundary(contentType) {
  const match = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType || "");
  return match ? (match[1] || match[2]).trim() : null;
}

async function readMultipartFile(req, boundary, onProgress) {
  const delim = Buffer.from(`\r\n--${boundary}`);
  let buffer = Buffer.alloc(0);
  let queue = Promise.resolve();
  let finished = false;
  let fail = null;
  let result = null;
  // 当前 part 状态
  let part = null; // { type: "file", name, handle, size } | { type: "field", name, chunks }

  async function processChunk(chunk) {
    buffer = buffer.length ? Buffer.concat([buffer, chunk]) : chunk;
    for (;;) {
      if (!part) {
        // 首个 boundary 无前导 \r\n（body 以 --boundary 开头），优先判断
        const lead = `--${boundary}`;
        if (buffer.subarray(0, lead.length).toString("latin1") === lead) {
          buffer = buffer.subarray(lead.length);
        } else {
          const idx = buffer.indexOf(delim);
          if (idx === -1) {
            // 保留尾部防止半个分隔符
            if (buffer.length > 64 * 1024) buffer = buffer.subarray(-64 * 1024);
            return;
          }
          buffer = buffer.subarray(idx + delim.length);
        }
        // header 结束：\r\n\r\n
        const headEnd = buffer.indexOf(Buffer.from("\r\n\r\n"));
        if (headEnd === -1) return; // header 未到齐，等下一 chunk
        const header = buffer.subarray(0, headEnd).toString("utf-8");
        buffer = buffer.subarray(headEnd + 4);
        const disposition = /Content-Disposition:[^\r\n]*/i.exec(header)?.[0] ?? "";
        const fileMatch = /filename="([^"]*)"/.exec(disposition);
        const nameMatch = /name="([^"]*)"/.exec(disposition);
        if (!fileMatch) {
          // 只接受文件 part；非文件 part 忽略其内容
          part = { type: "skip" };
        } else {
          let fileName = path.basename(fileMatch[1] || `upload-${Date.now()}`).replace(/[\\/:*?"<>|]/g, "_");
          part = { type: "file", name: fileName, handle: await fsp.open(path.join(UPLOAD_DIR, fileName), "w"), size: 0 };
        }
      }

      // part 已开：写数据直到下一个 boundary
      const next = buffer.indexOf(delim);
      if (next === -1) {
        if (part.type === "skip") {
          buffer = buffer.subarray(buffer.length - 4);
          return;
        }
        // 数据未完：除最后 4 字节（可能是半个分隔符）外全部写入
        const safe = buffer.length > 4 ? buffer.subarray(0, buffer.length - 4) : Buffer.alloc(0);
        if (part.type === "file") {
          if (safe.length) {
            await part.handle.write(safe);
            part.size += safe.length;
            onProgress?.(part.size);
          }
          buffer = buffer.subarray(buffer.length - 4);
        }
        return;
      }
      // part 数据到 boundary 为止
      const data = buffer.subarray(0, next);
      if (part.type === "file") {
        if (data.length) {
          await part.handle.write(data);
          part.size += data.length;
        }
        await part.handle.close();
        result = { fileName: part.name, size: part.size };
      }
      buffer = buffer.subarray(next + delim.length);
      part = null;
      // 若紧跟 "--" 则结束
      if (buffer.subarray(0, 2).toString() === "--") {
        finished = true;
        return;
      }
    }
  }

  await new Promise((resolve, reject) => {
    req.on("error", reject);
    req.on("aborted", () => {
      fail = new Error("Upload aborted");
      resolve();
    });
    req.on("data", (chunk) => {
      if (finished) return;
      // 串行化处理，杜绝 async 重入错序
      queue = queue.then(() => processChunk(chunk)).catch((err) => {
        fail = err;
        req.destroy();
      });
    });
    req.on("end", () => {
      // 冲刷残留：数据分支只消费到"倒数4字节"，结束时用假边界把最后一段推出来
      queue = queue.then(() => processChunk(Buffer.concat([buffer, Buffer.from(`\r\n--${boundary}`)]) && Buffer.alloc(0))).catch(() => {});
      // 直接在收尾时处理尾部数据
      queue = queue.then(async () => {
        if (finished || fail) return;
        const idx = buffer.indexOf(delim);
        const data = idx === -1 ? buffer : buffer.subarray(0, idx);
        if (part?.type === "file" && data.length) {
          await part.handle.write(data);
          part.size += data.length;
        }
        if (part?.type === "file") {
          await part.handle.close();
          result = { fileName: part.name, size: part.size };
        }
        finished = true;
      }).catch((err) => { fail = err; });
      queue.then(resolve).catch(reject);
    });
  });

  if (fail) throw fail;
  if (!finished) throw new Error("Malformed multipart body");
  return result;
}

// ---------------------------------------------------------------------------
// HTTP 服务
// ---------------------------------------------------------------------------

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".pdf": "application/pdf",
};

function lanAddresses() {
  const out = [];
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const iface of ifaces ?? []) {
      if (iface.family === "IPv4" && !iface.internal) out.push(iface.address);
    }
  }
  return out;
}

function json(res, code, data) {
  res.writeHead(code, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(data));
}

async function authorized(req, res) {
  if (isLoopback(req.socket.remoteAddress)) return true;
  const url = new URL(req.url, "http://x");
  const pin = req.headers["x-drop-pin"] || url.searchParams.get("pin");
  if (pin === PIN) return true;
  const cookies = Object.fromEntries(
    (req.headers.cookie || "").split("; ").filter(Boolean).map((c) => c.split("=")),
  );
  if (cookies.drop_session === loopbackSessionToken()) {
    // 外网会话令牌仅在本次进程有效，主要方便调试；正常使用路径是 PIN
    return true;
  }
  json(res, 401, { error: "需要 PIN 码" });
  return false;
}

const INDEX_HTML = await fsp.readFile(new URL("./public/index.html", import.meta.url), "utf-8");

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const send = (code, body, headers = {}) => {
    res.writeHead(code, headers);
    res.end(body);
  };

  try {
    // 静态资源
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      return send(200, INDEX_HTML, { "Content-Type": MIME[".html"] });
    }
    if (req.method === "GET" && url.pathname === "/public/app.js") {
      return send(
        200,
        await fsp.readFile(new URL("./public/app.js", import.meta.url), "utf-8"),
        { "Content-Type": MIME[".js"] },
      );
    }
    if (req.method === "GET" && url.pathname === "/public/app.css") {
      return send(
        200,
        await fsp.readFile(new URL("./public/app.css", import.meta.url), "utf-8"),
        { "Content-Type": MIME[".css"] },
      );
    }

    // 局域网地址 + PIN（本机可读，供前端生成二维码）
    if (req.method === "GET" && url.pathname === "/api/info") {
      return json(res, 200, {
        addresses: lanAddresses(),
        port: PORT,
        pin: isLoopback(req.socket.remoteAddress) ? PIN : undefined,
        uploadDir: UPLOAD_DIR,
      });
    }

    // 在访达中打开接收目录（macOS）
    if (req.method === "POST" && url.pathname === "/api/reveal") {
      if (!isLoopback(req.socket.remoteAddress)) return json(res, 403, { error: "仅限本机操作" });
      if (process.platform !== "darwin") return json(res, 501, { error: "仅 macOS 支持" });
      execFile("open", [UPLOAD_DIR]);
      return json(res, 200, { ok: true });
    }

    // 文件列表
    if (req.method === "GET" && url.pathname === "/api/files") {
      if (!(await authorized(req, res))) return;
      const names = await fsp.readdir(UPLOAD_DIR);
      const files = [];
      for (const name of names) {
        if (name.startsWith(".")) continue;
        const stat = await fsp.stat(path.join(UPLOAD_DIR, name));
        if (stat.isFile()) files.push({ name, size: stat.size, mtime: stat.mtimeMs });
      }
      files.sort((a, b) => b.mtime - a.mtime);
      return json(res, 200, { files });
    }

    // 上传
    if (req.method === "POST" && url.pathname === "/api/upload") {
      if (!(await authorized(req, res))) return;
      const boundary = parseBoundary(req.headers["content-type"]);
      if (!boundary) return json(res, 400, { error: "需要 multipart/form-data" });
      const result = await readMultipartFile(req, boundary);
      if (!result?.fileName) return json(res, 400, { error: "未收到文件" });
      return json(res, 200, { ok: true, ...result });
    }

    // 下载（支持范围请求略过 v1；浏览器直接全量下载）
    if (req.method === "GET" && url.pathname.startsWith("/api/download/")) {
      if (!(await authorized(req, res))) return;
      const name = path.basename(decodeURIComponent(url.pathname.slice("/api/download/".length)));
      const filePath = path.join(UPLOAD_DIR, name);
      if (!existsInUploadDir(name)) return json(res, 404, { error: "文件不存在" });
      const stat = await fsp.stat(filePath);
      res.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Length": stat.size,
        "Content-Disposition": `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
      });
      return createReadStream(filePath).pipe(res);
    }

    // 删除
    if (req.method === "DELETE" && url.pathname.startsWith("/api/files/")) {
      if (!(await authorized(req, res))) return;
      const name = path.basename(decodeURIComponent(url.pathname.slice("/api/files/".length)));
      if (!existsInUploadDir(name)) return json(res, 404, { error: "文件不存在" });
      await fsp.rm(path.join(UPLOAD_DIR, name));
      return json(res, 200, { ok: true });
    }

    send(404, "Not Found");
  } catch (err) {
    console.error("[drop]", err.message);
    if (!res.headersSent) json(res, 500, { error: err.message });
    else res.end();
  }
});

function existsInUploadDir(name) {
  const filePath = path.join(UPLOAD_DIR, name);
  const rel = path.relative(UPLOAD_DIR, filePath);
  return !rel.startsWith("..") && fs.existsSync(filePath) && fs.statSync(filePath).isFile();
}

server.listen(PORT, HOST, () => {
  console.log(`[drop] listening on http://127.0.0.1:${PORT}`);
  console.log(`[drop] LAN: ${lanAddresses().map((a) => `http://${a}:${PORT}`).join(", ") || "n/a"}`);
  console.log(`[drop] uploads → ${UPLOAD_DIR}`);
});
