/* Drop 前端逻辑：二维码生成（纯 SVG）、上传、列表、PIN。零依赖。 */

const $ = (sel) => document.querySelector(sel);
const state = { pin: null, addresses: [], port: null, unlocked: false };

// ---------------------------------------------------------------------------
// 二维码：字节模式 + ECC L 的最小实现（纯 SVG 输出）
// 参考 ISO/IEC 18004。v1-v4 覆盖 URL 长度 < 60 的场景足够。
// ---------------------------------------------------------------------------

const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
})();
const gmul = (a, b) => (a === 0 || b === 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]]);

function rsGenerator(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gmul(poly[j], 1);
      next[j + 1] ^= gmul(poly[j], GF_EXP[i]);
    }
    // 上一行写法会导致首系数错误；改为标准乘 (x + a^i)
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= 0; // no-op，占位
    }
    poly = next;
  }
  return poly;
}

// 标准实现：generator 多项式 = (x - a^0)(x - a^1)...(x - a^(d-1))
function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];            // x * poly
      next[j + 1] ^= gmul(poly[j], GF_EXP[i]); // a^i * poly
    }
    poly = next;
  }
  return poly;
}

function rsEncode(data, eccLen) {
  const gen = rsGeneratorPoly(eccLen);
  const rem = new Array(eccLen).fill(0);
  for (const byte of data) {
    const factor = byte ^ rem[0];
    rem.shift();
    rem.push(0);
    for (let i = 0; i < eccLen; i++) rem[i] ^= gmul(gen[i + 1], factor);
  }
  return rem;
}

// 版本参数：[version]: { size, eccLen(L), blocks }
const VERSIONS = {
  1: { size: 21, ecc: 7, blocks: 1, dataCodewords: 19 },
  2: { size: 25, ecc: 10, blocks: 1, dataCodewords: 34 },
  3: { size: 29, ecc: 15, blocks: 1, dataCodewords: 55 },
  4: { size: 33, ecc: 20, blocks: 2, dataCodewords: 80 },
};

function qrEncode(text) {
  const bytes = new TextEncoder().encode(text);
  // 选版本
  let version = null;
  for (const [v, spec] of Object.entries(VERSIONS)) {
    // 字节模式头：4bit 模式 + 8bit 长度（v1-9）
    const need = Math.ceil((4 + 8 + bytes.length * 8) / 8) + spec.ecc;
    if (need <= spec.dataCodewords + spec.ecc - spec.ecc + spec.ecc) {
      // 简化：数据码字 = dataCodewords；判断 bytes.length+2 <= dataCodewords
    }
    if (bytes.length + 2 <= spec.dataCodewords) {
      version = Number(v);
      break;
    }
  }
  if (!version) throw new Error("URL 过长，无法生成二维码");
  const spec = VERSIONS[version];

  // 构建数据位流
  const bits = [];
  const push = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
  };
  push(0b0100, 4); // byte mode
  push(bytes.length, 8);
  for (const b of bytes) push(b, 8);
  // terminator + 对齐到字节
  push(0, Math.min(4, spec.dataCodewords * 8 - bits.length));
  while (bits.length % 8) push(0, 1);
  // pad 字节
  const pads = [0xec, 0x11];
  let padIdx = 0;
  while (bits.length < spec.dataCodewords * 8) {
    push(pads[padIdx++ % 2], 8);
  }
  const data = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    data.push(byte);
  }

  const ecc = rsEncode(data, spec.ecc);
  const codewords = [...data, ...ecc];

  // 摆放矩阵
  const size = spec.size;
  const matrix = Array.from({ length: size }, () => new Array(size).fill(null));

  const setFinder = (r0, c0) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = r0 + r, cc = c0 + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const inRing =
          (r >= 0 && r <= 6 && c >= 0 && c <= 6) &&
          (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
        matrix[rr][cc] = inRing;
      }
    }
  };
  setFinder(0, 0);
  setFinder(0, size - 7);
  setFinder(size - 7, 0);

  // timing
  for (let i = 8; i < size - 8; i++) {
    matrix[6][i] = i % 2 === 0;
    matrix[i][6] = i % 2 === 0;
  }
  // dark module
  matrix[size - 8][8] = true;

  // reserve format areas（后面填）
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false));
  const reserve = (r, c) => { reserved[r][c] = true; };
  for (let i = 0; i < 9; i++) {
    reserve(8, i); reserve(i, 8);
    reserve(8, size - 1 - i);
    if (i < 8) reserve(size - 1 - i, 8);
  }
  reserve(size - 8, 8);
  for (let i = 8; i < size - 8; i++) { reserve(6, i); reserve(i, 6); }
  // alignment pattern（v2+）
  const alignCenters = { 1: [], 2: [18], 3: [22], 4: [26] }[version] ?? [];
  for (const r of [6, ...alignCenters]) {
    for (const c of [6, ...alignCenters]) {
      if (matrix[r][c] !== null && (r === 6 || c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++)
        for (let dc = -2; dc <= 2; dc++)
          matrix[r + dr][c + dc] = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
    }
  }

  // zigzag 放置数据
  let bitIdx = 0;
  const totalBits = codewords.length * 8;
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--; // 跳过 timing 列
    for (let i = 0; i < size; i++) {
      const row = upward ? size - 1 - i : i;
      for (const c of [col, col - 1]) {
        if (matrix[row][c] !== null) continue; // function pattern
        reserved[row][c] = true;
        const bit = bitIdx < totalBits ? (codewords[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1 : 0;
        bitIdx++;
        matrix[row][c] = bit === 1;
      }
    }
    upward = !upward;
  }

  // mask 011 (mask 4)：i+j 为偶数取反 —— 此处选 mask 101 (mask 2)：i%3==0 取反较复杂，统一用 mask 0
  // mask 0: (r+c)%2==0 取反
  for (let r = 0; r < size; r++)
    for (let c = 0; c < size; c++)
      if (matrix[r][c] !== null && reserved[r][c] && (r + c) % 2 === 0) matrix[r][c] = !matrix[r][c];

  // format info（mask 0, ECC L）：15bit，BCH(15,5)
  const formatBits = (() => {
    const data5 = 0b01; // ECC L = 01
    const fmt = (data5 << 3) | 0; // mask 0 = 000
    // BCH 生成 x^10+x^8+x^5+x^4+x^2+x+1 (0x537)
    let rem = fmt << 10;
    const gen = 0x537;
    for (let i = 14; i >= 10; i--) if ((rem >> i) & 1) rem ^= gen << (i - 10);
    let bits15 = ((fmt << 10) | rem) ^ 0b101010000010010;
    return Array.from({ length: 15 }, (_, i) => (bits15 >> (14 - i)) & 1);
  })();
  const formatPositions = [
    // (r,c) 顺序：围绕左上
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8],
  ];
  formatPositions.forEach(([r, c], i) => {
    matrix[r][c] = formatBits[i] === 1;
  });
  // 右下与左下的镜像副本
  for (let i = 0; i < 7; i++) matrix[size - 1 - i][8] = formatBits[i] === 1;
  for (let i = 0; i < 8; i++) matrix[8][size - 1 - i] = formatBits[14 - i] === 1;
  matrix[size - 8][8] = true; // dark module 恒定

  // 输出 SVG
  const quiet = 4;
  let path = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c] === true) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size + quiet * 2} ${size + quiet * 2}" shape-rendering="crispEdges" fill="#0f172a"><rect width="100%" height="100%" fill="#ffffff"/><path d="${path}"/></svg>`;
}

// ---------------------------------------------------------------------------
// API 交互
// ---------------------------------------------------------------------------

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.pin) headers["x-drop-pin"] = state.pin;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    showPinModal();
    throw new Error("需要 PIN");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function fmtSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

async function loadInfo() {
  try {
    const info = await api("/api/info");
    state.pin = info.pin;
    state.addresses = info.addresses || [];
    state.port = info.port;
    $("#upload-dir").textContent = info.uploadDir;
    $("#pin-display").textContent = info.pin ? info.pin : "—";
    const lan = state.addresses[0] ? `http://${state.addresses[0]}:${state.port}` : null;
    $("#lan-url").textContent = lan ?? "未检测到局域网地址（无 Wi-Fi？）";
    if (lan) {
      // 带 pin 的 URL：手机打开即自动验证
      const withPin = info.pin ? `${lan}/?pin=${info.pin}` : lan;
      $("#qr").innerHTML = qrEncode(withPin);
    }
    $("#net-note").textContent = "本机运行中";
    $("#net-note").classList.add("ok");
  } catch {
    $("#lan-url").textContent = "无法连接服务";
  }
}

const IMAGE_EXT = /\.(png|jpe?g|gif|webp|svg|bmp|avif)$/i;
const TEXT_EXT = /\.(txt|md|json|log|csv|ya?ml|js|ts|css|html?)$/i;
let lastFiles = [];

function previewUrl(name, inline) {
  const pin = state.pin ?? "";
  return `/api/download/${encodeURIComponent(name)}?pin=${encodeURIComponent(pin)}${inline ? "&inline=1" : ""}`;
}

let lastSignature = "";
function filesSignature(files) {
  return files.map((f) => `${f.name}:${f.size}:${f.mtime}`).join("|");
}

async function loadFiles() {
  try {
    const { files } = await api("/api/files");
    // 保留用户勾选：自动刷新（5s）不应清空选择
    const prevChecked = new Set(selectedNames());
    lastFiles = files;
    const signature = filesSignature(files);
    if (signature === lastSignature) return; // 内容未变化：不动 DOM，保留勾选与滚动
    lastSignature = signature;
    const list = $("#file-list");
    list.innerHTML = "";
    $("#empty").classList.toggle("hidden", files.length > 0);
    $("#file-count").textContent = files.length ? `· ${files.length}` : "";
    for (const file of files) {
      const li = document.createElement("li");
      li.className = "file-row";
      const date = new Date(file.mtime);
      const isImage = IMAGE_EXT.test(file.name);
      const isText = TEXT_EXT.test(file.name);
      const thumb = isImage
        ? `<img class="thumb" src="${previewUrl(file.name, true)}" alt="" loading="lazy" title="点击预览" />`
        : `<span class="thumb thumb-icon">${isText ? "TXT" : ""}</span>`;
      li.innerHTML = `
        <input type="checkbox" class="pick" aria-label="选择 ${escapeHtml(file.name)}" />
        ${thumb}
        <div class="file-body">
          <div class="name">${escapeHtml(file.name)}</div>
          <div class="meta">${fmtSize(file.size)} · ${date.toLocaleString()}</div>
        </div>
        <div class="spacer"></div>
        ${isImage || isText ? `<button class="ghost preview-btn" data-name="${escapeHtml(file.name)}">预览</button>` : ""}
        <a class="ghost" href="${previewUrl(file.name, false)}" download>下载</a>
        <button class="danger-link" data-name="${escapeHtml(file.name)}">删除</button>`;
      li.querySelector("button.danger-link").addEventListener("click", async () => {
        if (!confirm(`删除 ${file.name}？此操作不可撤销。`)) return;
        await api(`/api/files/${encodeURIComponent(file.name)}`, { method: "DELETE" });
        loadFiles();
      });
      const box = li.querySelector("input.pick");
      if (prevChecked.has(file.name)) box.checked = true;
      box.addEventListener("change", updateSelectionBar);
      li.querySelector("img.thumb")?.addEventListener("click", () => openPreview(file.name));
      li.querySelector("button.preview-btn")?.addEventListener("click", () => openPreview(file.name));
      list.appendChild(li);
    }
    updateSelectionBar();
  } catch (err) {
    if (err.message !== "需要 PIN") console.warn(err);
  }
}

function selectedNames() {
  return [...document.querySelectorAll("#file-list input.pick:checked")]
    .map((el) => el.closest(".file-row")?.querySelector(".name")?.textContent ?? "")
    .filter(Boolean);
}

function updateSelectionBar() {
  const picks = document.querySelectorAll("#file-list input.pick");
  const selected = selectedNames();
  $("#pick-all-wrap")?.classList.toggle("hidden", picks.length === 0);
  const bar = $("#selection-bar");
  bar.classList.toggle("hidden", selected.length === 0);
  $("#selection-count").textContent = String(selected.length);
}

// 预览面板：图片直接内联展示；文本拉前 64KB 展示
async function openPreview(name) {
  const modal = $("#preview-modal");
  const body = $("#preview-body");
  $("#preview-title").textContent = name;
  body.innerHTML = "";
  if (IMAGE_EXT.test(name)) {
    const img = document.createElement("img");
    img.src = previewUrl(name, true);
    img.alt = name;
    body.appendChild(img);
  } else {
    body.textContent = "读取中…";
    try {
      const res = await api(`/api/preview/text?name=${encodeURIComponent(name)}`);
      const pre = document.createElement("pre");
      pre.textContent = res.text + (res.truncated ? "\n\n…（已截断，完整内容请下载）" : "");
      body.innerHTML = "";
      body.appendChild(pre);
    } catch (err) {
      body.textContent = `读取失败：${err.message}`;
    }
  }
  modal.classList.remove("hidden");
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]);
}

// ---------------------------------------------------------------------------
// 上传
// ---------------------------------------------------------------------------

function uploadFiles(fileList) {
  for (const file of fileList) {
    const row = document.createElement("div");
    row.className = "upload-row";
    row.innerHTML = `
      <div class="row"><span>${escapeHtml(file.name)}</span><span class="muted">${fmtSize(file.size)}</span></div>
      <div class="progress"><div></div></div>`;
    $("#uploads").prepend(row);
    const bar = row.querySelector(".progress > div");

    const body = new FormData();
    body.append("file", file);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload");
    if (state.pin) xhr.setRequestHeader("x-drop-pin", state.pin);
    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) bar.style.width = `${Math.round((e.loaded / e.total) * 100)}%`;
    });
    xhr.addEventListener("load", () => {
      if (xhr.status === 200) {
        row.classList.add("done");
        row.querySelector(".row").innerHTML += `<span class="muted">完成</span>`;
        setTimeout(() => row.remove(), 2500);
        loadFiles();
      } else if (xhr.status === 401) {
        row.classList.add("error");
        row.insertAdjacentHTML("beforeend", `<div class="small">需要 PIN 码</div>`);
        showPinModal();
      } else {
        row.classList.add("error");
        row.insertAdjacentHTML("beforeend", `<div class="small">上传失败（${xhr.status}）</div>`);
      }
    });
    xhr.addEventListener("error", () => {
      row.classList.add("error");
      row.insertAdjacentHTML("beforeend", `<div class="small">网络错误</div>`);
    });
    xhr.send(body);
  }
}

// ---------------------------------------------------------------------------
// PIN 弹窗与事件绑定
// ---------------------------------------------------------------------------

function showPinModal() {
  $("#pin-modal").classList.remove("hidden");
  $("#pin-input").focus();
}

$("#pin-ok").addEventListener("click", async () => {
  const pin = $("#pin-input").value.trim();
  if (!/^\d{6}$/.test(pin)) {
    $("#pin-error").classList.remove("hidden");
    return;
  }
  const res = await fetch("/api/files", { headers: { "x-drop-pin": pin } });
  if (res.ok) {
    state.pin = pin;
    state.unlocked = true;
    $("#pin-modal").classList.add("hidden");
    $("#pin-error").classList.add("hidden");
    loadFiles();
  } else {
    $("#pin-error").classList.remove("hidden");
  }
});
$("#pin-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#pin-ok").click();
});

const dropzone = $("#dropzone");
dropzone.addEventListener("click", () => $("#file-input").click());
dropzone.addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") $("#file-input").click();
});
$("#file-input").addEventListener("change", (e) => {
  uploadFiles(e.target.files);
  e.target.value = "";
});
["dragenter", "dragover"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.add("drag");
  }),
);
["dragleave", "drop"].forEach((ev) =>
  dropzone.addEventListener(ev, (e) => {
    e.preventDefault();
    dropzone.classList.remove("drag");
  }),
);
dropzone.addEventListener("drop", (e) => {
  if (e.dataTransfer?.files?.length) uploadFiles(e.dataTransfer.files);
});

$("#refresh").addEventListener("click", loadFiles);

// 文本速传：发送一段文字/链接，落成 txt 文件
$("#text-send").addEventListener("click", async () => {
  const input = $("#text-input");
  const status = $("#text-status");
  const text = input.value;
  if (!text.trim()) return;
  status.textContent = "发送中…";
  try {
    const res = await api("/api/text", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    });
    input.value = "";
    status.textContent = `已保存为 ${res.fileName}`;
    loadFiles();
  } catch (err) {
    status.textContent = err.message === "需要 PIN" ? "需要 PIN 码" : `发送失败：${err.message}`;
  }
});

// 打包下载：走带 PIN 的下载链接
$("#download-zip").addEventListener("click", () => {
  window.location.href = `/api/zip?pin=${encodeURIComponent(state.pin ?? "")}`;
});

// 全选
$("#pick-all").addEventListener("change", (event) => {
  for (const box of document.querySelectorAll("#file-list input.pick")) box.checked = event.target.checked;
  updateSelectionBar();
});

// 打包选中
$("#zip-selected").addEventListener("click", () => {
  const names = selectedNames();
  if (names.length === 0) return;
  const q = names.map((n) => encodeURIComponent(n)).join(",");
  window.location.href = `/api/zip?pin=${encodeURIComponent(state.pin ?? "")}&names=${q}`;
});

// 关闭预览
$("#preview-close").addEventListener("click", () => $("#preview-modal").classList.add("hidden"));
$("#preview-modal").addEventListener("click", (event) => {
  if (event.target === event.currentTarget) event.currentTarget.classList.add("hidden");
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") $("#preview-modal").classList.add("hidden");
});
$("#open-finder").addEventListener("click", () => {
  fetch("/api/reveal", { method: "POST" }).catch(() => {});
});

// URL 带 pin 时自动解锁
const urlPin = new URLSearchParams(location.search).get("pin");
if (urlPin) state.pin = urlPin;

loadInfo().then(loadFiles);
setInterval(loadFiles, 5000);
