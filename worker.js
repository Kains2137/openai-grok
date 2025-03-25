const TARGET_URL = "https://grok.com/rest/app-chat/conversations/new";
const MODELS = ["grok-2", "grok-3", "grok-3-thinking"];
const MODELS_TO_CHECK = ["grok-2", "grok-3", "grok-3-thinking"];
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
];

async function fetchWithTimeout(url, options, timeout = 5000) {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) => setTimeout(() => reject(new Error("請求超時")), timeout)),
  ]);
}

function truncateCookie(cookie) {
  const maxLen = 30;
  return cookie.length > maxLen ? cookie.slice(0, 10) + "..." + cookie.slice(-10) : cookie;
}

async function getConfig(env) {
  await env.D1_DB.prepare(
    `CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY, data TEXT NOT NULL)`
  ).run();
  let row = await env.D1_DB.prepare("SELECT data FROM config WHERE id = 1").first();
  if (row && row.data) {
    try {
      return JSON.parse(row.data);
    } catch (e) {
      console.error("配置解析錯誤:", e);
    }
  }
  const defaultConfig = { cookies: [], last_cookie_index: { "grok-2": 0, "grok-3": 0, "grok-3-thinking": 0 }, temporary_mode: true };
  await setConfig(defaultConfig, env);
  return defaultConfig;
}

async function setConfig(config, env) {
  await env.D1_DB.prepare("REPLACE INTO config (id, data) VALUES (1, ?)")
    .bind(JSON.stringify(config))
    .run();
}

async function getNextAccount(model, env) {
  let config = await getConfig(env);
  if (!config.cookies || config.cookies.length === 0) {
    throw new Error("沒有可用的cookie");
  }
  const num = config.cookies.length;
  const current = ((config.last_cookie_index[model] || 0) + 1) % num;
  config.last_cookie_index[model] = current;
  await setConfig(config, env);
  return config.cookies[current];
}

function getCommonHeaders(cookie) {
  return {
    "Accept": "*/*",
    "Content-Type": "application/json",
    "Origin": "https://grok.com",
    "Referer": "https://grok.com/",
    "Cookie": cookie,
    "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)],
  };
}

// 修復：假設cookie永遠有效
async function checkRateLimitWithCookie(model, cookie, isReasoning) {
  return { remainingQueries: 9999 };
}

async function checkCookieStatus(cookie) {
  const rateLimitDetails = MODELS_TO_CHECK.map(model => ({
    model,
    remainingQueries: 9999
  }));
  return { expired: false, rateLimited: false, rateLimitDetails };
}

function magic(messages) {
  let disableSearch = false, forceConcise = false;
  if (messages && messages.length > 0) {
    let first = messages[0].content;
    if (first.includes("<|disableSearch|>")) {
      disableSearch = true;
      first = first.replace(/<\|disableSearch\|>/g, "");
    }
    if (first.includes("<|forceConcise|>")) {
      forceConcise = true;
      first = first.replace(/<\|forceConcise\|>/g, "");
    }
    messages[0].content = first;
  }
  return { disableSearch, forceConcise, messages };
}

function formatMessage(messages) {
  let roleMap = { user: "Human", assistant: "Assistant", system: "System" };
  const roleInfoPattern = /<roleInfo>\s*user:\s*([^\n]*)\s*assistant:\s*([^\n]*)\s*system:\s*([^\n]*)\s*prefix:\s*([^\n]*)\s*<\/roleInfo>\n/;
  let prefix = false, firstContent = messages[0].content;
  let match = firstContent.match(roleInfoPattern);
  if (match) {
    roleMap = { user: match[1], assistant: match[2], system: match[3] };
    prefix = match[4] === "1";
    messages[0].content = firstContent.replace(roleInfoPattern, "");
  }
  let formatted = "";
  for (const msg of messages) {
    let role = prefix ? "\b" + roleMap[msg.role] : roleMap[msg.role];
    formatted += `${role}: ${msg.content}\n`;
  }
  return formatted;
}

async function handleModels() {
  const data = MODELS.map(model => ({
    id: model,
    object: "model",
    created: Math.floor(Date.now() / 1000),
    owned_by: "Elbert",
    name: model,
  }));
  return new Response(JSON.stringify({ object: "list", data }), {
    headers: { "Content-Type": "application/json" },
  });
}

async function handleChatCompletions(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ") || authHeader.split(" ")[1] !== env.CONFIG_PASSWORD) {
    return new Response(JSON.stringify({ error: "無效的認證" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  const reqJson = await request.json();
  const streamFlag = reqJson.stream || false;
  const messages = reqJson.messages;
  let model = reqJson.model;
  if (!MODELS.includes(model)) {
    return new Response(JSON.stringify({ error: "模型不可用" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  if (!messages) {
    return new Response(JSON.stringify({ error: "必須提供消息" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
  const { disableSearch, forceConcise, messages: newMessages } = magic(messages);
  const formattedMessage = formatMessage(newMessages);
  const isReasoning = model.length > 6;
  model = model.substring(0, 6);
  return streamFlag
    ? await sendMessageStream(formattedMessage, model, disableSearch, forceConcise, isReasoning, env)
    : await sendMessageNonStream(formattedMessage, model, disableSearch, forceConcise, isReasoning, env);
}

async function handleRateLimits(request, env) {
  const reqJson = await request.json();
  const model = reqJson.model;
  const isReasoning = !!reqJson.isReasoning;
  if (!MODELS.includes(model)) {
    return new Response(JSON.stringify({ error: "模型不可用" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  let cookie;
  try {
    cookie = await getNextAccount(model, env);
  } catch (e) {
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const fakeData = { model, remainingQueries: 9999, resetTime: null };
  return new Response(JSON.stringify(fakeData), {
    headers: { "Content-Type": "application/json" },
  });
}

async function sendMessageStream(message, model, disableSearch, forceConcise, isReasoning, env) {
  let cookie;
  try {
    cookie = await getNextAccount(model, env);
  } catch (e) {
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const headers = getCommonHeaders(cookie);
  const config = await getConfig(env);
  const payload = {
    temporary: config.temporary_mode,
    modelName: model,
    message,
    fileAttachments: [],
    imageAttachments: [],
    disableSearch,
    enableImageGeneration: false,
    returnImageBytes: false,
    returnRawGrokInXaiRequest: false,
    enableImageStreaming: true,
    imageGenerationCount: 2,
    forceConcise,
    toolOverrides: {},
    enableSideBySide: true,
    isPreset: false,
    sendFinalMetadata: true,
    customInstructions: "",
    deepsearchPreset: "",
    isReasoning,
  };
  const response = await fetchWithTimeout(TARGET_URL, { method: "POST", headers, body: JSON.stringify(payload) });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      console.error(`Cookie ${truncateCookie(cookie)} 無效，移除中`);
      const config = await getConfig(env);
      config.cookies = config.cookies.filter(c => c !== cookie);
      await setConfig(config, env);
    }
    return new Response(JSON.stringify({ error: "發送消息失敗" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  const stream = new ReadableStream({
    async start(controller) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();
      let buffer = "", thinking = 2, batchSize = 0, batchContent = "";
      const MAX_BATCH_SIZE = 5, BATCH_INTERVAL = 50;
      let lastBatchTime = Date.now();

      const processBatch = async () => {
        if (batchContent) {
          const chunkData = {
            id: "chatcmpl-" + crypto.randomUUID(),
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model,
            choices: [{ index: 0, delta: { content: batchContent }, finish_reason: null }],
          };
          controller.enqueue(encoder.encode("data: " + JSON.stringify(chunkData) + "\n\n"));
          batchContent = "";
          batchSize = 0;
        }
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();
        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try {
            const data = JSON.parse(trimmed);
            if (!data?.result?.response || typeof data.result.response.token !== "string") continue;
            let token = data.result.response.token, content = token;
            if (isReasoning) {
              if (thinking === 2) { thinking = 1; content = `<Thinking>\n${token}`; }
              else if (thinking === 1 && !data.result.response.isThinking) { thinking = 0; content = `\n</Thinking>\n${token}`; }
            }
            batchContent += content;
            batchSize++;
            const now = Date.now();
            if (batchSize >= MAX_BATCH_SIZE || (now - lastBatchTime >= BATCH_INTERVAL && batchContent)) {
              await processBatch();
              lastBatchTime = now;
              await new Promise(resolve => setTimeout(resolve, 1));
            }
            if (data.result.response.isSoftStop) {
              await processBatch();
              const finalChunk = {
                id: "chatcmpl-" + crypto.randomUUID(),
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model,
                choices: [{ index: 0, delta: { content: "" }, finish_reason: "completed" }],
              };
              controller.enqueue(encoder.encode("data: " + JSON.stringify(finalChunk) + "\n\n"));
              controller.close();
              return;
            }
          } catch (e) {
            console.error("JSON解析錯誤:", e, "行內容:", trimmed);
          }
        }
      }
      if (buffer.trim()) {
        try {
          const data = JSON.parse(buffer.trim());
          if (data?.result?.response && typeof data.result.response.token === "string") {
            let token = data.result.response.token, content = token;
            if (isReasoning) {
              if (thinking === 2) { thinking = 1; content = `<Thinking>\n${token}`; }
              else if (thinking === 1 && !data.result.response.isThinking) { thinking = 0; content = `\n</Thinking>\n${token}`; }
            }
            batchContent += content;
          }
        } catch (e) {
          console.error("緩衝區解析錯誤:", e);
        }
      }
      await processBatch();
      controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      controller.close();
    }
  });
  return new Response(stream, { headers: { "Content-Type": "text/event-stream" } });
}

async function sendMessageNonStream(message, model, disableSearch, forceConcise, isReasoning, env) {
  let cookie;
  try {
    cookie = await getNextAccount(model, env);
  } catch (e) {
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const headers = getCommonHeaders(cookie);
  const config = await getConfig(env);
  const payload = {
    temporary: config.temporary_mode,
    modelName: model,
    message,
    fileAttachments: [],
    imageAttachments: [],
    disableSearch,
    enableImageGeneration: false,
    returnImageBytes: false,
    returnRawGrokInXaiRequest: false,
    enableImageStreaming: true,
    imageGenerationCount: 2,
    forceConcise,
    toolOverrides: {},
    enableSideBySide: true,
    isPreset: false,
    sendFinalMetadata: true,
    customInstructions: "",
    deepsearchPreset: "",
    isReasoning,
  };
  const response = await fetchWithTimeout(TARGET_URL, { method: "POST", headers, body: JSON.stringify(payload) });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      console.error(`Cookie ${truncateCookie(cookie)} 無效，移除中`);
      const config = await getConfig(env);
      config.cookies = config.cookies.filter(c => c !== cookie);
      await setConfig(config, env);
    }
    return new Response(JSON.stringify({ error: "發送消息失敗" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const fullText = await response.text();
  let finalMessage = "";
  const lines = fullText.split("\n").filter(line => line.trim() !== "");
  for (const line of lines) {
    try {
      const data = JSON.parse(line);
      if (data?.result?.response) {
        if (data.result.response.modelResponse && data.result.response.modelResponse.message) {
          finalMessage = data.result.response.modelResponse.message;
          break;
        } else if (typeof data.result.response.token === "string") {
          finalMessage += data.result.response.token;
        }
      }
    } catch (e) {
      console.error("JSON解析錯誤:", e);
    }
  }
  const openai_response = {
    id: "chatcmpl-" + crypto.randomUUID(),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, message: { role: "assistant", content: finalMessage }, finish_reason: "completed" }],
  };
  return new Response(JSON.stringify(openai_response), { headers: { "Content-Type": "application/json" } });
}

async function requireAuth(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/config_auth=([^;]+)/);
  return match && match[1] === env.CONFIG_PASSWORD;
}

function loginPage() {
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>登錄配置管理</title><style>body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;height:100vh}.login-container{background:#fff;padding:20px 30px;border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,0.1)}h2{margin-bottom:20px}input[type="password"]{width:100%;padding:8px;margin:10px 0;border:1px solid #ccc;border-radius:4px}button{background:#007BFF;color:#fff;border:none;padding:10px;border-radius:4px;cursor:pointer;width:100%}button:hover{background:#0056b3}</style></head><body><div class="login-container"><h2>請輸入密碼</h2><form method="POST" action="/config/login"><input type="password" name="password" placeholder="密碼" required><button type="submit">登錄</button></form></div></body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

async function handleLogin(request, env) {
  const formData = await request.formData();
  const password = formData.get("password") || "";
  if (password === env.CONFIG_PASSWORD) {
    const redirectURL = new URL("/config", request.url).toString();
    const isHttps = new URL(request.url).protocol === "https:";
    const cookieHeader = `config_auth=${env.CONFIG_PASSWORD}; Path=/; HttpOnly; ${isHttps ? "Secure; " : ""}SameSite=Strict`;
    return new Response("", { status: 302, headers: { "Set-Cookie": cookieHeader, "Location": redirectURL } });
  }
  return new Response("密碼錯誤", { status: 401 });
}

async function configPage(request, env) {
  const config = await getConfig(env);
  let cookieStatuses = await Promise.all(
    config.cookies.map(cookie => checkCookieStatus(cookie).catch(() => ({ expired: true, rateLimited: false, rateLimitDetails: [] })))
  );
  const tableRows = config.cookies.map((cookie, index) => {
    const status = cookieStatuses[index] || { expired: true, rateLimited: false, rateLimitDetails: [] };
    const cookieStateHtml = status.expired ? '<span style="color:red;">已過期</span>' : '<span style="color:green;">有效</span>';
    const rateLimitHtml = status.expired ? '--' : status.rateLimitDetails.map(detail => `${detail.model}: <span style="color:green;">有效 (剩餘: ${detail.remainingQueries})</span>`).join(" | ");
    return `<tr><td>${index + 1}</td><td>${truncateCookie(cookie)}</td><td>${cookieStateHtml}</td><td>${rateLimitHtml}</td><td><form method="POST" action="/config" class="form-inline"><input type="hidden" name="action" value="delete_one"><input type="hidden" name="index" value="${index}"><button type="submit" class="btn-danger">刪除</button></form></td></tr>`;
  }).join('');
  const html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>配置管理</title><style>body{font-family:Arial,sans-serif;background:#f9f9f9;margin:0;padding:20px}.container{max-width:900px;margin:auto;background:#fff;padding:20px;border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,0.1)}h1{text-align:center}table{width:100%;border-collapse:collapse;margin-top:20px}th,td{border:1px solid #ddd;padding:8px;text-align:left;word-break:break-all}th{background:#f2f2f2}form{margin:0}.actions{display:flex;gap:8px;margin-top:20px}button{background:#28a745;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer}button:hover{background:#218838}.btn-danger{background:#dc3545}.btn-danger:hover{background:#c82333}.btn-toggle{background:#17a2b8}.btn-toggle:hover{background:#138496}.form-inline{display:flex;align-items:center;gap:10px}input[type="text"]{flex:1;padding:8px;border:1px solid #ccc;border-radius:4px}</style></head><body><div class="container"><h1>配置管理</h1><p><strong>API Key:</strong> 與配置密碼相同</p><h2>當前Cookies</h2><table><thead><tr><th>#</th><th>Cookie</th><th>Cookie狀態</th><th>模型狀態</th><th>操作</th></tr></thead><tbody>${tableRows}</tbody></table><p>Temporary Mode: <strong>${config.temporary_mode ? "開啟" : "關閉"}</strong></p><hr><h2>添加Cookie</h2><form method="POST" action="/config" class="form-inline"><input type="hidden" name="action" value="add"><input type="text" name="cookie" placeholder="請輸入Cookie" required><button type="submit">添加</button></form><hr><h2>全局操作</h2><div class="actions"><form method="POST" action="/config"><input type="hidden" name="action" value="delete"><button type="submit" class="btn-danger">刪除所有Cookies</button></form><form method="POST" action="/config"><input type="hidden" name="action" value="toggle"><button type="submit" class="btn-toggle">切換Temporary Mode</button></form></div></div></body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

async function updateConfig(request, env) {
  const formData = await request.formData();
  const action = formData.get("action");
  const config = await getConfig(env);
  if (action === "add") {
    const newCookie = formData.get("cookie");
    if (newCookie && newCookie.trim() !== "") config.cookies.push(newCookie.trim());
  } else if (action === "delete") {
    config.cookies = [];
  } else if (action === "toggle") {
    config.temporary_mode = !config.temporary_mode;
  } else if (action === "delete_one") {
    const index = parseInt(formData.get("index"), 10);
    if (!isNaN(index) && index >= 0 && index < config.cookies.length) config.cookies.splice(index, 1);
  }
  await setConfig(config, env);
  return Response.redirect(new URL("/config", request.url).toString(), 302);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "") {
      return Response.redirect(new URL("/config", request.url).toString(), 302);
    }
    if (url.pathname.startsWith("/config")) {
      if (url.pathname === "/config/login") {
        return request.method === "GET" ? loginPage() : handleLogin(request, env);
      }
      if (!(await requireAuth(request, env))) {
        return Response.redirect(new URL("/config/login", request.url).toString(), 302);
      }
      return request.method === "GET" ? configPage(request, env) : updateConfig(request, env);
    } else if (url.pathname.startsWith("/v1/models")) {
      return handleModels();
    } else if (url.pathname.startsWith("/v1/rate-limits")) {
      return handleRateLimits(request, env);
    } else if (url.pathname.startsWith("/v1/chat/completions")) {
      return handleChatCompletions(request, env);
    }
    return new Response("Not Found", { status: 404 });
  }
};
