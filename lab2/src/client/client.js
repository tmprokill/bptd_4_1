/**
 * Клієнтська реалізація асиметричного шифрування RSA (Web Crypto API)
 * Лабораторна робота №2: БПТД, ХНУРЕ
 * Бригада: Чуваєв А. О. (вар. 16) та Світенко С. М. (вар. 13)
 */

let clientKeyPair = null;
let clientPublicKeyPem = "";
let serverPublicKeyPem = "";
let serverPublicKeyObj = null;

const MAX_PLAIN_CHUNK = 190; // 256 - 2*32 - 2 для OAEP-SHA256
const CIPHER_CHUNK = 256;    // 2048 бітів / 8 = 256 байтів

const API_BASE = window.location.origin.startsWith("http")
  ? window.location.origin
  : "http://localhost:5050";

// Елементи DOM
const statusDot = document.getElementById("statusDot");
const statusText = document.getElementById("statusText");
const btnReconnect = document.getElementById("btnReconnect");
const txtClientPubKey = document.getElementById("txtClientPubKey");
const clientKeyMeta = document.getElementById("clientKeyMeta");
const txtServerPubKey = document.getElementById("txtServerPubKey");
const serverKeyMeta = document.getElementById("serverKeyMeta");
const btnRegenClientKeys = document.getElementById("btnRegenClientKeys");
const btnFetchServerKey = document.getElementById("btnFetchServerKey");
const authForm = document.getElementById("authForm");
const inputLogin = document.getElementById("inputLogin");
const inputPassword = document.getElementById("inputPassword");
const inputNote = document.getElementById("inputNote");
const btnSend = document.getElementById("btnSend");
const preset16 = document.getElementById("preset16");
const preset13 = document.getElementById("preset13");
const step1Plaintext = document.getElementById("step1Plaintext");
const step2Cipher = document.getElementById("step2Cipher");
const step3Cipher = document.getElementById("step3Cipher");
const step4Decrypted = document.getElementById("step4Decrypted");
const logTerminal = document.getElementById("logTerminal");
const btnClearLog = document.getElementById("btnClearLog");

function log(msg, type = "info") {
  const time = new Date().toLocaleTimeString();
  const div = document.createElement("div");
  div.className = `log-line log-${type}`;
  div.textContent = `[${time}] ${msg}`;
  logTerminal.appendChild(div);
  logTerminal.scrollTop = logTerminal.scrollHeight;
}

// -------------------------------------------------------------
// Криптографічні утиліти (SPKI PEM <-> ArrayBuffer)
// -------------------------------------------------------------

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary_string = window.atob(base64);
  const len = binary_string.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

function spkiToPem(spkiBuffer) {
  const b64 = arrayBufferToBase64(spkiBuffer);
  const formatted = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
}

function pemToSpki(pem) {
  const cleanB64 = pem
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return base64ToArrayBuffer(cleanB64);
}

// -------------------------------------------------------------
// Блокове шифрування та розшифрування RSA (Web Crypto API)
// -------------------------------------------------------------

async function encryptChunks(plainBytes, pubKey) {
  const chunks = [];
  for (let offset = 0; offset < plainBytes.length; offset += MAX_PLAIN_CHUNK) {
    const chunk = plainBytes.slice(offset, offset + MAX_PLAIN_CHUNK);
    const enc = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, pubKey, chunk);
    chunks.push(new Uint8Array(enc));
  }
  const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalLen);
  let pos = 0;
  for (const c of chunks) {
    result.set(c, pos);
    pos += c.length;
  }
  return result.buffer;
}

async function decryptChunks(cipherBytes, privKey) {
  const chunks = [];
  for (let offset = 0; offset < cipherBytes.length; offset += CIPHER_CHUNK) {
    const chunk = cipherBytes.slice(offset, offset + CIPHER_CHUNK);
    const dec = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privKey, chunk);
    chunks.push(new Uint8Array(dec));
  }
  const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalLen);
  let pos = 0;
  for (const c of chunks) {
    result.set(c, pos);
    pos += c.length;
  }
  return result.buffer;
}

// -------------------------------------------------------------
// Генерація клієнтських RSA ключів (Web Crypto API)
// -------------------------------------------------------------

async function generateClientKeys() {
  try {
    log("Генерація клієнтської пари RSA 2048 біт (Web Crypto API)...", "info");
    clientKeyMeta.textContent = "Обчислення простих чисел P та Q (2048 біт)...";

    const t0 = performance.now();
    clientKeyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]), // 65537
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );
    const genTime = Math.round(performance.now() - t0);

    const spkiBuffer = await window.crypto.subtle.exportKey("spki", clientKeyPair.publicKey);
    clientPublicKeyPem = spkiToPem(spkiBuffer);
    txtClientPubKey.value = clientPublicKeyPem;

    clientKeyMeta.textContent = `RSA-2048 | Експонента: 65537 | Згенеровано за ${genTime} мс`;
    log(`Клієнтські ключі RSA-2048 успішно створено (${genTime} мс)`, "success");
  } catch (err) {
    log(`Помилка генерації клієнтських ключів: ${err.message}`, "error");
    clientKeyMeta.textContent = "Помилка генерації!";
  }
}

// -------------------------------------------------------------
// Отримання та імпорт публічного ключа сервера (.NET)
// -------------------------------------------------------------

async function fetchServerPublicKey() {
  try {
    serverKeyMeta.textContent = "Запит /api/handshake...";
    statusText.textContent = "Підключення...";
    statusDot.className = "status-indicator-dot";

    const resp = await fetch(`${API_BASE}/api/handshake`);
    if (!resp.ok) throw new Error(`HTTP помилка ${resp.status}`);

    const data = await resp.json();
    serverPublicKeyPem = data.serverPublicKey;
    txtServerPubKey.value = serverPublicKeyPem;

    // Імпортуємо PEM сервера у Web Crypto об'єкт
    const spkiBuffer = pemToSpki(serverPublicKeyPem);
    serverPublicKeyObj = await window.crypto.subtle.importKey(
      "spki",
      spkiBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"]
    );

    serverKeyMeta.textContent = `Розмір: ${data.keySize} біт | Схема: ${data.algorithm}`;
    statusText.textContent = "Онлайн (Підключено до .NET сервера)";
    statusDot.className = "status-indicator-dot online";
    log("Публічний ключ сервера (.NET) успішно імпортовано у Web Crypto API!", "success");
  } catch (err) {
    statusText.textContent = "Помилка зв'язку з сервером";
    statusDot.className = "status-indicator-dot offline";
    serverKeyMeta.textContent = "Не вдалося отримати ключ";
    log(`Помилка підключення до сервера: ${err.message}. Переконайтеся, що запущено dotnet run lab2/src/server/Program.cs`, "error");
  }
}

// -------------------------------------------------------------
// Двосторонній зашифрований обмін (Client -> Server -> Client)
// -------------------------------------------------------------

async function performSecureExchange() {
  if (!serverPublicKeyObj) {
    alert("Спочатку підключіться до сервера та отримайте його публічний ключ!");
    return;
  }
  if (!clientKeyPair) {
    alert("Клієнтські ключі ще не згенеровано!");
    return;
  }

  const login = inputLogin.value.trim();
  const password = inputPassword.value;
  const note = inputNote.value.trim();

  // 1. Формуємо відкритий JSON запит
  const plaintextPayload = {
    login: login,
    password: password,
    note: note,
    clientTimestamp: new Date().toISOString(),
    protocol: "RSA-OAEP-SHA256"
  };

  const plainJsonString = JSON.stringify(plaintextPayload, null, 2);
  step1Plaintext.textContent = plainJsonString;
  const rawBytes = new TextEncoder().encode(plainJsonString);
  log(`[КРОК 1]: Сформовано відкритий пакет авторизації (${rawBytes.length} байт)`, "info");

  try {
    // 2. Блокове шифрування відкритим ключем сервера (RSA-OAEP-SHA256)
    btnSend.disabled = true;
    btnSend.textContent = "⏳ Шифрування та передача...";

    const t0 = performance.now();
    const cipherBuffer = await encryptChunks(rawBytes, serverPublicKeyObj);
    const encTime = Math.round(performance.now() - t0);

    const encryptedPayloadBase64 = arrayBufferToBase64(cipherBuffer);
    step2Cipher.value = encryptedPayloadBase64;
    log(`[КРОК 2]: Дані зашифровано публічним ключем сервера (блоків: ${Math.ceil(rawBytes.length / MAX_PLAIN_CHUNK)}, ${encTime} мс). Розмір шифротексту: ${encryptedPayloadBase64.length} симв. Base64`, "success");

    // 3. Відправляємо через незахищений канал зв'язку на .NET сервер
    log(`[МЕРЕЖА]: Відправка зашифрованого запиту на ${API_BASE}/api/secure-exchange...`, "info");
    const netStartTime = performance.now();

    const response = await fetch(`${API_BASE}/api/secure-exchange`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        clientPublicKeyPem: clientPublicKeyPem,
        encryptedPayloadBase64: encryptedPayloadBase64
      })
    });

    const netTime = Math.round(performance.now() - netStartTime);
    if (!response.ok) {
      const errData = await response.json();
      throw new Error(errData.error || `HTTP ${response.status}`);
    }

    const resData = await response.json();
    const encryptedResponseBase64 = resData.encryptedResponseBase64;
    step3Cipher.value = encryptedResponseBase64;
    log(`[КРОК 3]: Отримано зашифровану сервером відповідь (RTT: ${netTime} мс, ${encryptedResponseBase64.length} симв. Base64)`, "info");

    // 4. Блокове розшифрування приватним ключем клієнта
    const cipherResponseBytes = new Uint8Array(base64ToArrayBuffer(encryptedResponseBase64));
    const tDec = performance.now();
    const decryptedBuffer = await decryptChunks(cipherResponseBytes, clientKeyPair.privateKey);
    const decTime = Math.round(performance.now() - tDec);

    const decryptedText = new TextDecoder().decode(decryptedBuffer);
    try {
      const parsedObj = JSON.parse(decryptedText);
      step4Decrypted.textContent = JSON.stringify(parsedObj, null, 2);
    } catch {
      step4Decrypted.textContent = decryptedText;
    }

    log(`[КРОК 4]: Відповідь сервера успішно розшифровано приватним ключем клієнта за ${decTime} мс! Двосторонній обмін підтверджено.`, "success");
  } catch (err) {
    log(`[ПОМИЛКА ОБМІНУ]: ${err.message}`, "error");
    step4Decrypted.textContent = `Помилка: ${err.message}`;
  } finally {
    btnSend.disabled = false;
    btnSend.innerHTML = `<span class="btn-icon">🔒</span> Зашифрувати та відправити на сервер`;
  }
}

// -------------------------------------------------------------
// Швидкі пресети для варіантів бригади
// -------------------------------------------------------------

preset16.addEventListener("click", () => {
  inputLogin.value = "chuvaiev_artem";
  inputPassword.value = "Art16_Pass_@2026";
  inputNote.value = "Чуваєв Артем (вар. 16): Асиметрична автентифікація RSA-2048 між C# та JS";
  log("Застосовано пресет: Чуваєв Артем (Варіант 16)", "info");
});

preset13.addEventListener("click", () => {
  inputLogin.value = "svitenko_sofiia";
  inputPassword.value = "Sofi13_Pass_@2026";
  inputNote.value = "Світенко Софія (вар. 13): Двостороннє шифрування за схемою RSA-OAEP-SHA256";
  log("Застосовано пресет: Світенко Софія (Варіант 13)", "info");
});

// Обробники кнопок
btnReconnect.addEventListener("click", fetchServerPublicKey);
btnFetchServerKey.addEventListener("click", fetchServerPublicKey);
btnRegenClientKeys.addEventListener("click", generateClientKeys);
authForm.addEventListener("submit", (e) => {
  e.preventDefault();
  performSecureExchange();
});
btnClearLog.addEventListener("click", () => {
  logTerminal.innerHTML = '<div class="log-line log-info">[СИСТЕМА]: Журнал очищено.</div>';
});

// Старт
window.addEventListener("DOMContentLoaded", async () => {
  await generateClientKeys();
  await fetchServerPublicKey();
});
