// client.js - Client interaction logic for Lab 3

let state = {
    selectedBits: 8,
    fileData: null, // { name: string, base64: string, text: string, isBinary: boolean }
    lastDigest: 0,
    lastBitString: '',
    collidedFileData: null, // { fileName: string, base64: string }
    signature: '',
    publicKeyPem: ''
};

// DOM Elements
const bitButtons = document.querySelectorAll('.bit-btn');
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const fileMetaInfo = document.getElementById('fileMetaInfo');
const textInput = document.getElementById('textInput');
const detectedTypeBadge = document.getElementById('detectedTypeBadge');

const loadDocBtn = document.getElementById('loadDocBtn');
const loadCodeBtn = document.getElementById('loadCodeBtn');
const loadImgBtn = document.getElementById('loadImgBtn');

const computeHashBtn = document.getElementById('computeHashBtn');
const resBitString = document.getElementById('resBitString');
const resHex = document.getElementById('resHex');
const resDec = document.getElementById('resDec');
const resSize = document.getElementById('resSize');

const testAvalancheBtn = document.getElementById('testAvalancheBtn');
const avalancheWrap = document.getElementById('avalancheWrap');
const avalancheFill = document.getElementById('avalancheFill');
const avalancheStats = document.getElementById('avalancheStats');

const findCollisionBtn = document.getElementById('findCollisionBtn');
const downloadCollidedBtn = document.getElementById('downloadCollidedBtn');
const collisionResultBox = document.getElementById('collisionResultBox');
const collisionStatusBadge = document.getElementById('collisionStatusBadge');
const collisionDetails = document.getElementById('collisionDetails');

const manualText1 = document.getElementById('manualText1');
const manualText2 = document.getElementById('manualText2');
const verifyManualBtn = document.getElementById('verifyManualBtn');
const manualVerifResult = document.getElementById('manualVerifResult');

const signHashBtn = document.getElementById('signHashBtn');
const verifySigBtn = document.getElementById('verifySigBtn');
const tamperSigBtn = document.getElementById('tamperSigBtn');
const rsaOutputBox = document.getElementById('rsaOutputBox');
const signatureVal = document.getElementById('signatureVal');
const verifBadge = document.getElementById('verifBadge');

// Initial setup
document.addEventListener('DOMContentLoaded', () => {
    initBitSelector();
    initFileUpload();
    initSampleButtons();
    initActionHandlers();

    // Default sample texts for manual collision
    manualText1.value = "ХНУРЕ, кафедра ПІ, БПТД. Чуваєв А. О. (вар. 16)";
    manualText2.value = "ХНУРЕ, кафедра ПІ, БПТД. Світенко С. М. (вар. 13)";
    textInput.value = "Привіт, світе! Криптографічна хеш-функція БПТД 2026.";
});

function initBitSelector() {
    bitButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            bitButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state.selectedBits = parseInt(btn.dataset.bits, 10);
            computeHash();
        });
    });
}

function initFileUpload() {
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });
}

function handleFile(file) {
    const isBinary = !file.type.startsWith('text') && !file.name.endsWith('.txt') && !file.name.endsWith('.cs') && !file.name.endsWith('.js');
    fileMetaInfo.textContent = `Обрано: ${file.name} (${formatBytes(file.size)})`;
    detectedTypeBadge.textContent = `Тип: ${detectCategoryFromName(file.name)}`;

    const reader = new FileReader();
    reader.onload = (e) => {
        if (isBinary) {
            const bytes = new Uint8Array(e.target.result);
            state.fileData = {
                name: file.name,
                base64: uint8ToBase64(bytes),
                text: null,
                isBinary: true
            };
            textInput.value = `[Двійковий файл: ${file.name}, ${bytes.length} байт]`;
        } else {
            const text = e.target.result;
            state.fileData = {
                name: file.name,
                base64: null,
                text: text,
                isBinary: false
            };
            textInput.value = text;
        }
        computeHash();
    };

    if (isBinary) {
        reader.readAsArrayBuffer(file);
    } else {
        reader.readAsText(file);
    }
}

function detectCategoryFromName(name) {
    const ext = name.split('.').pop().toLowerCase();
    if (['txt', 'docx', 'doc', 'pdf', 'rtf', 'md'].includes(ext)) return 'Документ';
    if (['cs', 'js', 'ts', 'py', 'cpp', 'html', 'css'].includes(ext)) return 'Вихідний код';
    if (['png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp'].includes(ext)) return 'Зображення';
    return 'Інший';
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Байт';
    const k = 1024;
    const sizes = ['Байт', 'КБ', 'МБ'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function uint8ToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

function base64ToUint8(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function initSampleButtons() {
    loadDocBtn.addEventListener('click', async () => {
        await loadSample('sample_document.txt');
    });

    loadCodeBtn.addEventListener('click', async () => {
        await loadSample('sample_code.cs');
    });

    loadImgBtn.addEventListener('click', async () => {
        await loadSample('sample_image.png');
    });
}

async function loadSample(fileName) {
    try {
        const resp = await fetch('/api/samples');
        const data = await resp.json();
        const sample = data.samples.find(s => s.name === fileName);
        if (!sample) return;

        fileMetaInfo.textContent = `Завантажено зразок: ${sample.name}`;
        detectedTypeBadge.textContent = `Тип: ${sample.type}`;

        if (sample.isBase64) {
            state.fileData = {
                name: sample.name,
                base64: sample.content,
                text: null,
                isBinary: true
            };
            textInput.value = `[Вбудований бінарний зразок: ${sample.name}]`;
        } else {
            state.fileData = {
                name: sample.name,
                base64: null,
                text: sample.content,
                isBinary: false
            };
            textInput.value = sample.content;
        }

        computeHash();
    } catch (e) {
        console.error('Помилка завантаження зразка:', e);
    }
}

function initActionHandlers() {
    computeHashBtn.addEventListener('click', computeHash);
    textInput.addEventListener('input', () => {
        state.fileData = null; // direct text mode
        detectedTypeBadge.textContent = 'Тип: Текст';
        fileMetaInfo.textContent = 'Введення через текстове поле';
    });

    testAvalancheBtn.addEventListener('click', testAvalanche);
    findCollisionBtn.addEventListener('click', findStealthCollision);
    downloadCollidedBtn.addEventListener('click', downloadCollidedFile);
    verifyManualBtn.addEventListener('click', verifyManualCollision);

    signHashBtn.addEventListener('click', signHashDigest);
    verifySigBtn.addEventListener('click', () => verifySignature(false));
    tamperSigBtn.addEventListener('click', () => verifySignature(true));
}

async function computeHash() {
    const payload = {
        bits: state.selectedBits
    };

    if (state.fileData && state.fileData.base64) {
        payload.fileBase64 = state.fileData.base64;
    } else {
        payload.text = textInput.value;
    }

    try {
        const res = await fetch('/api/hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        state.lastDigest = data.digest;
        state.lastBitString = data.bitString;

        resBitString.textContent = data.bitString;
        resHex.textContent = data.hex;
        resDec.textContent = data.digest;
        resSize.textContent = `${data.byteLength} байт`;

        // Оновлюємо відображення підписуваного дайджесту в панелі RSA
        const targetSource = document.getElementById('rsaTargetSource');
        const targetDigest = document.getElementById('rsaTargetDigest');
        const targetHex = document.getElementById('rsaTargetHex');
        if (targetSource) targetSource.textContent = state.fileData ? `Файл «${state.fileData.name}»` : 'Введений текст';
        if (targetDigest) targetDigest.textContent = data.bitString;
        if (targetHex) targetHex.textContent = `(${data.hex})`;

        // Reset RSA validation badge
        verifBadge.className = 'verification-badge';
        verifBadge.textContent = '';
        verifBadge.style.display = 'none';
    } catch (err) {
        console.error('Помилка обчислення хешу:', err);
    }
}

async function testAvalanche() {
    avalancheWrap.style.display = 'block';
    avalancheFill.style.width = '0%';
    avalancheStats.textContent = 'Виконується інверсія окремих бітів...';

    const payload = {
        bits: state.selectedBits
    };

    if (state.fileData && state.fileData.base64) {
        payload.fileBase64 = state.fileData.base64;
    } else {
        payload.text = textInput.value;
    }

    try {
        const res = await fetch('/api/avalanche', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        const pct = data.avgPercentage;
        avalancheFill.style.width = `${Math.min(pct, 100)}%`;
        avalancheStats.innerHTML = `Середня зміна виходу: <strong>${pct.toFixed(2)}%</strong> (Вимога &ge; 30%)<br>` +
            `Критерій виконано у <strong>${data.passRate.toFixed(1)}%</strong> з ${data.totalTests} інверсій [${data.meetsThreshold ? 'УСПІШНО' : 'НЕ ВИКОНАНО'}]`;
    } catch (err) {
        avalancheStats.textContent = 'Помилка виконання тесту: ' + err.message;
    }
}

async function findStealthCollision() {
    collisionResultBox.style.display = 'block';
    collisionStatusBadge.textContent = 'Пошук колізії...';
    collisionStatusBadge.style.color = '#f59e0b';
    collisionDetails.textContent = 'Генерація непомітних модифікацій без порушення структури файлу...';
    downloadCollidedBtn.style.display = 'none';

    const payload = {
        bits: state.selectedBits,
        fileName: state.fileData ? state.fileData.name : 'text_document.txt'
    };

    if (state.fileData && state.fileData.base64) {
        payload.fileBase64 = state.fileData.base64;
    } else {
        payload.text = textInput.value;
    }

    try {
        const res = await fetch('/api/collision/auto', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        if (data.success) {
            collisionStatusBadge.textContent = 'Колізію успішно знайдено!';
            collisionStatusBadge.style.color = '#34d399';
            collisionDetails.innerHTML = 
                `Стратегія: <strong>${data.strategy}</strong><br>` +
                `Кількість спроб: <strong>${data.attempts}</strong><br>` +
                `Вихідний хеш: <code>[${data.originalBitString}]</code> | Колізійний: <code>[${data.collisionBitString}]</code><br>` +
                `Оригінальний розмір: ${data.originalSize} Б &rarr; Новий розмір: ${data.collidedSize} Б (+${data.collidedSize - data.originalSize} Б)`;

            state.collidedFileData = {
                fileName: 'collision_' + payload.fileName,
                base64: data.collidedFileBase64
            };
            downloadCollidedBtn.style.display = 'inline-flex';
        } else {
            collisionStatusBadge.textContent = 'Не знайдено';
            collisionStatusBadge.style.color = '#ef4444';
            collisionDetails.textContent = data.message || 'Не вдалося знайти колізію за відведений ліміт спроб.';
        }
    } catch (err) {
        collisionDetails.textContent = 'Помилка підбору колізії: ' + err.message;
    }
}

function downloadCollidedFile() {
    if (!state.collidedFileData) return;
    const bytes = base64ToUint8(state.collidedFileData.base64);
    const blob = new Blob([bytes], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = state.collidedFileData.fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

async function verifyManualCollision() {
    const payload = {
        bits: state.selectedBits,
        text1: manualText1.value,
        text2: manualText2.value
    };

    try {
        const res = await fetch('/api/collision/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        manualVerifResult.style.display = 'block';

        if (data.match) {
            manualVerifResult.className = 'manual-verif-result match';
            manualVerifResult.innerHTML = 
                `<strong>КОЛІЗІЮ ЗАФІКСОВАНО!</strong><br>` +
                `Хеш тексту 1: <code>[${data.bitString1}]</code> (0x${data.digest1.toString(16).toUpperCase()})<br>` +
                `Хеш тексту 2: <code>[${data.bitString2}]</code> (0x${data.digest2.toString(16).toUpperCase()})<br>` +
                `Зміст: ${data.identicalContent ? 'Однакові (не колізія)' : 'Різний зміст (справжня колізія)'}`;
        } else {
            manualVerifResult.className = 'manual-verif-result mismatch';
            manualVerifResult.innerHTML = 
                `<strong>ХЕШІ ВІДРІЗНЯЮТЬСЯ (НЕМАЄ КОЛІЗІЇ)</strong><br>` +
                `Хеш тексту 1: <code>[${data.bitString1}]</code><br>` +
                `Хеш тексту 2: <code>[${data.bitString2}]</code><br>` +
                `Підказка: для 2 бітів простір всього 4 стани. Спробуйте змінити довжину пробілами в кінці.`;
        }
    } catch (err) {
        manualVerifResult.textContent = 'Помилка порівняння: ' + err.message;
    }
}

async function signHashDigest() {
    const payload = {
        digest: state.lastDigest
    };

    try {
        const res = await fetch('/api/rsa/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        state.signature = data.signature;
        state.publicKeyPem = data.publicKeyPem;

        rsaOutputBox.style.display = 'block';
        signatureVal.textContent = data.signature;
        verifySigBtn.style.display = 'inline-flex';
        tamperSigBtn.style.display = 'inline-flex';

        verifBadge.style.display = 'block';
        verifBadge.className = 'verification-badge valid';
        verifBadge.textContent = `Цифровий підпис сформовано для дайджесту [${state.lastBitString}]`;
    } catch (err) {
        console.error('Помилка формування ЕЦП:', err);
    }
}

async function verifySignature(tamper) {
    const digestToSend = tamper ? ((state.lastDigest ^ 0x01) & 0xFF) : state.lastDigest;
    const payload = {
        digest: digestToSend,
        signature: state.signature,
        publicKeyPem: state.publicKeyPem
    };

    try {
        const res = await fetch('/api/rsa/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        verifBadge.style.display = 'block';

        if (data.valid) {
            verifBadge.className = 'verification-badge valid';
            verifBadge.textContent = 'ВЕРИФІКАЦІЯ УСПІШНА: ЕЦП підтверджує цілісність та авторство дайджесту!';
        } else {
            verifBadge.className = 'verification-badge invalid';
            verifBadge.textContent = 'ВЕРИФІКАЦІЮ ВІДХИЛЕНО: Виявлено підробку або зміну дайджесту/підпису!';
        }
    } catch (err) {
        console.error('Помилка верифікації:', err);
    }
}
