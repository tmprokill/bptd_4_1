// client.js - Multi-participant Diffie-Hellman & Encrypted Chat logic

let state = {
    groupSession: null,
    pollingInterval: null,
    openWireMessageIds: new Set()
};

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initGroupDh();
    initChat();

    // Auto-initialize group on load
    document.getElementById('initGroupDhBtn').click();
});

function initTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    const contents = document.querySelectorAll('.tab-content');

    tabs.forEach(btn => {
        btn.addEventListener('click', () => {
            tabs.forEach(b => b.classList.remove('active'));
            contents.forEach(c => c.classList.remove('active'));

            btn.classList.add('active');
            const targetId = `tab-${btn.dataset.tab}`;
            const targetContent = document.getElementById(targetId);
            if (targetContent) targetContent.classList.add('active');

            if (btn.dataset.tab === 'chat') {
                updateActiveSenderStrip();
                startChatPolling();
            } else {
                stopChatPolling();
            }
        });
    });
}

function initGroupDh() {
    const container = document.getElementById('participantsContainer');
    const addBtn = document.getElementById('addParticipantBtn');
    const initBtn = document.getElementById('initGroupDhBtn');

    addBtn.addEventListener('click', () => {
        const count = container.querySelectorAll('.participant-item').length + 1;
        const item = document.createElement('div');
        item.className = 'participant-item';
        item.innerHTML = `
            <span class="p-num">${count}</span>
            <input type="text" class="p-name" value="Учасник ${count}" />
        `;
        container.appendChild(item);
    });

    initBtn.addEventListener('click', async () => {
        const inputs = container.querySelectorAll('.p-name');
        const names = Array.from(inputs).map(i => i.value.trim()).filter(n => n.length > 0);

        if (names.length < 3) {
            alert('Для групового протоколу Діффі-Хеллмана потрібно щонайменше 3 учасники!');
            return;
        }

        try {
            initBtn.disabled = true;
            initBtn.textContent = 'Обчислення раундів...';

            const res = await fetch('/api/dh/init-group', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ participants: names })
            });

            const data = await res.json();
            state.groupSession = data;

            document.getElementById('systemParamsBox').style.display = 'flex';
            document.getElementById('dispG').textContent = data.g;
            document.getElementById('dispP').textContent = data.p;

            document.getElementById('dispGroupSecret').textContent = data.sharedSecretHex;
            document.getElementById('dispAesKey').textContent = data.aesKeyBase64;
            document.getElementById('groupStatusBadge').textContent = 'Успішно погоджено (N=' + names.length + ')';

            // Відображаємо кроки каскаду
            const flow = document.getElementById('stepsFlowContainer');
            flow.innerHTML = '';
            data.steps.forEach(s => {
                const card = document.createElement('div');
                card.className = 'step-card';
                card.innerHTML = `
                    <div class="step-info">
                        <strong>Раунд ${s.round}:</strong> ${escapeHtml(s.from)} &rarr; ${escapeHtml(s.to)}
                    </div>
                    <div class="step-formula">${escapeHtml(s.formula)}</div>
                `;
                flow.appendChild(card);
            });

            // Відображаємо персональні ключі кожного учасника
            renderUserKeys(data.participants, data.sharedSecretHex);

            // Оновлюємо селектор відправника у чаті
            const select = document.getElementById('currentSenderSelect');
            select.innerHTML = '';
            names.forEach(name => {
                const opt = document.createElement('option');
                opt.value = name;
                opt.textContent = name;
                select.appendChild(opt);
            });

            select.onchange = updateActiveSenderStrip;
            updateActiveSenderStrip();

        } catch (err) {
            console.error('Помилка групового обміну:', err);
        } finally {
            initBtn.disabled = false;
            initBtn.textContent = 'Запустити обмін ключами';
        }
    });
}

function renderUserKeys(participants, sharedSecretHex) {
    const container = document.getElementById('userKeysContainer');
    if (!container || !participants) return;

    container.innerHTML = '';
    participants.forEach((p, idx) => {
        const card = document.createElement('div');
        card.className = 'user-key-card';
        card.innerHTML = `
            <div class="uk-header">
                <span class="uk-name">${escapeHtml(p.name)}</span>
                <span class="uk-badge">#${idx + 1} в кільці</span>
            </div>
            <div class="uk-field">
                <span class="uk-lbl">Закритий секретний ключ (x<sub>${idx + 1}</sub>):</span>
                <div class="uk-val priv" title="Таємний ключ учасника">${escapeHtml(p.privHex || p.priv)}</div>
            </div>
            <div class="uk-field">
                <span class="uk-lbl">Публічний токен (Y<sub>${idx + 1}</sub> = g<sup>x<sub>${idx + 1}</sub></sup> mod p):</span>
                <div class="uk-val pub" title="Відкритий токен">${escapeHtml(p.pubHex || p.pub)}</div>
            </div>
            <div class="uk-field">
                <span class="uk-lbl">Обчислений фінальний секрет (K):</span>
                <div class="uk-val shared" title="Обчислений спільний ключ">${escapeHtml(p.finalKeyHex || sharedSecretHex)}</div>
            </div>
        `;
        container.appendChild(card);
    });
}

function updateActiveSenderStrip() {
    if (!state.groupSession || !state.groupSession.participants) return;

    const select = document.getElementById('currentSenderSelect');
    if (!select) return;

    const currentName = select.value;
    const participant = state.groupSession.participants.find(p => p.name === currentName);

    const nameEl = document.getElementById('stripSenderName');
    const privEl = document.getElementById('stripSenderPriv');
    const pubEl = document.getElementById('stripSenderPub');
    const aesEl = document.getElementById('stripSenderAes');

    if (nameEl) nameEl.textContent = currentName;
    if (participant) {
        if (privEl) privEl.textContent = (participant.privHex || participant.priv).substring(0, 20) + '...';
        if (pubEl) pubEl.textContent = (participant.pubHex || participant.pub).substring(0, 20) + '...';
    }
    if (aesEl && state.groupSession) {
        aesEl.textContent = state.groupSession.aesKeyBase64;
    }
}

function initChat() {
    const sendBtn = document.getElementById('sendChatBtn');
    const input = document.getElementById('chatInput');
    const senderSelect = document.getElementById('currentSenderSelect');

    sendBtn.addEventListener('click', sendMessage);
    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    async function sendMessage() {
        const text = input.value.trim();
        if (!text) return;

        const sender = senderSelect.value;
        try {
            await fetch('/api/chat/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sender, text })
            });

            input.value = '';
            await fetchMessages();
        } catch (err) {
            console.error('Помилка надсилання повідомлення:', err);
        }
    }
}

function startChatPolling() {
    fetchMessages();
    if (!state.pollingInterval) {
        state.pollingInterval = setInterval(fetchMessages, 1500);
    }
}

function stopChatPolling() {
    if (state.pollingInterval) {
        clearInterval(state.pollingInterval);
        state.pollingInterval = null;
    }
}

async function fetchMessages() {
    try {
        const res = await fetch('/api/chat/messages');
        const data = await res.json();
        const container = document.getElementById('chatMessages');

        if (!data.messages) return;

        const currentSender = document.getElementById('currentSenderSelect').value;

        // Збираємо ID вже відображених повідомлень, щоб НЕ перезатирати DOM
        const existingBubbles = container.querySelectorAll('.chat-bubble');
        const existingIds = new Set(Array.from(existingBubbles).map(b => b.dataset.msgId));

        let hasNew = false;
        data.messages.forEach(m => {
            if (!existingIds.has(m.id)) {
                // Видаляємо стартове системне повідомлення, якщо прийшло перше реальне
                const sysMsg = container.querySelector('.chat-system-msg');
                if (sysMsg && existingBubbles.length === 0) {
                    sysMsg.remove();
                }

                const bubble = createMessageBubble(m, currentSender);
                container.appendChild(bubble);
                hasNew = true;
            } else {
                // Оновлюємо стилі при зміні поточного відправника без перемальовування
                const existing = container.querySelector(`.chat-bubble[data-msg-id="${m.id}"]`);
                if (existing) {
                    if (m.sender === currentSender) {
                        existing.classList.add('mine');
                    } else {
                        existing.classList.remove('mine');
                    }
                }
            }
        });

        // Прокручуємо донизу тільки якщо реально додано нові повідомлення
        if (hasNew) {
            container.scrollTop = container.scrollHeight;
        }
    } catch (err) {
        console.error('Помилка отримання повідомлень:', err);
    }
}

function createMessageBubble(m, currentSender) {
    const bubble = document.createElement('div');
    const isMine = m.sender === currentSender;
    bubble.className = `chat-bubble ${isMine ? 'mine' : ''}`;
    bubble.dataset.msgId = m.id;

    const isOpen = state.openWireMessageIds.has(m.id);

    bubble.innerHTML = `
        <div class="msg-meta">
            <span class="msg-sender">${escapeHtml(m.sender)}</span>
            <span class="msg-time">${escapeHtml(m.timestamp)}</span>
        </div>
        <div class="msg-body">
            <div class="msg-plaintext">
                <span class="bubble-tag badge-success">[OK] Розшифровано (AES-GCM)</span>
                <div class="msg-text">${escapeHtml(m.plaintext)}</div>
            </div>
            <button type="button" class="wire-toggle ${isOpen ? 'active' : ''}" onclick="toggleWire(this, '${m.id}')">
                ${isOpen ? 'Приховати зашифровані канальні дані' : 'Переглянути шифротекст у каналі (AES-256-GCM)'}
            </button>
            <div class="wire-content" style="display: ${isOpen ? 'block' : 'none'};">
                <div class="wire-row"><strong>Ciphertext (Base64):</strong> <code>${escapeHtml(m.ciphertext)}</code></div>
                <div class="wire-row"><strong>IV / Nonce (96-bit):</strong> <code>${escapeHtml(m.nonce)}</code></div>
                <div class="wire-row"><strong>Auth Tag (128-bit):</strong> <code>${escapeHtml(m.tag)}</code></div>
            </div>
        </div>
    `;
    return bubble;
}

window.toggleWire = function(btn, msgId) {
    const content = btn.nextElementSibling;
    if (content.style.display === 'block') {
        content.style.display = 'none';
        btn.classList.remove('active');
        btn.textContent = 'Переглянути шифротекст у каналі (AES-256-GCM)';
        state.openWireMessageIds.delete(msgId);
    } else {
        content.style.display = 'block';
        btn.classList.add('active');
        btn.textContent = 'Приховати зашифровані канальні дані';
        state.openWireMessageIds.add(msgId);
    }
};

function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return String(text).replace(/[&<>"']/g, m => map[m]);
}
