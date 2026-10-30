// app.js - E-Commerce Store with Clean Light Theme, OAuth 2.0 & Real LiqPay Gateway

const state = {
    cars: [],
    cart: [],
    currentOrder: null,
    currentUser: null,
    oauthToken: null,
    oauthCode: null
};

// ==========================================
// INITIALIZATION
// ==========================================
document.addEventListener('DOMContentLoaded', async () => {
    initTabs();
    initResetButton();

    // Check if user session already exists in sessionStorage
    const savedUser = sessionStorage.getItem('oauth_user');
    const savedToken = sessionStorage.getItem('oauth_token');
    if (savedUser && savedToken) {
        state.currentUser = JSON.parse(savedUser);
        state.oauthToken = savedToken;
        state.oauthCode = sessionStorage.getItem('oauth_code') || 'authenticated';
        unlockStore();
    } else {
        showGatekeeper();
    }

    await loadCars();
    await loadOrders();
});

// ==========================================
// TABS NAVIGATION (4 core tabs)
// ==========================================
function initTabs() {
    const tabs = document.querySelectorAll('.nav-tab');
    const panes = document.querySelectorAll('.tab-pane');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            panes.forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            const targetPane = document.getElementById(`pane-${tab.dataset.tab}`);
            if (targetPane) targetPane.classList.add('active');

            if (tab.dataset.tab === 'orders') {
                loadOrders();
            } else if (tab.dataset.tab === 'cart') {
                renderCart();
            }
        });
    });
}

function switchTab(tabName) {
    const btn = document.querySelector(`.nav-tab[data-tab="${tabName}"]`);
    if (btn) btn.click();
}

// ==========================================
// STEP 1: OAUTH 2.0 GATEKEEPER
// ==========================================
function showGatekeeper() {
    document.getElementById('oauthGatekeeper').style.display = 'flex';
    document.getElementById('appLayout').style.display = 'none';
}

function unlockStore() {
    document.getElementById('oauthGatekeeper').style.display = 'none';
    document.getElementById('appLayout').style.display = 'block';

    updateOAuthUI();
    renderCart();
}

window.loginWithOAuth = async function(userId) {
    try {
        // 1. Authorize: Отримання одноразового Authorization Code (RFC 6749)
        const authUrl = `/oauth/authorize?response_type=code&client_id=autostore-web-app&redirect_uri=http://localhost:5090/oauth/callback&user_id=${encodeURIComponent(userId)}`;
        const authRes = await fetch(authUrl);
        if (!authRes.ok) {
            const err = await authRes.json().catch(() => ({}));
            alert(`Помилка авторизації (${authRes.status}): ${err.error || 'Не вдалося отримати код авторизації'}`);
            return;
        }
        const authData = await authRes.json();

        if (!authData.code) {
            alert('Помилка авторизації: сервер не повернув Authorization Code');
            return;
        }

        state.oauthCode = authData.code;

        // 2. Token Exchange: Обмін коду на Bearer Access Token (RFC 6749)
        const tokenRes = await fetch('/oauth/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'authorization_code',
                code: state.oauthCode,
                client_id: 'autostore-web-app',
                client_secret: 'secret_oauth_key_2026',
                redirect_uri: 'http://localhost:5090/oauth/callback'
            })
        });

        if (!tokenRes.ok) {
            const err = await tokenRes.json().catch(() => ({}));
            alert(`Помилка отримання токена: ${err.error || 'Невірні параметри клієнта'}`);
            return;
        }

        const tokenData = await tokenRes.json();
        state.oauthToken = tokenData.access_token;
        state.currentUser = tokenData.user;

        // Зберігаємо сесію в браузері
        sessionStorage.setItem('oauth_user', JSON.stringify(state.currentUser));
        sessionStorage.setItem('oauth_token', state.oauthToken);
        sessionStorage.setItem('oauth_code', state.oauthCode);

        unlockStore();
    } catch (err) {
        console.error('Помилка OAuth:', err);
        alert('Помилка звʼязку з сервером автентифікації.');
    }
};

window.logoutOAuth = function() {
    state.currentUser = null;
    state.oauthToken = null;
    state.oauthCode = null;
    state.cart = [];
    state.currentOrder = null;

    sessionStorage.removeItem('oauth_user');
    sessionStorage.removeItem('oauth_token');
    sessionStorage.removeItem('oauth_code');

    renderCart();
    showGatekeeper();
};

function updateOAuthUI() {
    const userWidget = document.getElementById('oauthUserWidget');
    if (!userWidget) return;

    if (state.currentUser) {
        userWidget.innerHTML = `
            <div class="user-badge-inner">
                <span class="user-badge-name">${escapeHtml(state.currentUser.name)}</span>
                <span style="color: var(--text-muted); font-size: 0.78rem;">(${escapeHtml(state.currentUser.group)})</span>
                <button class="btn-logout" onclick="logoutOAuth()" title="Вийти з облікового запису">Вийти</button>
            </div>
        `;
    } else {
        userWidget.innerHTML = `
            <button class="btn btn-primary btn-sm" onclick="showGatekeeper()">Увійти через OAuth</button>
        `;
    }
}

// ==========================================
// STEP 2: CAR CATALOG & INVENTORY
// ==========================================
async function loadCars() {
    try {
        const res = await fetch('/api/cars');
        state.cars = await res.json();
        renderCars(state.cars);
        renderCart();
    } catch (err) {
        console.error('Помилка завантаження каталогу:', err);
    }
}

function renderCars(cars) {
    const container = document.getElementById('carsContainer');
    if (!container) return;
    container.innerHTML = '';

    cars.forEach(car => {
        const isZaz = car.id === 'zaz-968';
        const card = document.createElement('div');
        card.className = `car-card ${isZaz ? 'featured' : ''}`;

        const cartItem = state.cart.find(c => c.carId === car.id);
        const inCartQty = cartItem ? cartItem.quantity : 0;
        const availableToAdd = car.currentStock - inCartQty;

        let btnText = 'Додати в кошик';
        if (car.currentStock <= 0) btnText = 'Немає в наявності';
        else if (availableToAdd <= 0) btnText = 'Всі в кошику';

        card.innerHTML = `
            <div>
                <div class="car-header">
                    <div class="car-title-block">
                        <h3>${escapeHtml(car.name)}</h3>
                        <div class="car-sub">${car.year} рік випуску • ${escapeHtml(car.model)}</div>
                    </div>
                    <span class="stock-badge ${car.currentStock <= 0 ? 'out-of-stock' : ''}" id="stockBadge-${car.id}">
                        На складі: ${car.currentStock} шт.
                    </span>
                </div>

                <div class="car-specs">
                    <div class="spec-row">
                        <span class="spec-lbl">Двигун:</span>
                        <span class="spec-val">${escapeHtml(car.engine)}</span>
                    </div>
                    <div class="spec-row">
                        <span class="spec-lbl">Початковий залишок:</span>
                        <span class="spec-val">${car.initialStock} шт.</span>
                    </div>
                    <div class="spec-row">
                        <span class="spec-lbl">У вашому кошику:</span>
                        <span class="spec-val text-primary" id="carInCartVal-${car.id}">${inCartQty} шт.</span>
                    </div>
                </div>

                <p class="car-desc">
                    ${escapeHtml(car.description)}
                </p>
            </div>

            <div class="car-footer">
                <div class="car-price-box">
                    <span class="price-lbl">Ціна</span>
                    <span class="price-val">${car.price.toFixed(2)} грн</span>
                </div>
                <button class="btn btn-primary" onclick="addToCart('${car.id}')" ${availableToAdd <= 0 ? 'disabled' : ''}>
                    ${btnText}
                </button>
            </div>
        `;
        container.appendChild(card);
    });
}

function updateStockBadge(carId, newStock) {
    const badge = document.getElementById(`stockBadge-${carId}`);
    if (badge) {
        badge.textContent = `На складі: ${newStock} шт.`;
        if (newStock <= 0) {
            badge.classList.add('out-of-stock');
        } else {
            badge.classList.remove('out-of-stock');
        }
    }
}

function initResetButton() {
    const btn = document.getElementById('resetInventoryBtn');
    if (!btn) return;
    btn.addEventListener('click', async () => {
        try {
            btn.disabled = true;
            const res = await fetch('/api/inventory/reset', { method: 'POST' });
            const data = await res.json();
            state.cars = data.cars;
            state.cart = [];
            renderCars(state.cars);
            renderCart();
            await loadOrders();
            alert('Склад успішно скинуто до початкових значень (ЗАЗ-968М = 3 шт.)');
        } catch (err) {
            console.error('Помилка скидання складу:', err);
        } finally {
            btn.disabled = false;
        }
    });
}

// ==========================================
// STEP 3: SHOPPING CART
// ==========================================
window.addToCart = function(carId) {
    const car = state.cars.find(c => c.id === carId);
    if (!car) return;

    if (car.currentStock <= 0) {
        alert('Цього автомобіля немає в наявності!');
        return;
    }

    const cartItem = state.cart.find(c => c.carId === carId);
    if (cartItem) {
        if (cartItem.quantity >= car.currentStock) {
            alert(`Неможливо додати більше: на складі всього ${car.currentStock} шт.`);
            return;
        }
        cartItem.quantity += 1;
    } else {
        state.cart.push({
            carId: car.id,
            name: car.name,
            price: car.price,
            quantity: 1
        });
    }

    renderCart();
    renderCars(state.cars);
};

window.updateCartQty = function(carId, delta) {
    const cartItem = state.cart.find(c => c.carId === carId);
    if (!cartItem) return;

    const car = state.cars.find(c => c.id === carId);
    const newQty = cartItem.quantity + delta;

    if (newQty <= 0) {
        removeFromCart(carId);
        return;
    }

    if (car && newQty > car.currentStock) {
        alert(`На складі доступно лише ${car.currentStock} шт.`);
        return;
    }

    cartItem.quantity = newQty;
    renderCart();
    renderCars(state.cars);
};

window.removeFromCart = function(carId) {
    state.cart = state.cart.filter(c => c.carId !== carId);
    renderCart();
    renderCars(state.cars);
};

window.clearCart = function() {
    state.cart = [];
    renderCart();
    renderCars(state.cars);
};

function renderCart() {
    const totalCount = state.cart.reduce((sum, item) => sum + item.quantity, 0);
    const totalPrice = state.cart.reduce((sum, item) => sum + item.price * item.quantity, 0);

    const headerBadge = document.getElementById('headerCartBadge');
    const tabBadge = document.getElementById('tabCartBadge');
    if (headerBadge) headerBadge.textContent = totalCount;
    if (tabBadge) tabBadge.textContent = totalCount;

    const emptyView = document.getElementById('emptyCartView');
    const tableWrapper = document.getElementById('cartTableWrapper');
    const tbody = document.getElementById('cartTableBody');
    const checkoutBtn = document.getElementById('checkoutCartBtn');

    if (totalCount === 0) {
        if (emptyView) emptyView.style.display = 'block';
        if (tableWrapper) tableWrapper.style.display = 'none';
        if (checkoutBtn) checkoutBtn.disabled = true;
    } else {
        if (emptyView) emptyView.style.display = 'none';
        if (tableWrapper) tableWrapper.style.display = 'block';
        if (checkoutBtn) checkoutBtn.disabled = false;

        if (tbody) {
            tbody.innerHTML = '';
            state.cart.forEach(item => {
                const tr = document.createElement('tr');
                const rowTotal = item.price * item.quantity;
                const car = state.cars.find(c => c.id === item.carId);
                const maxStock = car ? car.currentStock : 99;

                tr.innerHTML = `
                    <td>
                        <strong>${escapeHtml(item.name)}</strong>
                    </td>
                    <td>${item.price.toFixed(2)} грн</td>
                    <td style="text-align: center;">
                        <div class="cart-qty-ctrl">
                            <button class="cart-qty-btn" onclick="updateCartQty('${item.carId}', -1)">−</button>
                            <span class="cart-qty-val">${item.quantity}</span>
                            <button class="cart-qty-btn" onclick="updateCartQty('${item.carId}', 1)" ${item.quantity >= maxStock ? 'disabled' : ''}>+</button>
                        </div>
                    </td>
                    <td style="text-align: right; font-weight: 700; color: var(--text-main);">
                        ${rowTotal.toFixed(2)} грн
                    </td>
                    <td style="text-align: center;">
                        <button class="btn-remove-item" onclick="removeFromCart('${item.carId}')" title="Видалити">Видалити</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    }

    const userSummaryEl = document.getElementById('cartSummaryUser');
    const countSummaryEl = document.getElementById('cartSummaryCount');
    const totalSummaryEl = document.getElementById('cartSummaryTotal');

    if (userSummaryEl) {
        userSummaryEl.textContent = state.currentUser ? `${state.currentUser.name}` : 'Гість';
    }
    if (countSummaryEl) {
        countSummaryEl.textContent = `${totalCount} шт.`;
    }
    if (totalSummaryEl) {
        totalSummaryEl.textContent = `${totalPrice.toFixed(2)} грн`;
    }
}

// ==========================================
// STEP 4: CHECKOUT & LIQPAY PAYMENT
// ==========================================
window.checkoutCart = async function() {
    if (state.cart.length === 0) {
        alert('Ваш кошик порожній! Оберіть хоча б один автомобіль.');
        return;
    }

    try {
        const payload = {
            items: state.cart.map(i => ({ carId: i.carId, quantity: i.quantity })),
            userId: state.currentUser ? state.currentUser.id : null,
            userName: state.currentUser ? state.currentUser.name : 'Гість'
        };

        const headers = { 'Content-Type': 'application/json' };
        if (state.oauthToken) {
            headers['Authorization'] = `Bearer ${state.oauthToken}`;
        }

        const res = await fetch('/api/orders/checkout', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            alert(`Помилка оформлення: ${err.error || 'Невідома помилка'}`);
            return;
        }

        const data = await res.json();
        state.currentOrder = data.order;
        state.paymentForm = data.paymentForm;

        // Очищаємо кошик після успішного чекауту
        state.cart = [];
        renderCart();
        renderCars(state.cars);

        // Відображаємо у вкладці оплати
        displayOrderInPaymentTab(data.order, data.paymentForm);
        switchTab('payment');

        const term = document.getElementById('pane-payment');
        if (term) term.scrollIntoView({ behavior: 'smooth' });
    } catch (err) {
        console.error('Помилка оформлення замовлення:', err);
    }
};

function displayOrderInPaymentTab(order, form) {
    document.getElementById('noActiveOrderMsg').style.display = 'none';
    document.getElementById('activeOrderDetails').style.display = 'block';

    document.getElementById('dispOrderId').textContent = order.orderId;
    document.getElementById('dispCarName').textContent = order.carName;
    document.getElementById('dispAmount').textContent = `${order.amount.toFixed(2)} ${order.currency}`;
    document.getElementById('dispCustomer').textContent = `${order.userName} ${state.currentUser ? `(${state.currentUser.group})` : ''}`;

    try {
        const jsonStr = atob(form.v3_data);
        const prettyJson = JSON.stringify(JSON.parse(jsonStr), null, 2);
        document.getElementById('dispV3DataJson').textContent = prettyJson;
    } catch {
        document.getElementById('dispV3DataJson').textContent = form.v3_data;
    }

    document.getElementById('dispV3DataBase64').textContent = form.v3_data;
    document.getElementById('dispFormSignature').textContent = form.v3_signature;
    document.getElementById('dispConcatString').textContent = form.concatenated_string;

    const realDataInput = document.getElementById('realLiqPayData');
    const realSigInput = document.getElementById('realLiqPaySignature');
    const openBtn = document.getElementById('openLiqPayCheckoutBtn');
    const syncBtn = document.getElementById('syncLiqPayStatusBtn');

    if (realDataInput) realDataInput.value = form.v3_data;
    if (realSigInput) realSigInput.value = form.v3_signature;
    if (openBtn) openBtn.disabled = false;
    if (syncBtn) syncBtn.disabled = false;

    const term = document.getElementById('paymentResultTerminal');
    if (term) term.style.display = 'none';
}

// ==========================================
// REAL LIQPAY STATUS SYNC (SERVER-TO-SERVER)
// ==========================================
window.syncOrderStatusWithLiqPay = async function() {
    if (!state.currentOrder) {
        alert('Немає активного замовлення для перевірки');
        return;
    }

    const syncBtn = document.getElementById('syncLiqPayStatusBtn');
    syncBtn.disabled = true;
    syncBtn.textContent = 'Запит до LiqPay API...';

    try {
        const res = await fetch(`/api/orders/${encodeURIComponent(state.currentOrder.orderId)}/sync-status`, {
            method: 'POST'
        });

        const data = await res.json();
        displayPaymentResult(data);

        if (data.cars) {
            state.cars = data.cars;
            renderCars(state.cars);
        }

        await loadOrders();
    } catch (err) {
        console.error('Помилка синхронізації статусу:', err);
        alert('Помилка звʼязку з сервером перевірки статусу');
    } finally {
        syncBtn.disabled = false;
        syncBtn.textContent = 'Опитати статус оплати з сервера LiqPay';
    }
};

function displayPaymentResult(result) {
    const term = document.getElementById('paymentResultTerminal');
    const termBadge = document.getElementById('termStatusBadge');
    const termBody = document.getElementById('termBody');

    term.style.display = 'block';

    const isSuccess = result.status === 'success' || result.status === 'sandbox' || (result.order && (result.order.state === 1 || result.order.state === 'Paid'));
    termBadge.textContent = isSuccess ? 'SUCCESS (SANDBOX)' : result.status.toUpperCase();
    termBadge.className = `term-status ${isSuccess ? 'valid' : 'invalid'}`;

    const liqpay = result.liqPayResult || {};

    let log = '';
    log += `[LiqPay Server-to-Server Status API]\n`;
    log += `Endpoint: POST https://www.liqpay.ua/api/request\n`;
    log += `Action: status | Order ID: ${liqpay.order_id || (result.order ? result.order.orderId : state.currentOrder.orderId)}\n`;
    log += `------------------------------------------------------------\n`;
    log += `LiqPay Response Status: [${liqpay.status || result.status}]\n`;
    log += `Transaction ID:         ${liqpay.payment_id || liqpay.transaction_id || 'N/A'}\n`;
    log += `Amount / Currency:      ${liqpay.amount || (result.order ? result.order.amount : '--')} ${liqpay.currency || 'UAH'}\n`;
    log += `Description:            ${liqpay.description || '--'}\n`;

    if (isSuccess) {
        log += `\n[ОБРОБКА СКЛАДУ]\n`;
        log += `Підпис транзакції:      ПІДТВЕРДЖЕНО (Server-to-Server)\n`;
        log += `Списання товару:        ${result.stockChanged ? 'ВИКОНАНО (-1 шт. на кожну позицію)' : 'Вже списано (ідемпотентність)'}\n`;
        if (result.order && result.order.stockBefore && result.order.stockAfter) {
            log += `Залишок на складі:      ${result.order.stockBefore} -> ${result.order.stockAfter}\n`;
        }
    } else {
        log += `\n[СТАТУС]\n`;
        log += `Статус:                 Оплата ще не завершена або відхилена\n`;
        log += `Списання товару:        СКАСОВАНО (Залишок збережено)\n`;
    }

    termBody.textContent = log;
}

// ==========================================
// ORDERS TABLE
// ==========================================
async function loadOrders() {
    try {
        const res = await fetch('/api/orders');
        const orders = await res.json();
        renderOrdersTable(orders);
    } catch (err) {
        console.error('Помилка завантаження замовлень:', err);
    }
}

function renderOrdersTable(orders) {
    const tbody = document.getElementById('ordersTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (orders.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 2rem;">Замовлень ще немає</td></tr>`;
        return;
    }

    orders.forEach(order => {
        const tr = document.createElement('tr');
        const dateStr = new Date(order.createdAt).toLocaleTimeString('uk-UA');

        let statusClass = 'status-pending';
        let statusText = 'Очікує';
        if (order.state === 1 || order.state === 'Paid' || order.status === 'success' || order.status === 'sandbox') {
            statusClass = 'status-success';
            statusText = 'Оплачено';
        } else if (order.state === 2 || order.state === 'Failed' || order.status === 'failure') {
            statusClass = 'status-failure';
            statusText = 'Відхилено';
        }

        const stockDiff = order.stockBefore && order.stockAfter 
            ? `${order.stockBefore} -> ${order.stockAfter}` 
            : '--';

        tr.innerHTML = `
            <td><code>${escapeHtml(order.orderId)}</code></td>
            <td><strong>${escapeHtml(order.carName)}</strong></td>
            <td style="font-weight: 700;">${order.amount.toFixed(2)} ${order.currency}</td>
            <td>${escapeHtml(order.userName)}</td>
            <td><span class="status-badge ${statusClass}">${statusText}</span></td>
            <td>${stockDiff}</td>
            <td><code>${order.transactionId || '--'}</code></td>
            <td style="color: var(--text-muted);">${dateStr}</td>
        `;
        tbody.appendChild(tr);
    });
}

// ==========================================
// HELPERS
// ==========================================
function escapeHtml(str) {
    if (!str) return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
