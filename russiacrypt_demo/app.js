
const state = {
  user: null,
  csrf: '',
  authMode: 'login',
  view: 'overview',
  adjustAction: 'add',
  users: [],
  marketPriceCents: 15000,
  marketHistory: []
};

const $ = (id) => document.getElementById(id);

const fmtEUR = (cents) =>
  new Intl.NumberFormat('de-DE', {
    style: 'currency',
    currency: 'EUR'
  }).format((Number(cents) || 0) / 100);

const fmtCoin = (units) =>
  `${((Number(units) || 0) / 100).toLocaleString('ru-RU', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  })} RUC`;

const fmtDate = (value) => {
  try {
    return new Date(value).toLocaleString('ru-RU', {
      day: '2-digit',
      month: '2-digit',
      year: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return value || '—';
  }
};

const esc = (v) =>
  String(v ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]));

async function api(path, body, options = {}) {
  const headers = { 'Content-Type': 'application/json' };

  if (options.csrf !== false && state.csrf) {
    headers['X-CSRF-Token'] = state.csrf;
  }

  const response = await fetch(path, {
    method: options.method || (body === undefined ? 'GET' : 'POST'),
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  let data;

  try {
    data = await response.json();
  } catch {
    data = { error: 'Сервер вернул некорректный ответ.' };
  }

  if (!response.ok) {
    throw new Error(data.error || 'Ошибка запроса.');
  }

  return data;
}

let toastTimer;

function toast(text, error = false) {
  const el = $('toast');
  if (!el) return;

  el.textContent = text;
  el.classList.toggle('error', error);
  el.classList.add('show');

  clearTimeout(toastTimer);

  toastTimer = setTimeout(
    () => el.classList.remove('show'),
    3300
  );
}

function setMessage(id, text, error = false) {
  const el = $(id);
  if (!el) return;

  el.textContent = text;
  el.classList.toggle('error', error);
}

async function loadMarket() {
  try {
    const response = await fetch('/api/market', {
      credentials: 'same-origin'
    });

    const data = await response.json();

    if (!response.ok || !Number.isFinite(Number(data.price_cents))) {
      return;
    }

    state.marketPriceCents = Number(data.price_cents);
    state.marketHistory = Array.isArray(data.history)
      ? data.history
      : [];

    const priceText = fmtEUR(state.marketPriceCents);

    [
      'overview-price',
      'overview-asset-price',
      'market-price',
      'market-detail-price',
      'trade-price',
      'trade-summary-price'
    ].forEach(id => {
      const element = $(id);
      if (element) element.textContent = priceText;
    });

    if (state.user) updateBalances();

    drawCharts();
  } catch (error) {
    console.error('Ошибка загрузки цены RUCOIN:', error);
  }
}

function setAuthMode(mode) {
  state.authMode = mode;

  document.querySelectorAll('[data-auth-mode]').forEach(btn =>
    btn.classList.toggle('active', btn.dataset.authMode === mode)
  );

  if ($('auth-title')) {
    $('auth-title').textContent =
      mode === 'login' ? 'С возвращением' : 'Создать аккаунт';
  }

  if ($('auth-desc')) {
    $('auth-desc').textContent =
      mode === 'login'
        ? 'Войдите, чтобы открыть свой портфель.'
        : 'Зарегистрируйтесь в демо-платформе RUSSIACRYPT.';
  }

  if ($('auth-submit-text')) {
    $('auth-submit-text').textContent =
      mode === 'login' ? 'Войти в аккаунт' : 'Создать аккаунт';
  }

  if ($('auth-password')) {
    $('auth-password').autocomplete =
      mode === 'login' ? 'current-password' : 'new-password';
  }

  setMessage('auth-message', '');
}

async function submitAuth(event) {
  event.preventDefault();

  const username = $('auth-username').value.trim();
  const password = $('auth-password').value;

  try {
    const endpoint =
      state.authMode === 'login' ? '/api/login' : '/api/register';

    const result = await api(
      endpoint,
      { username, password },
      { csrf: false }
    );

    state.csrf = result.csrf || '';
    $('auth-password').value = '';

    await loadApp();

    toast(
      state.authMode === 'login'
        ? 'Вход выполнен.'
        : 'Аккаунт создан. Добро пожаловать!'
    );
  } catch (error) {
    setMessage('auth-message', error.message, true);
  }
}

async function loadApp() {
  const data = await api('/api/me', undefined, { csrf: false });

  if (!data.authenticated) {
    showAuth();
    return;
  }

  state.user = data.user;
  state.csrf = data.csrf;

  $('auth-screen').classList.add('hidden');
  $('app-screen').classList.remove('hidden');

  $('top-username').textContent = state.user.username;

  $('top-role').textContent =
    state.user.role === 'admin'
      ? 'Владелец / Admin'
      : 'Демо-пользователь';

  $('welcome-name').textContent = state.user.username;
  $('user-avatar').textContent =
    state.user.username.slice(0, 1).toUpperCase();

  $('admin-nav').classList.toggle(
    'hidden',
    state.user.role !== 'admin'
  );

  if (state.view === 'admin' && state.user.role !== 'admin') {
    state.view = 'overview';
  }

  await loadMarket();

  updateBalances();
  goTo(state.view);

  await loadHistory();

  if (state.user.role === 'admin') {
    await loadAdmin();
  }

  drawCharts();
  updateClock();
}

function showAuth() {
  $('app-screen').classList.add('hidden');
  $('auth-screen').classList.remove('hidden');

  state.user = null;
  state.csrf = '';
}

function updateBalances() {
  if (!state.user) return;

  const total =
    Number(state.user.eur_cents) +
    Math.round(
      Number(state.user.rucoin_cents) *
      state.marketPriceCents / 100
    );

  $('eur-balance').textContent = fmtEUR(state.user.eur_cents);

  $('coin-balance').innerHTML =
    `${esc(fmtCoin(state.user.rucoin_cents).replace(' RUC', ''))} <small>RUC</small>`;

  $('portfolio-value').textContent = fmtEUR(total);
  $('deposit-balance').textContent = fmtEUR(state.user.eur_cents);
  $('withdraw-balance').textContent = fmtEUR(state.user.eur_cents);

  updateTradeQuote();
}

function goTo(view) {
  if (view === 'admin' && state.user?.role !== 'admin') {
    view = 'overview';
  }

  state.view = view;

  document.querySelectorAll('.view').forEach(section =>
    section.classList.toggle(
      'active',
      section.id === `view-${view}`
    )
  );

  document.querySelectorAll('.nav-item').forEach(btn =>
    btn.classList.toggle('active', btn.dataset.view === view)
  );

  const nav = document.querySelector(
    `.nav-item[data-view="${view}"]`
  );

  $('breadcrumb-title').textContent =
    nav ? nav.textContent.trim().replace('ADMIN', '').trim() : 'Обзор';

  $('sidebar').classList.remove('open');

  if (view === 'admin' && state.user?.role === 'admin') {
    loadAdmin();
  }

  if (view === 'history') loadHistory();
  if (view === 'withdraw') updateWithdrawWindow();

  if (view === 'market' || view === 'overview') {
    setTimeout(drawCharts, 30);
  }
}

function updateTradeQuote() {
  if (!state.user) return;

  const side = $('trade-side')?.value || 'buy';
  const raw = Number($('trade-amount')?.value || 0);
  const coinUnits = Math.max(0, Math.round(raw * 100));

  const eurCents = Math.round(
    coinUnits * state.marketPriceCents / 100
  );

  $('trade-total').textContent = fmtEUR(eurCents);

  $('trade-total-label').textContent =
    side === 'buy' ? 'К оплате' : 'К зачислению';

  $('trade-available').textContent =
    side === 'buy'
      ? fmtEUR(state.user.eur_cents)
      : fmtCoin(state.user.rucoin_cents);

  $('trade-submit').innerHTML =
    `${side === 'buy' ? 'Купить RUCOIN' : 'Продать RUCOIN'} <span>→</span>`;
}

async function loadHistory() {
  if (!state.user) return;

  try {
    const data = await api('/api/ledger');
    const items = data.items || [];

    const renderRows = (list, compact = false) => {
      if (!list.length) {
        return compact
          ? '<div class="empty-state">Операций пока нет</div>'
          : '<tr><td colspan="5" class="empty-cell">Операций пока нет</td></tr>';
      }

      if (compact) {
        return list.slice(0, 4).map(item => {
          const icon =
            item.kind === 'buy' ? '↙' :
            item.kind === 'sell' ? '↗' :
            item.kind.includes('topup') ? '+' : '◷';

          const title =
            item.kind === 'buy' ? 'Покупка RUCOIN' :
            item.kind === 'sell' ? 'Продажа RUCOIN' :
            item.kind === 'demo_topup' ? 'Тестовое пополнение' :
            item.kind === 'demo_withdraw' ? 'Демо-вывод' :
            item.kind === 'admin_adjust' ? 'Корректировка админом' :
            'Событие аккаунта';

          const value = item.eur_delta
            ? `${item.eur_delta > 0 ? '+' : '−'}${fmtEUR(Math.abs(item.eur_delta))}`
            : item.rucoin_delta
              ? `${item.rucoin_delta > 0 ? '+' : '−'}${fmtCoin(Math.abs(item.rucoin_delta))}`
              : '—';

          return `<div class="recent-item">
            <div class="recent-icon">${icon}</div>
            <div class="recent-copy">
              <b>${title}</b>
              <small>${fmtDate(item.created_at)}</small>
            </div>
            <div class="recent-value ${item.eur_delta + item.rucoin_delta > 0 ? 'delta-positive' : ''}">
              ${esc(value)}
            </div>
          </div>`;
        }).join('');
      }

      return list.map(item => {
        const title =
          item.kind === 'buy' ? 'Покупка' :
          item.kind === 'sell' ? 'Продажа' :
          item.kind === 'demo_topup' ? 'Тестовое пополнение' :
          item.kind === 'demo_withdraw' ? 'Демо-вывод' :
          item.kind === 'admin_adjust' ? 'Админ-корректировка' :
          'Аккаунт';

        const eur = item.eur_delta
          ? `${item.eur_delta > 0 ? '+' : '−'}${fmtEUR(Math.abs(item.eur_delta))}`
          : '—';

        const coin = item.rucoin_delta
          ? `${item.rucoin_delta > 0 ? '+' : '−'}${fmtCoin(Math.abs(item.rucoin_delta))}`
          : '—';

        return `<tr>
          <td><span class="kind-pill">${title}</span></td>
          <td>${esc(item.description)}</td>
          <td class="${item.eur_delta > 0 ? 'delta-positive' : item.eur_delta < 0 ? 'delta-negative' : ''}">${esc(eur)}</td>
          <td class="${item.rucoin_delta > 0 ? 'delta-positive' : item.rucoin_delta < 0 ? 'delta-negative' : ''}">${esc(coin)}</td>
          <td>${fmtDate(item.created_at)}</td>
        </tr>`;
      }).join('');
    };

    $('recent-activity').innerHTML = renderRows(items, true);
    $('history-body').innerHTML = renderRows(items, false);

  } catch (error) {
    setMessage('trade-message', error.message, true);
  }
}

async function refreshMeAndHistory() {
  const data = await api('/api/me', undefined, { csrf: false });

  if (data.authenticated) {
    state.user = data.user;
    state.csrf = data.csrf;

    updateBalances();
    await loadHistory();
  }
}

async function submitTrade(event) {
  event.preventDefault();

  const amount = $('trade-amount').value;
  const side = $('trade-side').value;

  try {
    const result = await api('/api/trade', { side, amount });

    await loadMarket();
    await refreshMeAndHistory();

    setMessage('trade-message', result.message);
    toast(result.message);

  } catch (error) {
    setMessage('trade-message', error.message, true);
  }
}

async function doDeposit(amount) {
  try {
    const result = await api('/api/deposit', {
      amount: String(amount)
    });

    await refreshMeAndHistory();

    setMessage('deposit-message', result.message);
    toast(`Добавлено ${fmtEUR(amount * 100)} виртуальных EUR.`);

  } catch (error) {
    setMessage('deposit-message', error.message, true);
  }
}

async function submitWithdraw(event) {
  event.preventDefault();

  try {
    const result = await api('/api/withdraw', {
      amount: $('withdraw-amount').value
    });

    await refreshMeAndHistory();

    setMessage('withdraw-message', result.message);
    toast(result.message);

    $('withdraw-amount').value = '';

  } catch (error) {
    setMessage('withdraw-message', error.message, true);
  }
}

function moscowParts() {
  const parts = new Intl.DateTimeFormat('en-GB', {
    timeZone: 'Europe/Moscow',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23'
  }).formatToParts(new Date());

  return {
    hour: Number(parts.find(p => p.type === 'hour')?.value || 0),
    minute: Number(parts.find(p => p.type === 'minute')?.value || 0)
  };
}

function updateWithdrawWindow() {
  const { hour, minute } = moscowParts();
  const open = hour === 16 && minute >= 30;

  $('withdraw-window-state').textContent =
    open ? 'Открыто сейчас' : 'Сегодня в 16:30 MSK';

  $('withdraw-window-state').style.color =
    open ? '#69d6a5' : '#d2bd8d';
}

function updateClock() {
  const formatter = new Intl.DateTimeFormat('ru-RU', {
    timeZone: 'Europe/Moscow',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23'
  });

  if ($('live-clock')) {
    $('live-clock').textContent =
      `${formatter.format(new Date())} MSK`;
  }

  updateWithdrawWindow();
}

async function loadAdmin() {
  if (state.user?.role !== 'admin') return;

  try {
    const [usersData, ledgerData] = await Promise.all([
      api('/api/admin/users'),
      api('/api/admin/ledger')
    ]);

    state.users = usersData.items || [];

    const users = state.users;
    const nonAdmin = users.filter(u => u.role !== 'admin');

    $('admin-stats').innerHTML =
      `<div class="admin-stat"><span>Всего аккаунтов</span><b>${users.length}</b></div>
       <div class="admin-stat"><span>Пользовательских аккаунтов</span><b>${nonAdmin.length}</b></div>
       <div class="admin-stat"><span>Суммарный RUCOIN</span><b>${fmtCoin(nonAdmin.reduce((sum, u) => sum + u.rucoin_cents, 0))}</b></div>`;

    $('users-body').innerHTML = users.length
      ? users.map(u => `<tr>
          <td><b>${esc(u.username)}</b></td>
          <td>${u.role === 'admin' ? '<span class="kind-pill">ADMIN</span>' : 'Пользователь'}</td>
          <td>${fmtEUR(u.eur_cents)}</td>
          <td>${esc(fmtCoin(u.rucoin_cents))}</td>
          <td>#${u.id}</td>
        </tr>`).join('')
      : '<tr><td colspan="5" class="empty-cell">Аккаунтов нет</td></tr>';

    $('adjust-user').innerHTML =
      '<option value="">Выбери аккаунт</option>' +
      users.filter(u => u.role !== 'admin').map(u =>
        `<option value="${u.id}">${esc(u.username)} · #${u.id}</option>`
      ).join('');

    const logs = ledgerData.items || [];

    $('admin-ledger-body').innerHTML = logs.length
      ? logs.map(item => {
          const eur = item.eur_delta
            ? `${item.eur_delta > 0 ? '+' : '−'}${fmtEUR(Math.abs(item.eur_delta))}`
            : '—';

          const coin = item.rucoin_delta
            ? `${item.rucoin_delta > 0 ? '+' : '−'}${fmtCoin(Math.abs(item.rucoin_delta))}`
            : '—';

          return `<tr>
            <td><b>${esc(item.username)}</b></td>
            <td>${esc(item.description)}</td>
            <td class="${item.eur_delta > 0 ? 'delta-positive' : item.eur_delta < 0 ? 'delta-negative' : ''}">${esc(eur)}</td>
            <td>${esc(coin)}</td>
            <td>${fmtDate(item.created_at)}</td>
          </tr>`;
        }).join('')
      : '<tr><td colspan="5" class="empty-cell">Журнал пока пуст</td></tr>';

  } catch (error) {
    setMessage('admin-message', error.message, true);
  }
}

async function submitAdjust(event) {
  event.preventDefault();

  try {
    const result = await api('/api/admin/adjust', {
      user_id: $('adjust-user').value,
      asset: $('adjust-asset').value,
      action: state.adjustAction,
      amount: $('adjust-amount').value,
      reason: $('adjust-reason').value.trim()
    });

    setMessage('admin-message', result.message);
    toast(result.message);

    $('adjust-amount').value = '';
    $('adjust-reason').value = '';

    await loadAdmin();

  } catch (error) {
    setMessage('admin-message', error.message, true);
  }
}

function drawChart(canvasId, data, color = '#8d79ff') {
  const canvas = $(canvasId);
  if (!canvas || !data.length) return;

  const rect = canvas.getBoundingClientRect();
  if (!rect.width) return;

  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(1, Math.floor(rect.width * dpr));
  const height = Math.max(1, Math.floor(rect.height * dpr));

  canvas.width = width;
  canvas.height = height;

  const ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = rect.height;

  const pad = {
    left: 8,
    right: 8,
    top: 12,
    bottom: 14
  };

  const min = Math.min(...data) - 1.2;
  const max = Math.max(...data) + 1.2;

  const x = i =>
    pad.left + i * (w - pad.left - pad.right) / (data.length - 1);

  const y = v =>
    pad.top + (max - v) * (h - pad.top - pad.bottom) / (max - min);

  ctx.strokeStyle = 'rgba(135,155,190,.11)';
  ctx.lineWidth = 1;

  for (let i = 0; i < 4; i++) {
    const yy = pad.top +
      i * (h - pad.top - pad.bottom) / 3;

    ctx.beginPath();
    ctx.moveTo(pad.left, yy);
    ctx.lineTo(w - pad.right, yy);
    ctx.stroke();
  }

  ctx.beginPath();

  data.forEach((v, i) =>
    i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))
  );

  ctx.lineTo(x(data.length - 1), h - pad.bottom);
  ctx.lineTo(x(0), h - pad.bottom);
  ctx.closePath();

  const gradient = ctx.createLinearGradient(0, 0, 0, h);

  gradient.addColorStop(0, 'rgba(139,114,255,.23)');
  gradient.addColorStop(1, 'rgba(139,114,255,0)');

  ctx.fillStyle = gradient;
  ctx.fill();

  ctx.beginPath();

  data.forEach((v, i) =>
    i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))
  );

  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.lineJoin = 'round';
  ctx.stroke();

  ctx.beginPath();
  ctx.arc(
    x(data.length - 1),
    y(data[data.length - 1]),
    3.5,
    0,
    Math.PI * 2
  );

  ctx.fillStyle = '#5bd7d2';
  ctx.fill();
}

function drawCharts() {
  const series = state.marketHistory.map(
    item => Number(item.price_cents) / 100
  );

  if (series.length === 0) {
    series.push(state.marketPriceCents / 100);
  }

  if (series.length === 1) {
    series.unshift(series[0]);
  }

  drawChart('overview-chart', series);
  drawChart('market-chart', series);
}

// Навигация и обработчики

$('auth-form').addEventListener('submit', submitAuth);

document.querySelectorAll('[data-auth-mode]').forEach(btn =>
  btn.addEventListener('click', () => setAuthMode(btn.dataset.authMode))
);

document.querySelectorAll('.nav-item').forEach(btn =>
  btn.addEventListener('click', () => goTo(btn.dataset.view))
);

document.querySelectorAll('[data-go]').forEach(btn =>
  btn.addEventListener('click', () => goTo(btn.dataset.go))
);

$('trade-form').addEventListener('submit', submitTrade);
$('trade-amount').addEventListener('input', updateTradeQuote);

document.querySelectorAll('[data-side]').forEach(btn =>
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-side]').forEach(b =>
      b.classList.toggle('active', b === btn)
    );

    $('trade-side').value = btn.dataset.side;

    setMessage('trade-message', '');
    updateTradeQuote();
  })
);

document.querySelectorAll('[data-coin-amount]').forEach(btn =>
  btn.addEventListener('click', () => {
    $('trade-amount').value = btn.dataset.coinAmount;
    updateTradeQuote();
  })
);

document.querySelectorAll('[data-deposit]').forEach(btn =>
  btn.addEventListener('click', () =>
    doDeposit(Number(btn.dataset.deposit))
  )
);

$('withdraw-form').addEventListener('submit', submitWithdraw);
$('adjust-form').addEventListener('submit', submitAdjust);

document.querySelectorAll('[data-adjust]').forEach(btn =>
  btn.addEventListener('click', () => {
    state.adjustAction = btn.dataset.adjust;
    $('adjust-action').value = state.adjustAction;

    document.querySelectorAll('[data-adjust]').forEach(b =>
      b.classList.toggle('active', b === btn)
    );
  })
);

$('refresh-users').addEventListener('click', loadAdmin);

$('logout-btn').addEventListener('click', async () => {
  try {
    await api('/api/logout', {});
  } catch (e) {
    // Сессия могла уже завершиться.
  }

  state.view = 'overview';
  showAuth();
  toast('Вы вышли из аккаунта.');
});

$('menu-toggle').addEventListener('click', () =>
  $('sidebar').classList.toggle('open')
);

$('banner-close').addEventListener('click', () =>
  document.querySelector('.demo-banner')?.classList.add('hidden')
);

window.addEventListener('resize', () =>
  setTimeout(drawCharts, 50)
);

setInterval(updateClock, 1000);
setInterval(loadMarket, 15000);

(async function boot() {
  setAuthMode('login');

  try {
    await loadApp();
  } catch (error) {
    showAuth();
    setMessage('auth-message', error.message, true);
  }
})();
