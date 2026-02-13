// ==================== State ====================
let currentUser = null;
let pins = [];
let folders = [];
let kmlFolders = [];
let kmlFiles = [];
let allUsers = [];
let kmlLayers = {};
let myLocationMarker = null;
let myLocationCircle = null;
let pinMarkers = {};
let pinMode = false;
let pendingPinLatLng = null;
let editingPinId = null;
let authMode = 'login';
let watchId = null;
let pendingUsersCount = 0;
let pushSubscription = null;
let deferredInstallPrompt = null;
let userUsageData = null;

// ==================== Map Init ====================
const map = L.map('map', {
  center: [35.0, 135.0],
  zoom: 6,
  zoomControl: false,
  minZoom: 2,
  maxBounds: [[-90, -180], [90, 180]],
  maxBoundsViscosity: 1.0
});

L.control.zoom({ position: 'bottomright' }).addTo(map);

// GSI Tiles
const gsiStd = L.tileLayer('https://cyberjapandata.gsi.go.jp/xyz/std/{z}/{x}/{y}.png', {
  attribution: '<a href="https://maps.gsi.go.jp/development/ichiran.html">国土地理院</a>',
  maxZoom: 18,
  noWrap: true
});
const gsiPhoto = L.tileLayer('https://cyberjapandata.gsi.go.jp/xyz/seamlessphoto/{z}/{x}/{y}.jpg', {
  attribution: '<a href="https://maps.gsi.go.jp/development/ichiran.html">国土地理院</a>',
  maxZoom: 18,
  noWrap: true
});

gsiStd.addTo(map);
L.control.layers({
  '国土地理院地図': gsiStd,
  '航空写真': gsiPhoto
}, {}, { position: 'topright' }).addTo(map);

// Map click for pin placement
map.getContainer().addEventListener('click', function(e) {
  if (!pinMode) return;
  if (e.target.closest('.leaflet-control-container, .leaflet-popup, .header-buttons')) return;
  const rect = map.getContainer().getBoundingClientRect();
  const point = L.point(e.clientX - rect.left, e.clientY - rect.top);
  pendingPinLatLng = map.containerPointToLatLng(point);
  populateFolderSelect('pin-folder');
  document.getElementById('pin-title').value = '';
  document.getElementById('pin-desc').value = '';
  document.getElementById('pin-images').value = '';
  document.getElementById('pin-image-preview').innerHTML = '';
  openModal('modal-pin');
});

// ==================== Utility ====================
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

function notify(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = 'notification notification-' + type;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 2500);
}

async function api(url, opts = {}) {
  let res;
  try {
    res = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...opts.headers },
      credentials: 'include',
      ...opts
    });
  } catch (err) {
    throw new Error('ネットワークエラー: サーバーに接続できません');
  }
  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error('サーバーからの応答を解析できませんでした');
  }
  if (!res.ok) throw new Error(data.error || 'エラーが発生しました');
  return data;
}

async function apiFormData(url, formData) {
  const res = await fetch(url, {
    method: 'POST',
    body: formData,
    credentials: 'include'
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || 'エラーが発生しました');
  return data;
}

function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

// Get visibility badge based on public/shared status
function getVisibilityBadge(isPublic, isShared) {
  if (isPublic) {
    return '<span class="badge badge-public">公開</span>';
  } else if (isShared) {
    return '<span class="badge badge-shared">共有</span>';
  } else {
    return '<span class="badge badge-private">非公開</span>';
  }
}

// ==================== Auth ====================
let loginMode = 'login';

async function checkAuth() {
  try {
    currentUser = await api('/api/auth/me');
    updateLoginScreen();
    updateUI();
  } catch {
    currentUser = null;
    updateLoginScreen();
    updateUI();
  }
}

function updateLoginScreen() {
  const loginScreen = document.getElementById('login-screen');
  if (currentUser) {
    loginScreen.classList.add('hidden');
  } else {
    loginScreen.classList.remove('hidden');
  }
}

function toggleLoginMode(e) {
  e.preventDefault();
  loginMode = loginMode === 'login' ? 'register' : 'login';
  document.getElementById('login-email-group').style.display = loginMode === 'register' ? '' : 'none';
  document.getElementById('login-display-name-group').style.display = loginMode === 'register' ? '' : 'none';
  document.getElementById('login-terms').style.display = loginMode === 'register' ? '' : 'none';
  document.getElementById('login-submit').textContent = loginMode === 'login' ? 'ログイン' : 'アカウント作成';
  document.getElementById('login-toggle-link').textContent = loginMode === 'login' ? 'アカウントを作成' : 'ログインする';
  document.getElementById('login-username').placeholder = loginMode === 'register' ? 'Taro Yamada' : 'ユーザー名';
  document.querySelector('#login-form .form-group:first-child label').textContent = loginMode === 'register' ? 'User Name (Full Name)' : 'ユーザー名';
  document.getElementById('login-error').classList.remove('show');
}

async function submitLogin() {
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const email = document.getElementById('login-email').value.trim();
  const displayName = document.getElementById('login-display-name').value.trim();
  const errEl = document.getElementById('login-error');

  if (!username || !password) {
    errEl.textContent = 'ユーザー名とパスワードを入力してください';
    errEl.classList.add('show');
    return;
  }

  if (loginMode === 'register' && !email) {
    errEl.textContent = 'メールアドレスを入力してください';
    errEl.classList.add('show');
    return;
  }

  try {
    const endpoint = loginMode === 'login' ? '/api/auth/login' : '/api/auth/register';
    const body = loginMode === 'login'
      ? { username, password }
      : { username, password, email, display_name: displayName || username };
    const result = await api(endpoint, { method: 'POST', body: JSON.stringify(body) });

    // Handle pending registration
    if (result.pending) {
      errEl.textContent = '';
      errEl.classList.remove('show');
      // Show success modal
      openModal('modal-register-success');
      // Clear form and switch to login mode
      document.getElementById('login-username').value = '';
      document.getElementById('login-password').value = '';
      document.getElementById('login-email').value = '';
      document.getElementById('login-display-name').value = '';
      loginMode = 'login';
      document.getElementById('login-email-group').style.display = 'none';
      document.getElementById('login-display-name-group').style.display = 'none';
      document.getElementById('login-submit').textContent = 'ログイン';
      document.getElementById('login-toggle-link').textContent = 'アカウントを作成';
      document.getElementById('login-username').placeholder = 'ユーザー名';
      document.querySelector('#login-form .form-group:first-child label').textContent = 'ユーザー名';
      return;
    }

    currentUser = result;
    updateLoginScreen();
    notify('ログインしました');
    updateUI();
    loadAll();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.classList.add('show');
  }
}

function showAuthModal(mode = 'login') {
  authMode = mode;
  document.getElementById('auth-title').textContent = mode === 'login' ? 'ログイン' : 'アカウント作成';
  document.getElementById('auth-submit').textContent = mode === 'login' ? 'ログイン' : '作成';
  document.getElementById('auth-toggle').textContent = mode === 'login' ? 'アカウントを作成' : 'ログインする';
  document.getElementById('auth-username').value = '';
  document.getElementById('auth-password').value = '';
  document.getElementById('auth-display-name').value = '';
  document.getElementById('auth-display-name-group').style.display = mode === 'register' ? '' : 'none';
  document.getElementById('auth-error').style.display = 'none';
  openModal('modal-auth');
}

function toggleAuthMode(e) {
  e.preventDefault();
  showAuthModal(authMode === 'login' ? 'register' : 'login');
}

async function submitAuth() {
  const username = document.getElementById('auth-username').value.trim();
  const password = document.getElementById('auth-password').value;
  const displayName = document.getElementById('auth-display-name').value.trim();
  const errEl = document.getElementById('auth-error');
  try {
    const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/register';
    const body = authMode === 'login'
      ? { username, password }
      : { username, password, display_name: displayName || username };
    const result = await api(endpoint, { method: 'POST', body: JSON.stringify(body) });

    // Handle pending registration
    if (result.pending) {
      closeModal('modal-auth');
      notify(result.message, 'success');
      return;
    }

    currentUser = result;
    closeModal('modal-auth');
    notify(authMode === 'login' ? 'ログインしました' : 'アカウントを作成しました');
    updateUI();
    loadAll();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
}

async function logout() {
  await api('/api/auth/logout', { method: 'POST' });
  currentUser = null;
  userUsageData = null;
  notify('ログアウトしました');
  updateLoginScreen();
  updateUI();
}

// Password setup for external members
function checkPasswordSetup() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('setup') === 'password') {
    const email = params.get('email');
    if (email) {
      showPasswordSetupModal(decodeURIComponent(email));
    }
  }
}

function showPasswordSetupModal(email) {
  document.getElementById('setup-email').value = email;
  document.getElementById('setup-username').value = '';
  document.getElementById('setup-display-name').value = '';
  document.getElementById('setup-password').value = '';
  document.getElementById('setup-password-confirm').value = '';
  document.getElementById('setup-error').style.display = 'none';
  openModal('modal-password-setup');
}

async function submitPasswordSetup() {
  const email = document.getElementById('setup-email').value;
  const username = document.getElementById('setup-username').value.trim();
  const displayName = document.getElementById('setup-display-name').value.trim();
  const password = document.getElementById('setup-password').value;
  const passwordConfirm = document.getElementById('setup-password-confirm').value;
  const errEl = document.getElementById('setup-error');

  // Validate username (full name in Roman letters)
  if (!username) {
    errEl.textContent = 'ユーザー名を入力してください';
    errEl.style.display = 'block';
    return;
  }

  const fullNamePattern = /^[A-Za-z]+\s+[A-Za-z]+(\s+[A-Za-z]+)*$/;
  if (!fullNamePattern.test(username)) {
    errEl.textContent = 'ユーザー名はローマ字のフルネームで入力してください（例: Taro Yamada）';
    errEl.style.display = 'block';
    return;
  }

  if (!password) {
    errEl.textContent = 'パスワードを入力してください';
    errEl.style.display = 'block';
    return;
  }

  if (password.length < 12) {
    errEl.textContent = 'パスワードは12文字以上にしてください';
    errEl.style.display = 'block';
    return;
  }

  if (password !== passwordConfirm) {
    errEl.textContent = 'パスワードが一致しません';
    errEl.style.display = 'block';
    return;
  }

  try {
    const result = await api('/api/auth/setup-password', {
      method: 'POST',
      body: JSON.stringify({ email, username, display_name: displayName || username, password })
    });

    closeModal('modal-password-setup');
    currentUser = result.user;
    notify('アカウントを設定しました');

    // Clear URL params
    window.history.replaceState({}, document.title, window.location.pathname);

    updateLoginScreen();
    updateUI();
    loadAll();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
}

async function loadUsers() {
  if (!currentUser) { allUsers = []; return; }
  try {
    allUsers = await api('/api/users');
  } catch { allUsers = []; }
}

// ==================== UI ====================
function updateUI() {
  document.getElementById('btn-add-pin').style.display = currentUser ? '' : 'none';
  document.getElementById('btn-notifications').style.display = currentUser ? '' : 'none';
  if (currentUser) {
    checkUnreadComments();
    // Check for new comments every 30 seconds
    if (!window.notificationInterval) {
      window.notificationInterval = setInterval(checkUnreadComments, 30000);
    }
    // Check when app becomes visible (user returns to app)
    if (!window.visibilityListenerAdded) {
      window.visibilityListenerAdded = true;
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' && currentUser) {
          checkUnreadComments();
        }
      });
    }
  } else {
    if (window.notificationInterval) {
      clearInterval(window.notificationInterval);
      window.notificationInterval = null;
    }
  }
  renderSidebar();
}

function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
}

function renderSidebar() {
  const c = document.getElementById('sidebar-content');
  let html = '';

  // Auth section
  if (currentUser) {
    const tierBadge = userUsageData
      ? (userUsageData.plan === 'premium' || userUsageData.is_admin
          ? '<span class="badge badge-premium">Premium</span>'
          : '<span class="badge badge-free">Free</span>')
      : '';
    html += `<div class="user-info">
      <i class="fas fa-user"></i> <span>${escHtml(currentUser.display_name || currentUser.username)}</span>
      ${currentUser.is_admin ? ' <span class="badge badge-public">管理者</span>' : ''}
      ${tierBadge}
      <div style="float:right;display:flex;gap:4px;">
        ${currentUser.is_admin ? `<button class="btn btn-sm btn-secondary admin-btn" onclick="showAdminPanel()" title="管理者パネル">
          <i class="fas fa-user-shield"></i>${pendingUsersCount > 0 ? `<span class="notification-badge">${pendingUsersCount}</span>` : ''}
        </button>` : ''}
        <button class="btn btn-sm btn-secondary" onclick="showAccountSettings()" title="設定"><i class="fas fa-cog"></i></button>
        <button class="btn btn-sm btn-secondary" onclick="logout()">ログアウト</button>
      </div>
    </div>`;
  } else {
    html += `<div style="margin-bottom:12px;">
      <button class="btn btn-primary btn-block" onclick="showAuthModal('login')">
        <i class="fas fa-sign-in-alt"></i> ログイン / アカウント作成
      </button>
    </div>`;
  }

  // KML Folders section
  html += '<div class="section-title">KMLフォルダ</div>';
  if (currentUser) {
    html += `<div style="margin-bottom:8px;display:flex;gap:4px;">
      <button class="btn btn-sm btn-primary" onclick="showKmlFolderModal()">
        <i class="fas fa-folder-plus"></i> フォルダ作成
      </button>
      <button class="btn btn-sm btn-secondary" onclick="showReorderKmlFoldersModal()" title="並び替え">
        <i class="fas fa-sort"></i>
      </button>
    </div>`;
  }
  html += renderKmlFolderList();

  // Pin Folders section (pins grouped by folder)
  if (currentUser) {
    html += '<div class="section-title">ピンフォルダ</div>';
    html += `<div style="margin-bottom:8px;display:flex;gap:4px;">
      <button class="btn btn-sm btn-primary" onclick="showFolderModal()">
        <i class="fas fa-folder-plus"></i> フォルダ作成
      </button>
      <button class="btn btn-sm btn-secondary" onclick="showReorderFoldersModal()" title="並び替え">
        <i class="fas fa-sort"></i>
      </button>
    </div>`;
    html += renderPinFolderList();
  }

  // Usage limits footer for free tier users
  if (currentUser && userUsageData && userUsageData.has_limits) {
    const u = userUsageData.usage;
    html += `<div class="sidebar-usage-footer">
      <div class="usage-title"><i class="fas fa-chart-pie"></i> 無料プラン使用状況</div>
      <div class="usage-items">
        <div class="usage-item">
          <span class="usage-label">KMLフォルダ</span>
          <span class="usage-value ${u.kmlFolders.current >= u.kmlFolders.max ? 'at-limit' : ''}">${u.kmlFolders.current}/${u.kmlFolders.max}</span>
        </div>
        <div class="usage-item">
          <span class="usage-label">ピンフォルダ</span>
          <span class="usage-value ${u.pinFolders.current >= u.pinFolders.max ? 'at-limit' : ''}">${u.pinFolders.current}/${u.pinFolders.max}</span>
        </div>
        <div class="usage-item">
          <span class="usage-label">KMLファイル</span>
          <span class="usage-value ${u.kmlFiles.current >= u.kmlFiles.max ? 'at-limit' : ''}">${u.kmlFiles.current}/${u.kmlFiles.max}</span>
        </div>
        <div class="usage-item">
          <span class="usage-label">ピン</span>
          <span class="usage-value ${u.pins.current >= u.pins.max ? 'at-limit' : ''}">${u.pins.current}/${u.pins.max}</span>
        </div>
        <div class="usage-item">
          <span class="usage-label">共有</span>
          <span class="usage-value ${u.shares.current >= u.shares.max ? 'at-limit' : ''}">${u.shares.current}/${u.shares.max}</span>
        </div>
      </div>
      <a href="#" onclick="showAccountSettings();return false;" class="upgrade-link">
        <i class="fas fa-crown"></i> プレミアムにアップグレード
      </a>
    </div>`;
  }

  c.innerHTML = html;
}

// ==================== KML Folder Management ====================
function renderKmlFolderList() {
  if (kmlFolders.length === 0 && !currentUser) {
    return '<p style="font-size:13px;color:#999;">KMLデータがありません</p>';
  }
  if (kmlFolders.length === 0) {
    return '<p style="font-size:13px;color:#999;">フォルダがありません</p>';
  }

  let html = '';
  // Render only top-level folders (parent_id = null)
  const topFolders = kmlFolders.filter(f => !f.parent_id);
  for (const folder of topFolders) {
    html += renderKmlFolderNode(folder, 0);
  }
  return html;
}

function renderKmlFolderNode(folder, depth) {
  const files = kmlFiles.filter(f => f.folder_id === folder.id);
  const childFolders = kmlFolders.filter(f => f.parent_id === folder.id);
  const isOwner = folder.is_owner;
  const isVisible = folder.is_visible;
  const visBadge = getVisibilityBadge(folder.is_public, folder.is_shared);
  const totalCount = files.length + childFolders.length;

  let html = `<div class="kml-folder-item" style="margin-left:${depth * 12}px;" data-folder-id="${folder.id}">
    <div class="folder-name-row">${escHtml(folder.name)} ${visBadge} <span class="folder-count">(${totalCount})</span></div>
    <div class="kml-folder-header" onclick="toggleKmlFolder(${folder.id})">
      <i class="fas fa-chevron-right toggle-icon"></i>
      <i class="fas fa-folder folder-icon"></i>
      <div class="kml-folder-actions" onclick="event.stopPropagation()">
        <button onclick="toggleKmlFolderVisibilityBtn(${folder.id})" title="表示切替" class="icon-btn ${isVisible ? 'active' : ''}"><i class="fas fa-eye"></i></button>
        ${isOwner ? `<button onclick="showRenameKmlFolderModal(${folder.id})" title="名前変更" class="icon-btn"><i class="fas fa-edit"></i></button>
        <button onclick="showMoveKmlFolderModal(${folder.id})" title="移動" class="icon-btn"><i class="fas fa-arrows-alt"></i></button>
        <button onclick="showKmlUploadModal(${folder.id})" title="追加" class="icon-btn"><i class="fas fa-plus"></i></button>` : ''}
        ${(isOwner || folder.is_shared) ? `<button onclick="showShareKmlFolderModal(${folder.id})" title="${isOwner ? '共有' : 'メンバー確認'}" class="icon-btn"><i class="fas fa-share-alt"></i></button>` : ''}
        ${isOwner ? `<button onclick="deleteKmlFolder(${folder.id})" title="削除" class="icon-btn delete"><i class="fas fa-trash"></i></button>` : ''}
      </div>
    </div>
    <div class="kml-folder-files" id="kml-folder-files-${folder.id}">`;

  // Render child folders first
  for (const child of childFolders) {
    html += renderKmlFolderNode(child, 0);
  }

  // Then render files
  if (files.length > 0) {
    html += files.map(f => `
      <div class="kml-file-item" data-file-id="${f.id}">
        <i class="fas fa-file"></i>
        <span class="kml-file-name" onclick="focusKmlFile(${f.id})">${escHtml(f.original_name)}</span>
        <div class="kml-file-actions">
          <button onclick="zoomToKmlFile(${f.id})" title="ズーム" class="icon-btn"><i class="fas fa-search-plus"></i></button>
          ${isOwner ? `<button onclick="showMoveKmlFileModal(${f.id})" title="移動" class="icon-btn"><i class="fas fa-arrows-alt"></i></button>
          <button onclick="deleteKmlFile(${f.id})" title="削除" class="icon-btn delete"><i class="fas fa-trash"></i></button>` : ''}
        </div>
      </div>
    `).join('');
  } else if (childFolders.length === 0) {
    html += '<p style="font-size:12px;color:#999;padding:4px;">ファイルがありません</p>';
  }

  html += '</div></div>';
  return html;
}

function toggleKmlFolder(folderId) {
  const header = document.querySelector(`.kml-folder-item[data-folder-id="${folderId}"] .kml-folder-header`);
  const files = document.getElementById(`kml-folder-files-${folderId}`);
  header.classList.toggle('expanded');
  files.classList.toggle('open');
}

async function toggleKmlFolderVisibility(folderId, visible) {
  if (!currentUser) return;
  try {
    await api(`/api/kml-folders/${folderId}/visibility`, {
      method: 'POST',
      body: JSON.stringify({ is_visible: visible })
    });
    // Update local state
    const folder = kmlFolders.find(f => f.id === folderId);
    if (folder) folder.is_visible = visible ? 1 : 0;
    // Update map layers
    updateKmlLayers();
  } catch (err) {
    notify(err.message, 'error');
  }
}

function updateKmlLayers() {
  // Remove all KML layers
  Object.values(kmlLayers).forEach(layer => map.removeLayer(layer));
  kmlLayers = {};

  // Add visible folders' files
  for (const folder of kmlFolders) {
    if (!folder.is_visible) continue;
    const files = kmlFiles.filter(f => f.folder_id === folder.id);
    for (const file of files) {
      displayKmlFile(file);
    }
  }
}

function zoomToKmlFolder(folderId) {
  const files = kmlFiles.filter(f => f.folder_id === folderId);
  const bounds = L.latLngBounds([]);
  for (const file of files) {
    if (kmlLayers[file.id] && kmlLayers[file.id].getLayers().length > 0) {
      bounds.extend(kmlLayers[file.id].getBounds());
    }
  }
  if (bounds.isValid()) {
    map.fitBounds(bounds, { padding: [50, 50] });
  } else {
    notify('表示中のKMLがありません', 'error');
  }
}

function zoomToKmlFile(fileId) {
  if (kmlLayers[fileId] && kmlLayers[fileId].getLayers().length > 0) {
    map.fitBounds(kmlLayers[fileId].getBounds(), { padding: [50, 50] });
  } else {
    notify('KMLが表示されていません', 'error');
  }
}

function focusKmlFile(fileId) {
  // Close sidebar on mobile
  if (window.innerWidth <= 600) toggleSidebar();
  // Zoom to KML
  zoomToKmlFile(fileId);
}

async function toggleKmlFolderVisibilityBtn(folderId) {
  const folder = kmlFolders.find(f => f.id === folderId);
  if (!folder) return;

  const newVisible = !folder.is_visible;

  // Update icon immediately
  const btn = document.querySelector(`.kml-folder-item[data-folder-id="${folderId}"] .icon-btn[title="表示切替"]`);
  if (btn) {
    btn.classList.toggle('active', newVisible);
  }

  await toggleKmlFolderVisibility(folderId, newVisible);
}

function displayKmlFile(file) {
  const geoJsonOptions = {
    interactive: false,
    style: function() {
      return { color: '#e53935', weight: 2, opacity: 0.9, fillOpacity: 0 };
    }
  };

  // Extract key from r2_key (e.g., "kml/uuid.kml" -> "uuid.kml")
  const key = file.r2_key.replace('kml/', '');
  const layer = omnivore
    .kml(`/api/kml-files/${key}`, null, L.geoJson(null, geoJsonOptions))
    .on('error', () => {
      console.error('KML load error:', file.original_name);
      notify(`KML読み込みエラー: ${file.original_name}`, 'error');
    })
    .addTo(map);
  kmlLayers[file.id] = layer;
}

function showKmlFolderModal() {
  document.getElementById('kml-folder-name').value = '';
  document.getElementById('kml-folder-public').checked = false;
  document.getElementById('kml-folder-public').parentElement.style.display = currentUser?.is_admin ? '' : 'none';
  populateKmlFolderSelect('kml-folder-parent', null);
  openModal('modal-kml-folder');
}

function populateKmlFolderSelect(selectId, selectedId) {
  const sel = document.getElementById(selectId);
  sel.innerHTML = '<option value="">-- なし --</option>';
  function addOptions(parentId, depth) {
    const children = kmlFolders.filter(f => (f.parent_id || null) === parentId && f.is_owner);
    for (const f of children) {
      const opt = document.createElement('option');
      opt.value = f.id;
      opt.textContent = '\u00A0\u00A0'.repeat(depth) + f.name;
      if (f.id == selectedId) opt.selected = true;
      sel.appendChild(opt);
      addOptions(f.id, depth + 1);
    }
  }
  addOptions(null, 0);
}

async function createKmlFolder() {
  const name = document.getElementById('kml-folder-name').value.trim();
  if (!name) { notify('フォルダ名を入力してください', 'error'); return; }

  try {
    await api('/api/kml-folders', {
      method: 'POST',
      body: JSON.stringify({
        name,
        parent_id: document.getElementById('kml-folder-parent').value || null,
        is_public: document.getElementById('kml-folder-public').checked
      })
    });
    closeModal('modal-kml-folder');
    notify('KMLフォルダを作成しました');
    await loadKmlFolders();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

async function deleteKmlFolder(folderId) {
  const folder = kmlFolders.find(f => f.id === folderId);
  if (!folder) return;
  const files = kmlFiles.filter(f => f.folder_id === folderId);
  const hasShares = folder.shared_with;

  let msg = 'このKMLフォルダを削除しますか？\n\n';
  if (files.length > 0) {
    msg += `⚠️ 内包している ${files.length} 件のKMLファイルも全て削除されます。\n`;
  }
  if (hasShares) {
    msg += '⚠️ 共有中のユーザーからも削除されます。\n';
  }
  msg += '\nこの操作は取り消せません。';

  if (!confirm(msg)) return;
  try {
    await api(`/api/kml-folders/${folderId}`, { method: 'DELETE' });
    notify('KMLフォルダを削除しました');
    await loadKmlFolders();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

// Move KML folder to another parent
function showMoveKmlFolderModal(folderId) {
  document.getElementById('move-kml-folder-id').value = folderId;
  const folder = kmlFolders.find(f => f.id === folderId);
  document.getElementById('move-kml-folder-name').textContent = folder ? folder.name : '';

  // Populate folder select excluding self and children
  const sel = document.getElementById('move-kml-folder-target');
  sel.innerHTML = '<option value="">-- ルート（最上位）--</option>';

  function addOptions(parentId, depth) {
    const children = kmlFolders.filter(f => (f.parent_id || null) === parentId && f.is_owner);
    for (const f of children) {
      if (f.id === folderId) continue;
      // Check if f is a descendant of folderId (prevent circular)
      let isDescendant = false;
      let current = f;
      while (current && current.parent_id) {
        if (current.parent_id === folderId) { isDescendant = true; break; }
        current = kmlFolders.find(p => p.id === current.parent_id);
      }
      if (isDescendant) continue;

      const opt = document.createElement('option');
      opt.value = f.id;
      opt.textContent = '\u00A0\u00A0'.repeat(depth) + f.name;
      if (f.id === folder?.parent_id) opt.selected = true;
      sel.appendChild(opt);
      addOptions(f.id, depth + 1);
    }
  }
  addOptions(null, 0);
  openModal('modal-move-kml-folder');
}

async function moveKmlFolder() {
  const folderId = document.getElementById('move-kml-folder-id').value;
  const targetId = document.getElementById('move-kml-folder-target').value || null;

  try {
    await api(`/api/kml-folders/${folderId}/move`, {
      method: 'POST',
      body: JSON.stringify({ parent_id: targetId ? parseInt(targetId) : null })
    });
    closeModal('modal-move-kml-folder');
    notify('KMLフォルダを移動しました');
    loadKmlFolders();
  } catch (err) { notify(err.message, 'error'); }
}

// Folder reorder modals
function showReorderKmlFoldersModal() {
  const listEl = document.getElementById('reorder-kml-folder-list');
  const topFolders = kmlFolders.filter(f => !f.parent_id && f.is_owner);
  listEl.innerHTML = topFolders.map(f => `
    <div class="reorder-item" data-id="${f.id}">
      <span>${escHtml(f.name)}</span>
      <div class="reorder-buttons">
        <button onclick="reorderKmlFolder(${f.id}, -1)" class="icon-btn"><i class="fas fa-arrow-up"></i></button>
        <button onclick="reorderKmlFolder(${f.id}, 1)" class="icon-btn"><i class="fas fa-arrow-down"></i></button>
      </div>
    </div>
  `).join('') || '<p style="color:#999;">フォルダがありません</p>';
  openModal('modal-reorder-kml-folders');
}

async function reorderKmlFolder(folderId, direction) {
  const topFolders = kmlFolders.filter(f => !f.parent_id && f.is_owner);
  const idx = topFolders.findIndex(f => f.id === folderId);
  const targetIdx = idx + direction;
  if (targetIdx < 0 || targetIdx >= topFolders.length) return;

  const targetFolder = topFolders[targetIdx];
  try {
    await api(`/api/kml-folders/${folderId}/reorder`, {
      method: 'POST',
      body: JSON.stringify({ target_id: targetFolder.id })
    });
    await loadKmlFolders();
    showReorderKmlFoldersModal(); // Refresh list
  } catch (err) { notify(err.message, 'error'); }
}

function showReorderFoldersModal() {
  const listEl = document.getElementById('reorder-folder-list');
  const topFolders = folders.filter(f => !f.parent_id && f.is_owner);
  listEl.innerHTML = topFolders.map(f => `
    <div class="reorder-item" data-id="${f.id}">
      <span>${escHtml(f.name)}</span>
      <div class="reorder-buttons">
        <button onclick="reorderFolder(${f.id}, -1)" class="icon-btn"><i class="fas fa-arrow-up"></i></button>
        <button onclick="reorderFolder(${f.id}, 1)" class="icon-btn"><i class="fas fa-arrow-down"></i></button>
      </div>
    </div>
  `).join('') || '<p style="color:#999;">フォルダがありません</p>';
  openModal('modal-reorder-folders');
}

async function reorderFolder(folderId, direction) {
  const topFolders = folders.filter(f => !f.parent_id && f.is_owner);
  const idx = topFolders.findIndex(f => f.id === folderId);
  const targetIdx = idx + direction;
  if (targetIdx < 0 || targetIdx >= topFolders.length) return;

  const targetFolder = topFolders[targetIdx];
  try {
    await api(`/api/folders/${folderId}/reorder`, {
      method: 'POST',
      body: JSON.stringify({ target_id: targetFolder.id })
    });
    await loadFolders();
    showReorderFoldersModal(); // Refresh list
  } catch (err) { notify(err.message, 'error'); }
}

function showRenameKmlFolderModal(folderId) {
  const folder = kmlFolders.find(f => f.id === folderId);
  if (!folder) return;
  document.getElementById('rename-kml-folder-id').value = folderId;
  document.getElementById('rename-kml-folder-name').value = folder.name;
  document.getElementById('rename-kml-folder-public').checked = !!folder.is_public;
  document.getElementById('rename-kml-folder-public').parentElement.style.display = currentUser?.is_admin ? '' : 'none';
  openModal('modal-rename-kml-folder');
}

async function renameKmlFolder() {
  const folderId = document.getElementById('rename-kml-folder-id').value;
  const name = document.getElementById('rename-kml-folder-name').value.trim();
  if (!name) { notify('フォルダ名を入力してください', 'error'); return; }

  try {
    await api(`/api/kml-folders/${folderId}`, {
      method: 'PUT',
      body: JSON.stringify({
        name,
        is_public: document.getElementById('rename-kml-folder-public').checked
      })
    });
    closeModal('modal-rename-kml-folder');
    notify('フォルダ設定を変更しました');
    loadKmlFolders();
  } catch (err) { notify(err.message, 'error'); }
}

function showKmlUploadModal(folderId) {
  document.getElementById('kml-upload-folder-id').value = folderId;
  document.getElementById('kml-upload-file').value = '';
  openModal('modal-kml-upload');
}

async function uploadKmlFile() {
  const folderId = document.getElementById('kml-upload-folder-id').value;
  const fileInput = document.getElementById('kml-upload-file');
  if (!fileInput.files || !fileInput.files[0]) {
    notify('ファイルを選択してください', 'error');
    return;
  }

  const formData = new FormData();
  formData.append('kml', fileInput.files[0]);
  formData.append('folder_id', folderId);

  try {
    await apiFormData('/api/kml-files/upload', formData);
    closeModal('modal-kml-upload');
    notify('KMLをアップロードしました');
    await loadKmlFolders();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

async function deleteKmlFile(fileId) {
  if (!confirm('このKMLファイルを削除しますか？')) return;
  try {
    await api(`/api/kml-files/${fileId}`, { method: 'DELETE' });
    notify('KMLを削除しました');
    await loadKmlFolders();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

let shareKmlSharedWith = [];

async function showShareKmlFolderModal(folderId) {
  document.getElementById('share-kml-folder-id').value = folderId;
  const folder = kmlFolders.find(f => f.id === folderId);
  const isOwner = folder?.is_owner || (currentUser && currentUser.is_admin);

  // Clear previous state to prevent checkbox states from carrying over between folders
  shareKmlSharedWith = [];
  document.getElementById('share-kml-user-list').innerHTML = '';

  // Fetch shared members
  try {
    const shares = await api(`/api/kml-folders/${folderId}/shares`);
    shareKmlSharedWith = shares.map(s => s.shared_with_user_id);
    renderShareKmlMembers(shares);
  } catch (err) {
    shareKmlSharedWith = [];
    document.getElementById('share-kml-members').innerHTML = '<p style="color:#999;">共有メンバーはいません</p>';
  }

  // Show/hide owner controls
  const ownerControls = document.getElementById('share-kml-owner-controls');
  const saveBtn = document.getElementById('share-kml-save-btn');
  const title = document.getElementById('share-kml-title');

  if (isOwner) {
    ownerControls.style.display = '';
    saveBtn.style.display = '';
    title.textContent = 'KMLフォルダを共有';
    document.getElementById('share-kml-search').value = '';
    renderShareKmlUserList('');
  } else {
    ownerControls.style.display = 'none';
    saveBtn.style.display = 'none';
    title.textContent = '共有メンバー確認';
  }

  openModal('modal-share-kml');
}

function renderShareKmlMembers(shares) {
  const container = document.getElementById('share-kml-members');
  if (!shares || shares.length === 0) {
    container.innerHTML = '<p style="color:#999;margin:0;">共有メンバーはいません</p>';
    return;
  }

  container.innerHTML = shares.map(s => `
    <div style="display:flex;align-items:center;padding:4px 0;">
      <i class="fas fa-user" style="color:#666;margin-right:8px;"></i>
      <span>${escHtml(s.display_name || s.username)}</span>
    </div>
  `).join('');
}

function filterShareKmlUsers() {
  const query = document.getElementById('share-kml-search').value.toLowerCase();
  renderShareKmlUserList(query);
}

function renderShareKmlUserList(query) {
  const listEl = document.getElementById('share-kml-user-list');

  // Get currently checked user IDs from UI (if modal is already open)
  const checkedIds = new Set(shareKmlSharedWith);
  listEl.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
    checkedIds.add(parseInt(cb.value));
  });
  listEl.querySelectorAll('input[type="checkbox"]:not(:checked)').forEach(cb => {
    checkedIds.delete(parseInt(cb.value));
  });

  let html = '';
  for (const user of allUsers) {
    // Skip admins
    if (user.is_admin) continue;

    const isChecked = checkedIds.has(user.id);
    const displayName = user.display_name || user.username;
    const matchesSearch = query && displayName.toLowerCase().includes(query);

    // Show checked users OR users matching search (search required for non-checked)
    if (isChecked || matchesSearch) {
      const checked = isChecked ? 'checked' : '';
      html += `<div class="user-select-item ${checked ? 'selected' : ''}" onclick="toggleUserSelect(this, event)">
        <input type="checkbox" value="${user.id}" ${checked}>
        <span>${escHtml(displayName)}</span>
      </div>`;
    }
  }
  listEl.innerHTML = html || '<p style="padding:8px;color:#999;">ユーザー名を入力して検索してください</p>';
}

function toggleUserSelect(el, event) {
  // Allow click anywhere on the row to toggle, including the checkbox itself
  const cb = el.querySelector('input[type="checkbox"]');
  // If clicking on the checkbox, it already toggles, so only toggle for other clicks
  if (event && event.target === cb) {
    el.classList.toggle('selected', cb.checked);
  } else {
    cb.checked = !cb.checked;
    el.classList.toggle('selected', cb.checked);
  }
}

async function shareKmlFolder() {
  const folderId = document.getElementById('share-kml-folder-id').value;
  const checkboxes = document.querySelectorAll('#share-kml-user-list input[type="checkbox"]:checked');
  const userIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

  try {
    await api(`/api/kml-folders/${folderId}/share`, {
      method: 'POST',
      body: JSON.stringify({ user_ids: userIds })
    });
    closeModal('modal-share-kml');
    notify('共有設定を更新しました');
    await loadKmlFolders();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

// ==================== Account Settings ====================
function showAccountSettings() {
  document.getElementById('settings-display-name').value = currentUser.display_name || currentUser.username;
  document.getElementById('settings-current-password').value = '';
  document.getElementById('settings-new-password').value = '';
  document.getElementById('settings-confirm-password').value = '';
  document.getElementById('settings-error').style.display = 'none';
  openModal('modal-settings');
  // Update push notification UI
  updatePushUI();
  // Update install UI
  updateInstallUI();
  // Load plan information
  loadPlanInfo();
  // Load passkeys
  loadPasskeys();
}

async function saveAccountSettings() {
  const displayName = document.getElementById('settings-display-name').value.trim();
  const currentPassword = document.getElementById('settings-current-password').value;
  const newPassword = document.getElementById('settings-new-password').value;
  const confirmPassword = document.getElementById('settings-confirm-password').value;
  const errEl = document.getElementById('settings-error');

  // Validate password change if attempting
  if (newPassword || confirmPassword) {
    if (!currentPassword) {
      errEl.textContent = '現在のパスワードを入力してください';
      errEl.style.display = 'block';
      return;
    }
    if (newPassword.length < 12) {
      errEl.textContent = '新しいパスワードは12文字以上にしてください';
      errEl.style.display = 'block';
      return;
    }
    if (newPassword !== confirmPassword) {
      errEl.textContent = '新しいパスワードが一致しません';
      errEl.style.display = 'block';
      return;
    }
  }

  try {
    // Update display name
    if (displayName && displayName !== currentUser.display_name) {
      await api('/api/auth/profile', {
        method: 'PUT',
        body: JSON.stringify({ display_name: displayName })
      });
      currentUser.display_name = displayName;
    }

    // Update password if provided
    if (newPassword) {
      await api('/api/auth/password', {
        method: 'PUT',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword
        })
      });
    }

    closeModal('modal-settings');
    notify('設定を保存しました');
    renderSidebar();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.style.display = 'block';
  }
}

// ==================== Plan Management ====================
async function loadPlanInfo() {
  const loadingEl = document.getElementById('plan-loading');
  const infoEl = document.getElementById('plan-info');
  const badgeEl = document.getElementById('plan-badge');
  const sourceEl = document.getElementById('plan-source');
  const actionsEl = document.getElementById('plan-actions');
  const endsAtEl = document.getElementById('plan-ends-at');

  loadingEl.style.display = 'block';
  infoEl.style.display = 'none';

  try {
    const data = await api('/api/subscription');

    loadingEl.style.display = 'none';
    infoEl.style.display = 'block';

    // Set badge
    if (data.plan === 'premium') {
      badgeEl.textContent = 'プレミアム';
      badgeEl.style.background = '#28a745';
      badgeEl.style.color = 'white';
    } else {
      badgeEl.textContent = '無料プラン';
      badgeEl.style.background = '#6c757d';
      badgeEl.style.color = 'white';
    }

    // Set source info
    if (data.member_source === 'wordpress') {
      sourceEl.textContent = '（WordPress経由）';
    } else if (data.member_source === 'stripe') {
      sourceEl.textContent = '（アプリ内課金）';
    } else {
      sourceEl.textContent = '';
    }

    // Set actions based on plan and source
    actionsEl.innerHTML = '';

    if (data.plan === 'free') {
      // Free user - show upgrade button (only if Stripe is configured)
      if (data.stripe_enabled) {
        actionsEl.innerHTML = `
          <button class="btn btn-sm btn-primary" onclick="upgradeToPremium()">
            <i class="fas fa-crown"></i> プレミアムへ
          </button>
        `;
      } else {
        actionsEl.innerHTML = `
          <span style="font-size:11px;color:#666;">アプリ内課金は準備中です</span>
        `;
      }
    } else if (data.managed_by === 'stripe') {
      // Stripe managed - show manage button
      actionsEl.innerHTML = `
        <button class="btn btn-sm btn-secondary" onclick="openStripePortal()">
          <i class="fas fa-cog"></i> 管理
        </button>
      `;
    } else if (data.managed_by === 'wordpress') {
      // WordPress managed - show info
      actionsEl.innerHTML = `
        <span style="font-size:11px;color:#666;">WordPress側で管理</span>
      `;
    }

    // Show subscription end date if canceling
    if (data.subscription_ends_at) {
      const endsDate = new Date(data.subscription_ends_at);
      endsAtEl.textContent = `※ ${endsDate.toLocaleDateString('ja-JP')} にプレミアムが終了します`;
      endsAtEl.style.display = 'block';
    } else {
      endsAtEl.style.display = 'none';
    }

  } catch (err) {
    console.error('Failed to load plan info:', err);
    loadingEl.style.display = 'none';
    infoEl.style.display = 'block';
    badgeEl.textContent = '無料プラン';
    badgeEl.style.background = '#6c757d';
    badgeEl.style.color = 'white';
    sourceEl.textContent = '';
    actionsEl.innerHTML = `
      <span style="font-size:11px;color:#999;">読み込みに失敗しました</span>
    `;
  }
}

async function upgradeToPremium() {
  try {
    const data = await api('/api/stripe/create-checkout-session', {
      method: 'POST',
      body: JSON.stringify({
        success_url: window.location.origin + '?upgrade=success',
        cancel_url: window.location.origin
      })
    });

    if (data.url) {
      window.location.href = data.url;
    } else {
      notify('チェックアウトセッションの作成に失敗しました', 'error');
    }
  } catch (err) {
    notify(err.message, 'error');
  }
}

async function openStripePortal() {
  // Prompt for password verification
  const password = prompt('セキュリティ確認のため、パスワードを入力してください');
  if (!password) {
    return;
  }

  try {
    const data = await api('/api/stripe/create-portal-session', {
      method: 'POST',
      body: JSON.stringify({ password })
    });

    if (data.url) {
      window.location.href = data.url;
    } else {
      notify('ポータルセッションの作成に失敗しました', 'error');
    }
  } catch (err) {
    notify(err.message, 'error');
  }
}

async function cancelSubscription() {
  if (!confirm('本当にプレミアムを解約しますか？\n現在の請求期間終了までは引き続きご利用いただけます。')) {
    return;
  }

  try {
    const data = await api('/api/subscription/cancel', {
      method: 'POST'
    });

    notify(data.message);
    loadPlanInfo();
  } catch (err) {
    notify(err.message, 'error');
  }
}

// ==================== Usage Data ====================
async function loadUsageData() {
  if (!currentUser) {
    userUsageData = null;
    return;
  }
  try {
    userUsageData = await api('/api/usage');
  } catch (err) {
    console.error('Failed to load usage data:', err);
    userUsageData = null;
  }
}

// ==================== Admin Panel ====================
async function loadPendingUsers() {
  if (!currentUser || !currentUser.is_admin) {
    pendingUsersCount = 0;
    return;
  }
  try {
    const users = await api('/api/admin/pending-users');
    pendingUsersCount = users.length;
  } catch (err) {
    console.error('Failed to load pending users:', err);
    pendingUsersCount = 0;
  }
}

async function showAdminPanel() {
  if (!currentUser || !currentUser.is_admin) return;

  const listEl = document.getElementById('admin-pending-users');
  listEl.innerHTML = '<p style="color:#999;">読み込み中...</p>';
  openModal('modal-admin');

  try {
    const users = await api('/api/admin/pending-users');
    if (users.length === 0) {
      listEl.innerHTML = '<p style="color:#999;">承認待ちのユーザーはいません</p>';
    } else {
      listEl.innerHTML = users.map(u => `
        <div class="pending-user-item" data-user-id="${u.id}">
          <div class="pending-user-info">
            <strong>${escHtml(u.display_name || u.username)}</strong>
            <span style="color:#666;font-size:12px;">@${escHtml(u.username)}</span>
            <span style="color:#999;font-size:11px;">${new Date(u.created_at).toLocaleString('ja-JP')}</span>
          </div>
          <div class="pending-user-actions">
            <button class="btn btn-sm btn-primary" onclick="approveUser(${u.id})">
              <i class="fas fa-check"></i> 承認
            </button>
            <button class="btn btn-sm btn-danger" onclick="rejectUser(${u.id})">
              <i class="fas fa-times"></i> 拒否
            </button>
          </div>
        </div>
      `).join('');
    }
    pendingUsersCount = users.length;
    renderSidebar(); // Update badge
  } catch (err) {
    listEl.innerHTML = `<p style="color:#dc3545;">読み込みエラー: ${err.message}</p>`;
  }
}

async function approveUser(userId) {
  try {
    const result = await api(`/api/admin/users/${userId}/approve`, { method: 'POST' });
    notify(result.message);
    // Remove from list
    document.querySelector(`.pending-user-item[data-user-id="${userId}"]`)?.remove();
    pendingUsersCount = Math.max(0, pendingUsersCount - 1);
    renderSidebar();
    // Check if list is empty
    const listEl = document.getElementById('admin-pending-users');
    if (!listEl.querySelector('.pending-user-item')) {
      listEl.innerHTML = '<p style="color:#999;">承認待ちのユーザーはいません</p>';
    }
  } catch (err) {
    notify(err.message, 'error');
  }
}

async function rejectUser(userId) {
  if (!confirm('このユーザーの申請を拒否しますか？')) return;
  try {
    const result = await api(`/api/admin/users/${userId}/reject`, { method: 'POST' });
    notify(result.message);
    // Remove from list
    document.querySelector(`.pending-user-item[data-user-id="${userId}"]`)?.remove();
    pendingUsersCount = Math.max(0, pendingUsersCount - 1);
    renderSidebar();
    // Check if list is empty
    const listEl = document.getElementById('admin-pending-users');
    if (!listEl.querySelector('.pending-user-item')) {
      listEl.innerHTML = '<p style="color:#999;">承認待ちのユーザーはいません</p>';
    }
  } catch (err) {
    notify(err.message, 'error');
  }
}

function switchAdminTab(tab) {
  document.querySelectorAll('#modal-admin .tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`#modal-admin .tab:nth-child(${tab === 'users' ? 1 : 2})`).classList.add('active');
  document.getElementById('admin-tab-users').style.display = tab === 'users' ? '' : 'none';
  document.getElementById('admin-tab-security').style.display = tab === 'security' ? '' : 'none';
  if (tab === 'security') loadSecurityLogs();
}

async function loadSecurityLogs() {
  const listEl = document.getElementById('admin-security-logs');
  const filter = document.getElementById('security-log-filter').value;
  listEl.innerHTML = '<p style="color:#999;">読み込み中...</p>';

  try {
    const url = filter ? `/api/admin/security-logs?type=${filter}` : '/api/admin/security-logs';
    const logs = await api(url);
    if (logs.length === 0) {
      listEl.innerHTML = '<p style="color:#999;">ログがありません</p>';
    } else {
      listEl.innerHTML = logs.map(log => {
        const date = new Date(log.created_at).toLocaleString('ja-JP');
        const eventLabels = {
          'login_success': '<span style="color:#28a745;">ログイン成功</span>',
          'login_failed': '<span style="color:#dc3545;">ログイン失敗</span>',
          'rate_limit_exceeded': '<span style="color:#fd7e14;">レート制限</span>',
          'register_duplicate_username': '<span style="color:#6c757d;">重複ユーザー名</span>'
        };
        const details = log.details ? JSON.parse(log.details) : {};
        return `<div class="security-log-item">
          <div style="display:flex;justify-content:space-between;margin-bottom:2px;">
            ${eventLabels[log.event_type] || log.event_type}
            <span style="color:#999;">${date}</span>
          </div>
          <div style="color:#666;">
            IP: ${log.ip_address || 'N/A'}
            ${details.username ? ` | User: ${escHtml(details.username)}` : ''}
            ${details.reason ? ` | Reason: ${details.reason}` : ''}
          </div>
        </div>`;
      }).join('');
    }
  } catch (err) {
    listEl.innerHTML = `<p style="color:#dc3545;">読み込みエラー: ${err.message}</p>`;
  }
}

// ==================== Pin Folder Management ====================
function renderPinFolderList() {
  // Group pins by folder
  const folderPins = {};
  const noFolderPins = [];

  for (const pin of pins) {
    if (currentUser && (pin.user_id === currentUser.id || currentUser.is_admin ||
        (pin.folder_id && folders.find(f => f.id === pin.folder_id && !f.is_owner)))) {
      if (pin.folder_id) {
        if (!folderPins[pin.folder_id]) folderPins[pin.folder_id] = [];
        folderPins[pin.folder_id].push(pin);
      } else {
        noFolderPins.push(pin);
      }
    }
  }

  let html = '';

  // "すべて" folder for pins without folder
  if (noFolderPins.length > 0) {
    html += `<div class="pin-folder-section">
      <div class="folder-name-row">すべて <span class="folder-count">(${noFolderPins.length})</span></div>
      <div class="pin-folder-header" onclick="togglePinFolder('all')">
        <i class="fas fa-chevron-right toggle-icon"></i>
        <i class="fas fa-folder folder-icon"></i>
      </div>
      <div class="pin-folder-content" id="pin-folder-all">
        ${noFolderPins.map(p => renderPinItem(p)).join('')}
      </div>
    </div>`;
  }

  // Render folders hierarchically - only top-level folders
  const topFolders = folders.filter(f => !f.parent_id);
  for (const folder of topFolders) {
    html += renderFolderNode(folder, folderPins, 0);
  }

  if (html === '') {
    return '<p style="font-size:13px;color:#999;">フォルダがありません</p>';
  }
  return html;
}

function renderFolderNode(folder, folderPins, depth) {
  const pinsInFolder = folderPins[folder.id] || [];
  const childFolders = folders.filter(f => f.parent_id === folder.id);
  const isOwner = folder.is_owner;
  const isVisible = folder.is_visible;
  const visBadge = getVisibilityBadge(folder.is_public, folder.is_shared);
  const totalCount = pinsInFolder.length + childFolders.length;

  let html = `<div class="pin-folder-section" style="margin-left:${depth * 12}px;" data-folder-id="${folder.id}">
    <div class="folder-name-row">${escHtml(folder.name)} ${visBadge} <span class="folder-count">(${totalCount})</span></div>
    <div class="pin-folder-header" onclick="togglePinFolder(${folder.id})">
      <i class="fas fa-chevron-right toggle-icon"></i>
      <i class="fas fa-folder folder-icon"></i>
      <div class="folder-actions" onclick="event.stopPropagation()">
        <button onclick="toggleFolderVisibilityBtn(${folder.id})" title="表示切替" class="icon-btn ${isVisible ? 'active' : ''}"><i class="fas fa-eye"></i></button>
        ${isOwner ? `<button onclick="showRenameFolderModal(${folder.id})" title="名前変更" class="icon-btn"><i class="fas fa-edit"></i></button>
        <button onclick="showMoveFolderModal(${folder.id})" title="移動" class="icon-btn"><i class="fas fa-arrows-alt"></i></button>` : ''}
        ${(isOwner || folder.is_shared) ? `<button onclick="showShareFolderModal(${folder.id})" title="${isOwner ? '共有' : 'メンバー確認'}" class="icon-btn"><i class="fas fa-share-alt"></i></button>` : ''}
        ${isOwner ? `
        <button onclick="deleteFolder(${folder.id})" title="削除" class="icon-btn delete"><i class="fas fa-trash"></i></button>` : ''}
      </div>
    </div>
    <div class="pin-folder-content" id="pin-folder-${folder.id}">`;

  // Render child folders first
  for (const child of childFolders) {
    html += renderFolderNode(child, folderPins, 0);
  }

  // Then render pins
  if (pinsInFolder.length > 0) {
    html += pinsInFolder.map(p => renderPinItem(p)).join('');
  } else if (childFolders.length === 0) {
    html += '<p style="font-size:12px;color:#999;padding:4px;">ピンがありません</p>';
  }

  html += '</div></div>';
  return html;
}

function togglePinFolder(folderId) {
  const header = event.target.closest('.pin-folder-header');
  const content = document.getElementById(`pin-folder-${folderId}`);
  if (header && content) {
    header.classList.toggle('expanded');
    content.classList.toggle('open');
  }
}

async function toggleFolderVisibility(folderId, visible) {
  if (!currentUser) return;
  try {
    await api(`/api/folders/${folderId}/visibility`, {
      method: 'POST',
      body: JSON.stringify({ is_visible: visible })
    });
    // Update local state
    const folder = folders.find(f => f.id === folderId);
    if (folder) folder.is_visible = visible ? 1 : 0;
    // Update pin markers
    updatePinMarkers();
  } catch (err) {
    notify(err.message, 'error');
  }
}

async function toggleFolderVisibilityBtn(folderId) {
  const folder = folders.find(f => f.id === folderId);
  if (!folder) return;

  const newVisible = !folder.is_visible;

  // Update icon immediately
  const btn = document.querySelector(`.pin-folder-section[data-folder-id="${folderId}"] .icon-btn[title="表示切替"]`);
  if (btn) {
    btn.classList.toggle('active', newVisible);
  }

  await toggleFolderVisibility(folderId, newVisible);
}

function updatePinMarkers() {
  // Remove all pin markers
  Object.values(pinMarkers).forEach(m => map.removeLayer(m));
  pinMarkers = {};

  // Add visible pins based on folder visibility
  for (const pin of pins) {
    // Check if pin's folder is visible (or pin has no folder)
    let isVisible = true;
    if (pin.folder_id) {
      const folder = folders.find(f => f.id === pin.folder_id);
      if (folder && !folder.is_visible) {
        isVisible = false;
      }
    }
    if (isVisible) {
      addPinMarker(pin);
    }
  }
}

function addPinMarker(pin) {
  const isOwn = currentUser && pin.user_id === currentUser.id;
  const color = isOwn ? '#1a73e8' : '#e53935';
  const icon = L.divIcon({
    className: '',
    html: `<div style="
      background:${color};width:28px;height:28px;border-radius:50% 50% 50% 0;
      transform:rotate(-45deg);border:2px solid white;
      box-shadow:0 2px 6px rgba(0,0,0,0.3);display:flex;align-items:center;justify-content:center;
    "><i class="fas fa-map-pin" style="color:white;font-size:12px;transform:rotate(45deg);"></i></div>`,
    iconSize: [28, 28],
    iconAnchor: [14, 28],
    popupAnchor: [0, -28]
  });

  const marker = L.marker([pin.lat, pin.lng], { icon }).addTo(map);
  marker.bindPopup(() => createPinPopup(pin));
  pinMarkers[pin.id] = marker;
}

function renderPinItem(pin) {
  const visBadge = getVisibilityBadge(pin.is_public, pin.is_shared);
  const canEdit = currentUser && (pin.user_id === currentUser.id || currentUser.is_admin);
  const dateStr = pin.created_at ? pin.created_at.split('T')[0] : '';
  return `<div class="pin-item" data-pin-id="${pin.id}">
    <div class="pin-item-header" onclick="focusPin(${pin.id})">
      <h4>${escHtml(pin.title)} ${visBadge}</h4>
      <p>${escHtml(pin.description || '').substring(0, 60)}</p>
    </div>
    <div class="pin-meta">
      <span><i class="fas fa-user"></i> ${escHtml(pin.author || '')}</span>
      <span><i class="fas fa-calendar"></i> ${dateStr}</span>
      ${pin.images && pin.images.length > 0 ? '<span><i class="fas fa-image"></i> ' + pin.images.length + '</span>' : ''}
      ${canEdit ? `<button onclick="event.stopPropagation(); showMovePinModal(${pin.id})" title="移動" class="icon-btn" style="margin-left:auto;"><i class="fas fa-arrows-alt"></i></button>` : ''}
    </div>
  </div>`;
}

function showFolderModal() {
  document.getElementById('folder-name').value = '';
  populateFolderSelect('folder-parent', null, true);
  openModal('modal-folder');
}

async function createFolder() {
  const name = document.getElementById('folder-name').value.trim();
  if (!name) { notify('フォルダ名を入力してください', 'error'); return; }

  try {
    await api('/api/folders', {
      method: 'POST',
      body: JSON.stringify({
        name,
        parent_id: document.getElementById('folder-parent').value || null
      })
    });
    closeModal('modal-folder');
    notify('フォルダを作成しました');
    await loadFolders();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

async function deleteFolder(folderId) {
  const folder = folders.find(f => f.id === folderId);
  if (!folder) return;
  const pinsInFolder = pins.filter(p => p.folder_id === folderId);
  const hasShares = folder.shared_with;

  let msg = 'このフォルダを削除しますか？\n\n';
  if (pinsInFolder.length > 0) {
    msg += `⚠️ 内包している ${pinsInFolder.length} 件のピンも全て削除されます。\n`;
  }
  if (hasShares) {
    msg += '⚠️ 共有中のユーザーからも削除されます。\n';
  }
  msg += '\nこの操作は取り消せません。';

  if (!confirm(msg)) return;
  try {
    await api('/api/folders/' + folderId, { method: 'DELETE' });
    notify('フォルダを削除しました');
    await loadFolders();
    await loadPins();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

function showRenameFolderModal(folderId) {
  const folder = folders.find(f => f.id === folderId);
  if (!folder) return;
  document.getElementById('rename-folder-id').value = folderId;
  document.getElementById('rename-folder-name').value = folder.name;
  document.getElementById('rename-folder-public').checked = !!folder.is_public;
  document.getElementById('rename-folder-public').parentElement.style.display = currentUser?.is_admin ? '' : 'none';
  openModal('modal-rename-folder');
}

async function renameFolder() {
  const folderId = document.getElementById('rename-folder-id').value;
  const name = document.getElementById('rename-folder-name').value.trim();
  if (!name) { notify('フォルダ名を入力してください', 'error'); return; }

  try {
    await api(`/api/folders/${folderId}`, {
      method: 'PUT',
      body: JSON.stringify({
        name,
        is_public: document.getElementById('rename-folder-public').checked
      })
    });
    closeModal('modal-rename-folder');
    notify('フォルダ設定を変更しました');
    loadFolders();
  } catch (err) { notify(err.message, 'error'); }
}

let shareFolderSharedWith = [];

async function showShareFolderModal(folderId) {
  document.getElementById('share-folder-id').value = folderId;
  const folder = folders.find(f => f.id === folderId);
  const isOwner = folder?.is_owner || (currentUser && currentUser.is_admin);

  // Clear previous state to prevent checkbox states from carrying over between folders
  shareFolderSharedWith = [];
  document.getElementById('share-folder-user-list').innerHTML = '';

  // Fetch shared members
  try {
    const shares = await api(`/api/folders/${folderId}/shares`);
    shareFolderSharedWith = shares.map(s => s.shared_with_user_id);
    renderShareFolderMembers(shares);
  } catch (err) {
    shareFolderSharedWith = [];
    document.getElementById('share-folder-members').innerHTML = '<p style="color:#999;">共有メンバーはいません</p>';
  }

  // Show/hide owner controls
  const ownerControls = document.getElementById('share-folder-owner-controls');
  const saveBtn = document.getElementById('share-folder-save-btn');
  const title = document.getElementById('share-folder-title');

  if (isOwner) {
    ownerControls.style.display = '';
    saveBtn.style.display = '';
    title.textContent = 'ピンフォルダを共有';
    document.getElementById('share-folder-search').value = '';
    renderShareFolderUserList('');
  } else {
    ownerControls.style.display = 'none';
    saveBtn.style.display = 'none';
    title.textContent = '共有メンバー確認';
  }

  openModal('modal-share-folder');
}

function renderShareFolderMembers(shares) {
  const container = document.getElementById('share-folder-members');
  if (!shares || shares.length === 0) {
    container.innerHTML = '<p style="color:#999;margin:0;">共有メンバーはいません</p>';
    return;
  }

  container.innerHTML = shares.map(s => `
    <div style="display:flex;align-items:center;padding:4px 0;">
      <i class="fas fa-user" style="color:#666;margin-right:8px;"></i>
      <span>${escHtml(s.display_name || s.username)}</span>
    </div>
  `).join('');
}

function filterShareFolderUsers() {
  const query = document.getElementById('share-folder-search').value.toLowerCase();
  renderShareFolderUserList(query);
}

function renderShareFolderUserList(query) {
  const listEl = document.getElementById('share-folder-user-list');

  // Get currently checked user IDs from UI (if modal is already open)
  const checkedIds = new Set(shareFolderSharedWith);
  listEl.querySelectorAll('input[type="checkbox"]:checked').forEach(cb => {
    checkedIds.add(parseInt(cb.value));
  });
  listEl.querySelectorAll('input[type="checkbox"]:not(:checked)').forEach(cb => {
    checkedIds.delete(parseInt(cb.value));
  });

  let html = '';
  for (const user of allUsers) {
    // Skip admins
    if (user.is_admin) continue;

    const isChecked = checkedIds.has(user.id);
    const displayName = user.display_name || user.username;
    const matchesSearch = query && displayName.toLowerCase().includes(query);

    // Show checked users OR users matching search (search required for non-checked)
    if (isChecked || matchesSearch) {
      const checked = isChecked ? 'checked' : '';
      html += `<div class="user-select-item ${checked ? 'selected' : ''}" onclick="toggleUserSelect(this, event)">
        <input type="checkbox" value="${user.id}" ${checked}>
        <span>${escHtml(displayName)}</span>
      </div>`;
    }
  }
  listEl.innerHTML = html || '<p style="padding:8px;color:#999;">ユーザー名を入力して検索してください</p>';
}

async function shareFolder() {
  const folderId = document.getElementById('share-folder-id').value;
  const checkboxes = document.querySelectorAll('#share-folder-user-list input[type="checkbox"]:checked');
  const userIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

  try {
    await api(`/api/folders/${folderId}/share`, {
      method: 'POST',
      body: JSON.stringify({ user_ids: userIds })
    });
    closeModal('modal-share-folder');
    notify('共有設定を更新しました');
    await loadFolders();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

// Move folder to another parent
function showMoveFolderModal(folderId) {
  document.getElementById('move-folder-id').value = folderId;
  const folder = folders.find(f => f.id === folderId);
  document.getElementById('move-folder-name').textContent = folder ? folder.name : '';

  // Populate folder select excluding self and children
  const sel = document.getElementById('move-folder-target');
  sel.innerHTML = '<option value="">-- ルート（最上位）--</option>';

  function addOptions(parentId, depth) {
    const children = folders.filter(f => (f.parent_id || null) === parentId && f.is_owner);
    for (const f of children) {
      // Exclude self and check for circular reference
      if (f.id === folderId) continue;
      // Check if f is a descendant of folderId (prevent circular)
      let isDescendant = false;
      let current = f;
      while (current && current.parent_id) {
        if (current.parent_id === folderId) { isDescendant = true; break; }
        current = folders.find(p => p.id === current.parent_id);
      }
      if (isDescendant) continue;

      const opt = document.createElement('option');
      opt.value = f.id;
      opt.textContent = '\u00A0\u00A0'.repeat(depth) + f.name;
      if (f.id === folder?.parent_id) opt.selected = true;
      sel.appendChild(opt);
      addOptions(f.id, depth + 1);
    }
  }
  addOptions(null, 0);
  openModal('modal-move-folder');
}

async function moveFolder() {
  const folderId = document.getElementById('move-folder-id').value;
  const targetId = document.getElementById('move-folder-target').value || null;

  try {
    await api(`/api/folders/${folderId}/move`, {
      method: 'POST',
      body: JSON.stringify({ parent_id: targetId ? parseInt(targetId) : null })
    });
    closeModal('modal-move-folder');
    notify('フォルダを移動しました');
    loadFolders();
  } catch (err) { notify(err.message, 'error'); }
}

// Move pin to another folder
function showMovePinModal(pinId) {
  document.getElementById('move-pin-id').value = pinId;
  const pin = pins.find(p => p.id === pinId);
  document.getElementById('move-pin-name').textContent = pin ? pin.title : '';
  populateFolderSelect('move-pin-target', pin?.folder_id);
  openModal('modal-move-pin');
}

async function movePin() {
  const pinId = document.getElementById('move-pin-id').value;
  const targetId = document.getElementById('move-pin-target').value || null;

  try {
    await api(`/api/pins/${pinId}/move`, {
      method: 'POST',
      body: JSON.stringify({ folder_id: targetId ? parseInt(targetId) : null })
    });
    closeModal('modal-move-pin');
    notify('ピンを移動しました');
    loadPins();
  } catch (err) { notify(err.message, 'error'); }
}

// Move KML file to another folder
function showMoveKmlFileModal(fileId) {
  document.getElementById('move-kml-file-id').value = fileId;
  const file = kmlFiles.find(f => f.id === fileId);
  document.getElementById('move-kml-file-name').textContent = file ? file.original_name : '';

  // Populate KML folder select
  const sel = document.getElementById('move-kml-file-target');
  sel.innerHTML = '';
  for (const f of kmlFolders) {
    if (!f.is_owner) continue;
    const opt = document.createElement('option');
    opt.value = f.id;
    opt.textContent = f.name;
    if (f.id === file?.folder_id) opt.selected = true;
    sel.appendChild(opt);
  }
  openModal('modal-move-kml-file');
}

async function moveKmlFile() {
  const fileId = document.getElementById('move-kml-file-id').value;
  const targetId = document.getElementById('move-kml-file-target').value;

  if (!targetId) {
    notify('移動先フォルダを選択してください', 'error');
    return;
  }

  try {
    await api(`/api/kml-files/${fileId}/move`, {
      method: 'POST',
      body: JSON.stringify({ folder_id: parseInt(targetId) })
    });
    closeModal('modal-move-kml-file');
    notify('KMLファイルを移動しました');
    loadKmlFolders();
  } catch (err) { notify(err.message, 'error'); }
}

function populateFolderSelect(selectId, selectedId, includeNone) {
  const sel = document.getElementById(selectId);
  sel.innerHTML = '<option value="">-- なし --</option>';

  // First add owned folders
  function addOptions(parentId, depth, filterFn) {
    const children = folders.filter(f => (f.parent_id || null) === parentId && filterFn(f));
    for (const f of children) {
      const opt = document.createElement('option');
      opt.value = f.id;
      const prefix = f.is_owner ? '' : '📁 ';
      opt.textContent = '\u00A0\u00A0'.repeat(depth) + prefix + f.name;
      if (f.id == selectedId) opt.selected = true;
      sel.appendChild(opt);
      addOptions(f.id, depth + 1, filterFn);
    }
  }

  // Add owned folders first
  addOptions(null, 0, f => f.is_owner);

  // Add shared/public folders (not owned)
  const sharedFolders = folders.filter(f => !f.is_owner && !f.parent_id);
  if (sharedFolders.length > 0) {
    const divider = document.createElement('option');
    divider.disabled = true;
    divider.textContent = '── 共有フォルダ ──';
    sel.appendChild(divider);
    addOptions(null, 0, f => !f.is_owner);
  }
}

// ==================== Pins ====================
async function loadPins() {
  try {
    pins = await api('/api/pins');
    renderPinMarkers();
    renderSidebar();
  } catch (err) {
    console.error('Pin load error:', err);
    notify('ピンの読み込みに失敗しました', 'error');
  }
}

function renderPinMarkers() {
  updatePinMarkers();
}

function createPinPopup(pin) {
  const div = document.createElement('div');
  div.style.cssText = 'max-width:280px;';
  const visBadge = getVisibilityBadge(pin.is_public, pin.is_shared);
  const dateStr = pin.created_at ? pin.created_at.split('T')[0] : '';
  let html = `<h4 style="margin:0 0 4px;">${escHtml(pin.title)} ${visBadge}</h4>`;
  html += `<p style="font-size:12px;color:#666;margin:0 0 4px;">${escHtml(pin.description || '')}</p>`;
  html += `<p style="font-size:11px;color:#999;">作成者: ${escHtml(pin.author || '')} | ${dateStr}</p>`;

  if (pin.images && pin.images.length > 0) {
    html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:6px;">';
    for (const img of pin.images) {
      const key = img.r2_key.replace('images/', '');
      html += `<img src="/api/images/${key}" style="width:60px;height:60px;object-fit:cover;border-radius:4px;cursor:pointer;" onclick="openLightbox('/api/images/${key}')">`;
    }
    html += '</div>';
  }

  const canEdit = currentUser && (pin.user_id === currentUser.id || currentUser.is_admin);
  if (canEdit) {
    html += `<div style="margin-top:8px;display:flex;gap:6px;">
      <button class="btn btn-sm btn-primary" onclick="editPin(${pin.id})"><i class="fas fa-edit"></i> 編集</button>
      <button class="btn btn-sm btn-danger" onclick="deletePin(${pin.id})"><i class="fas fa-trash"></i> 削除</button>
    </div>`;
  }

  // Comments section
  html += `<div style="margin-top:10px;border-top:1px solid #eee;padding-top:8px;">
    <div style="font-size:12px;font-weight:bold;margin-bottom:6px;"><i class="fas fa-comments"></i> コメント</div>
    <div id="pin-comments-${pin.id}" style="max-height:120px;overflow-y:auto;font-size:11px;">
      <div style="color:#999;">読み込み中...</div>
    </div>`;

  if (currentUser) {
    html += `<div style="margin-top:6px;display:flex;gap:4px;">
      <input type="text" id="comment-input-${pin.id}" maxlength="50" placeholder="コメント（50文字以内）" style="flex:1;font-size:11px;padding:4px 6px;border:1px solid #ddd;border-radius:4px;">
      <button class="btn btn-sm btn-primary" onclick="addPinComment(${pin.id})" style="padding:4px 8px;"><i class="fas fa-paper-plane"></i></button>
    </div>`;
  }
  html += '</div>';

  div.innerHTML = html;

  // Load comments after popup is created
  setTimeout(() => loadPinComments(pin.id), 100);

  return div;
}

async function loadPinComments(pinId) {
  const container = document.getElementById(`pin-comments-${pinId}`);
  if (!container) return;

  try {
    const res = await fetch(`/api/pins/${pinId}/comments`, { credentials: 'include' });
    if (!res.ok) throw new Error('Failed to load comments');
    const comments = await res.json();

    if (comments.length === 0) {
      container.innerHTML = '<div style="color:#999;">コメントはありません</div>';
      return;
    }

    container.innerHTML = comments.map(c => {
      const canDelete = currentUser && (c.user_id === currentUser.id || currentUser.is_admin);
      const dateStr = c.created_at ? c.created_at.split('T')[0] : '';
      return `<div style="margin-bottom:6px;padding:4px;background:#f8f9fa;border-radius:4px;">
        <div style="display:flex;justify-content:space-between;align-items:start;">
          <div style="flex:1;">
            <span style="font-weight:bold;color:#333;">${escHtml(c.author_name)}</span>
            <span style="color:#999;margin-left:4px;">${dateStr}</span>
          </div>
          ${canDelete ? `<button onclick="deletePinComment(${pinId}, ${c.id})" style="background:none;border:none;color:#dc3545;cursor:pointer;padding:0 2px;font-size:10px;"><i class="fas fa-times"></i></button>` : ''}
        </div>
        <div style="color:#555;margin-top:2px;">${escHtml(c.content)}</div>
      </div>`;
    }).join('');
  } catch (err) {
    container.innerHTML = '<div style="color:#dc3545;">読み込みエラー</div>';
  }
}

async function addPinComment(pinId) {
  const input = document.getElementById(`comment-input-${pinId}`);
  if (!input) return;

  const content = input.value.trim();
  if (!content) {
    notify('コメントを入力してください', 'error');
    return;
  }
  if (content.length > 50) {
    notify('コメントは50文字以内で入力してください', 'error');
    return;
  }

  try {
    const res = await fetch(`/api/pins/${pinId}/comments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ content })
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Failed to add comment');
    }

    input.value = '';
    loadPinComments(pinId);
  } catch (err) {
    notify(err.message, 'error');
  }
}

async function deletePinComment(pinId, commentId) {
  if (!confirm('このコメントを削除しますか？')) return;

  try {
    const res = await fetch(`/api/pins/${pinId}/comments/${commentId}`, {
      method: 'DELETE',
      credentials: 'include'
    });

    if (!res.ok) {
      const data = await res.json();
      throw new Error(data.error || 'Failed to delete comment');
    }

    loadPinComments(pinId);
  } catch (err) {
    notify(err.message, 'error');
  }
}

// ==================== Push Notifications ====================
async function initPushNotifications() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    console.log('Push notifications not supported');
    return;
  }

  try {
    // Register service worker
    const registration = await navigator.serviceWorker.register('/sw.js');
    console.log('Service Worker registered');

    // Check current subscription
    pushSubscription = await registration.pushManager.getSubscription();
    updatePushUI();

    // Listen for messages from service worker
    navigator.serviceWorker.addEventListener('message', (event) => {
      if (event.data?.type === 'push-received') {
        // New push notification received - refresh notification count
        console.log('Push received, refreshing notifications');
        checkUnreadComments();
      } else if (event.data?.type === 'notification-click') {
        // User clicked notification - handle navigation
        const data = event.data?.data;
        if (data?.type && data?.id) {
          zoomToNotification(data.type, data.id);
        }
      }
    });
  } catch (err) {
    console.error('Service Worker registration failed:', err);
  }
}

async function subscribeToPush() {
  try {
    // Get VAPID public key
    const res = await fetch('/api/push/vapid-key');
    if (!res.ok) {
      notify('プッシュ通知は現在利用できません', 'error');
      return;
    }
    const { vapidPublicKey } = await res.json();

    const registration = await navigator.serviceWorker.ready;

    // Request permission
    const permission = await Notification.requestPermission();
    if (permission !== 'granted') {
      notify('通知の許可が必要です', 'error');
      return;
    }

    // Subscribe
    pushSubscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(vapidPublicKey)
    });

    // Send subscription to server
    await fetch('/api/push/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ subscription: pushSubscription.toJSON() })
    });

    notify('プッシュ通知を有効にしました');
    updatePushUI();
  } catch (err) {
    console.error('Failed to subscribe:', err);
    notify('プッシュ通知の設定に失敗しました', 'error');
  }
}

async function unsubscribeFromPush() {
  try {
    if (pushSubscription) {
      const endpoint = pushSubscription.endpoint;
      await pushSubscription.unsubscribe();

      await fetch('/api/push/unsubscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ endpoint })
      });

      pushSubscription = null;
      notify('プッシュ通知を無効にしました');
      updatePushUI();
    }
  } catch (err) {
    console.error('Failed to unsubscribe:', err);
    notify('設定の解除に失敗しました', 'error');
  }
}

function updatePushUI() {
  const btn = document.getElementById('settings-push-btn');
  const status = document.getElementById('settings-push-status');
  const container = document.getElementById('settings-push-container');

  // Check if push is supported
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    if (status) status.textContent = 'このブラウザは対応していません';
    if (btn) btn.style.display = 'none';
    return;
  }

  const testBtn = document.getElementById('settings-push-test');

  if (btn) {
    if (pushSubscription) {
      btn.innerHTML = '<i class="fas fa-bell-slash"></i> OFF';
      btn.classList.remove('btn-primary');
      btn.classList.add('btn-secondary');
    } else {
      btn.innerHTML = '<i class="fas fa-bell"></i> ON';
      btn.classList.remove('btn-secondary');
      btn.classList.add('btn-primary');
    }
  }

  if (testBtn) {
    testBtn.style.display = pushSubscription ? 'inline-block' : 'none';
  }

  if (status) {
    status.textContent = pushSubscription ? '通知ON' : '通知OFF';
  }
}

function togglePushNotifications() {
  if (pushSubscription) {
    unsubscribeFromPush();
  } else {
    subscribeToPush();
  }
}

async function testPushNotification() {
  const resultEl = document.getElementById('settings-push-result');
  resultEl.style.display = 'block';
  resultEl.style.color = '#666';
  resultEl.textContent = 'テスト送信中...';

  try {
    const res = await fetch('/api/push/test', {
      method: 'POST',
      credentials: 'include'
    });
    const data = await res.json();

    if (res.ok) {
      resultEl.style.color = '#28a745';
      resultEl.innerHTML = '✓ 送信成功！通知が届くか確認してください<br><small>Steps: ' + (data.debug?.steps?.length || 0) + '</small>';
    } else {
      resultEl.style.color = '#dc3545';
      const steps = data.debug?.steps?.join('<br>') || '';
      resultEl.innerHTML = `✗ エラー: ${data.error || data.message}<br><small style="white-space:pre-wrap;">${steps}</small>`;
    }
  } catch (err) {
    resultEl.style.color = '#dc3545';
    resultEl.textContent = '✗ 通信エラー: ' + err.message;
  }
}

// ==================== App Install ====================
function initInstallPrompt() {
  // Capture the install prompt event
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    console.log('Install prompt captured');
  });

  // Detect when app is installed
  window.addEventListener('appinstalled', () => {
    deferredInstallPrompt = null;
    console.log('App installed');
  });
}

function updateInstallUI() {
  const availableEl = document.getElementById('install-available');
  const iosEl = document.getElementById('install-ios');
  const installedEl = document.getElementById('install-installed');

  if (!availableEl || !iosEl || !installedEl) return;

  // Hide all first
  availableEl.style.display = 'none';
  iosEl.style.display = 'none';
  installedEl.style.display = 'none';

  // Check if already installed (standalone mode)
  const isStandalone = window.matchMedia('(display-mode: standalone)').matches ||
                       window.navigator.standalone === true;

  if (isStandalone) {
    installedEl.style.display = 'block';
    return;
  }

  // Check if iOS
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
  if (isIOS) {
    iosEl.style.display = 'block';
    return;
  }

  // Check if install prompt is available
  if (deferredInstallPrompt) {
    availableEl.style.display = 'block';
  } else {
    // Not installable or already installed
    installedEl.style.display = 'block';
  }
}

async function installApp() {
  if (!deferredInstallPrompt) {
    notify('インストールプロンプトが利用できません', 'error');
    return;
  }

  deferredInstallPrompt.prompt();
  const { outcome } = await deferredInstallPrompt.userChoice;

  if (outcome === 'accepted') {
    notify('アプリをインストールしました！');
    deferredInstallPrompt = null;
    updateInstallUI();
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

// ==================== Comment Notifications ====================
let unreadComments = [];

async function checkUnreadComments() {
  if (!currentUser) return;

  try {
    const res = await fetch('/api/comments/unread', { credentials: 'include' });
    if (!res.ok) return;

    unreadComments = await res.json();
    updateNotificationBadge();
  } catch (err) {
    console.error('Failed to check notifications:', err);
  }
}

function updateNotificationBadge() {
  const badge = document.getElementById('notification-badge');
  const btn = document.getElementById('btn-notifications');
  if (!badge || !btn) return;

  const count = unreadComments.length;

  if (count > 0) {
    badge.textContent = count > 99 ? '99+' : count;
    badge.style.display = 'block';
    // Set app badge on home screen icon
    if ('setAppBadge' in navigator) {
      navigator.setAppBadge(count).catch(() => {});
    }
  } else {
    badge.style.display = 'none';
    // Clear app badge
    if ('clearAppBadge' in navigator) {
      navigator.clearAppBadge().catch(() => {});
    }
  }
}

async function openNotificationsPopup() {
  const list = document.getElementById('notifications-list');
  if (!list) return;

  openModal('modal-notifications');

  if (unreadComments.length === 0) {
    list.innerHTML = '<div style="color:#999;text-align:center;padding:20px;">新着通知はありません</div>';
    return;
  }

  list.innerHTML = unreadComments.map(item => {
    const dateStr = item.created_at ? item.created_at.replace('T', ' ').substring(0, 16) : '';

    if (item.type === 'comment') {
      return `<div onclick="zoomToNotification('pin', ${item.lat}, ${item.lng}, ${item.pin_id})" style="padding:10px;border-bottom:1px solid #eee;cursor:pointer;transition:background 0.2s;" onmouseover="this.style.background='#f5f5f5'" onmouseout="this.style.background='transparent'">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-weight:bold;color:#17a2b8;"><i class="fas fa-comment"></i> コメント</span>
          <span style="font-size:11px;color:#999;">${dateStr}</span>
        </div>
        <div style="font-size:12px;color:#333;margin-bottom:4px;">
          <i class="fas fa-map-pin" style="color:#007bff;"></i> ${escHtml(item.pin_title)}
        </div>
        <div style="font-size:12px;color:#666;margin-bottom:4px;">
          <span style="font-weight:bold;">${escHtml(item.author_name)}</span>: ${escHtml(item.content)}
        </div>
        <div style="font-size:11px;color:#999;">
          <i class="fas fa-folder"></i> ${escHtml(item.folder_name || '未分類')}
        </div>
      </div>`;
    } else if (item.type === 'pin') {
      return `<div onclick="zoomToNotification('pin', ${item.lat}, ${item.lng}, ${item.pin_id})" style="padding:10px;border-bottom:1px solid #eee;cursor:pointer;transition:background 0.2s;" onmouseover="this.style.background='#f5f5f5'" onmouseout="this.style.background='transparent'">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-weight:bold;color:#28a745;"><i class="fas fa-map-pin"></i> 新規ピン</span>
          <span style="font-size:11px;color:#999;">${dateStr}</span>
        </div>
        <div style="font-size:12px;color:#333;margin-bottom:4px;">
          ${escHtml(item.pin_title)}
        </div>
        <div style="font-size:12px;color:#666;margin-bottom:4px;">
          <span style="font-weight:bold;">${escHtml(item.author_name)}</span>${item.content ? ': ' + escHtml(item.content.substring(0, 50)) : ''}
        </div>
        <div style="font-size:11px;color:#999;">
          <i class="fas fa-folder"></i> ${escHtml(item.folder_name || '未分類')}
        </div>
      </div>`;
    } else if (item.type === 'kml') {
      return `<div onclick="zoomToNotification('kml', 0, 0, ${item.kml_id})" style="padding:10px;border-bottom:1px solid #eee;cursor:pointer;transition:background 0.2s;" onmouseover="this.style.background='#f5f5f5'" onmouseout="this.style.background='transparent'">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-weight:bold;color:#fd7e14;"><i class="fas fa-file"></i> 新規KML</span>
          <span style="font-size:11px;color:#999;">${dateStr}</span>
        </div>
        <div style="font-size:12px;color:#333;margin-bottom:4px;">
          ${escHtml(item.title)}
        </div>
        <div style="font-size:12px;color:#666;margin-bottom:4px;">
          <span style="font-weight:bold;">${escHtml(item.author_name)}</span>
        </div>
        <div style="font-size:11px;color:#999;">
          <i class="fas fa-folder"></i> ${escHtml(item.folder_name || '未分類')}
        </div>
      </div>`;
    }
    return '';
  }).join('');
}

async function closeNotificationsPopup() {
  closeModal('modal-notifications');

  // Mark all comments as read
  if (unreadComments.length > 0) {
    try {
      await fetch('/api/comments/mark-read', {
        method: 'POST',
        credentials: 'include'
      });
      unreadComments = [];
      updateNotificationBadge();
    } catch (err) {
      console.error('Failed to mark comments as read:', err);
    }
  }
}

function zoomToCommentPin(lat, lng, pinId) {
  zoomToNotification('pin', lat, lng, pinId);
}

function zoomToNotification(type, lat, lng, id) {
  closeModal('modal-notifications');

  if (type === 'pin') {
    map.setView([lat, lng], 16);
    // Open the pin popup if marker exists
    if (pinMarkers[id]) {
      setTimeout(() => {
        pinMarkers[id].openPopup();
      }, 300);
    }
  } else if (type === 'kml') {
    // Zoom to KML file bounds
    const kmlLayer = kmlLayers[id];
    if (kmlLayer) {
      try {
        const bounds = kmlLayer.getBounds();
        if (bounds.isValid()) {
          map.fitBounds(bounds, { padding: [50, 50] });
        }
      } catch (e) {
        console.error('Failed to zoom to KML:', e);
      }
    } else {
      // If layer not visible, try to load and zoom
      const file = kmlFiles.find(f => f.id === id);
      if (file) {
        focusKmlFile(id);
      }
    }
  }
}

function startPinMode() {
  if (!currentUser) { showAuthModal(); return; }
  pinMode = true;
  document.getElementById('btn-add-pin').classList.add('active');
  map.getContainer().style.cursor = 'crosshair';
  document.body.classList.add('pin-mode-active');
  notify('地図をクリックしてピンを配置してください');
}

function cancelPinMode() {
  pinMode = false;
  pendingPinLatLng = null;
  document.getElementById('btn-add-pin').classList.remove('active');
  map.getContainer().style.cursor = '';
  document.body.classList.remove('pin-mode-active');
  closeModal('modal-pin');
}

// Compress image to target size (default 1MB)
async function compressImage(file, maxSizeKB = 1000, maxWidth = 1920, maxHeight = 1920) {
  return new Promise((resolve) => {
    // If already small enough and is JPEG, return as-is
    if (file.size <= maxSizeKB * 1024 && file.type === 'image/jpeg') {
      resolve(file);
      return;
    }

    const img = new Image();
    img.onload = () => {
      let width = img.width;
      let height = img.height;

      // Scale down if larger than max dimensions
      if (width > maxWidth || height > maxHeight) {
        const ratio = Math.min(maxWidth / width, maxHeight / height);
        width = Math.round(width * ratio);
        height = Math.round(height * ratio);
      }

      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;

      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);

      // Try different quality levels to get under target size
      let quality = 0.9;
      const tryCompress = () => {
        canvas.toBlob((blob) => {
          if (blob.size > maxSizeKB * 1024 && quality > 0.1) {
            quality -= 0.1;
            tryCompress();
          } else {
            const compressedFile = new File([blob], file.name.replace(/\.[^.]+$/, '.jpg'), {
              type: 'image/jpeg',
              lastModified: Date.now()
            });
            console.log(`Compressed: ${(file.size/1024).toFixed(0)}KB -> ${(compressedFile.size/1024).toFixed(0)}KB`);
            resolve(compressedFile);
          }
        }, 'image/jpeg', quality);
      };
      tryCompress();
    };

    img.onerror = () => resolve(file); // Fallback to original
    img.src = URL.createObjectURL(file);
  });
}

// Compress multiple images
async function compressImages(files) {
  const compressed = [];
  for (const file of files) {
    if (file.type.startsWith('image/')) {
      compressed.push(await compressImage(file));
    } else {
      compressed.push(file);
    }
  }
  return compressed;
}

function previewPinImages(input) {
  const container = document.getElementById('pin-image-preview');
  container.innerHTML = '';
  for (const file of input.files) {
    const img = document.createElement('img');
    img.className = 'image-preview';
    img.src = URL.createObjectURL(file);
    container.appendChild(img);
  }
}

async function savePin() {
  const title = document.getElementById('pin-title').value.trim();
  if (!title) { notify('タイトルを入力してください', 'error'); return; }

  const imageInput = document.getElementById('pin-images');
  const hasImages = imageInput.files && imageInput.files.length > 0;

  try {
    let pin;
    if (hasImages) {
      // Compress images before upload
      notify('画像を圧縮中...', 'info');
      const compressedImages = await compressImages(imageInput.files);

      // Use FormData for multipart upload
      const formData = new FormData();
      formData.append('title', title);
      formData.append('description', document.getElementById('pin-desc').value.trim());
      formData.append('lat', pendingPinLatLng.lat);
      formData.append('lng', pendingPinLatLng.lng);
      formData.append('folder_id', document.getElementById('pin-folder').value || '');
      for (const file of compressedImages) {
        formData.append('images', file);
      }
      pin = await apiFormData('/api/pins', formData);
    } else {
      // JSON request
      pin = await api('/api/pins', {
        method: 'POST',
        body: JSON.stringify({
          title,
          description: document.getElementById('pin-desc').value.trim(),
          lat: pendingPinLatLng.lat,
          lng: pendingPinLatLng.lng,
          folder_id: document.getElementById('pin-folder').value || null
        })
      });
    }
    cancelPinMode();
    notify('ピンを作成しました');
    await loadPins();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

function focusPin(pinId) {
  const pin = pins.find(p => p.id === pinId);
  if (!pin) return;
  map.setView([pin.lat, pin.lng], 16);
  if (pinMarkers[pinId]) pinMarkers[pinId].openPopup();
  if (window.innerWidth <= 600) toggleSidebar();
}

async function editPin(pinId) {
  editingPinId = pinId;
  const pin = pins.find(p => p.id === pinId);
  if (!pin) return;

  map.closePopup();
  document.getElementById('edit-pin-title').value = pin.title;
  document.getElementById('edit-pin-desc').value = pin.description || '';
  document.getElementById('edit-pin-images').value = '';
  populateFolderSelect('edit-pin-folder', pin.folder_id);

  // Show current images
  const imgContainer = document.getElementById('edit-pin-current-images');
  imgContainer.innerHTML = '';
  if (pin.images) {
    for (const img of pin.images) {
      const key = img.r2_key.replace('images/', '');
      const wrapper = document.createElement('div');
      wrapper.className = 'img-wrapper';
      wrapper.innerHTML = `
        <img src="/api/images/${key}" onclick="openLightbox('/api/images/${key}')">
        <button class="img-delete" onclick="removePinImage(${pin.id}, ${img.id}, this)" title="削除">&times;</button>
      `;
      imgContainer.appendChild(wrapper);
    }
  }

  openModal('modal-pin-edit');
}

function closeEditPin() {
  editingPinId = null;
  closeModal('modal-pin-edit');
}

async function updatePin() {
  if (!editingPinId) return;
  try {
    await api('/api/pins/' + editingPinId, {
      method: 'PUT',
      body: JSON.stringify({
        title: document.getElementById('edit-pin-title').value.trim(),
        description: document.getElementById('edit-pin-desc').value.trim(),
        folder_id: document.getElementById('edit-pin-folder').value || null
      })
    });

    // Upload new images (compressed)
    const imageInput = document.getElementById('edit-pin-images');
    if (imageInput.files && imageInput.files.length > 0) {
      notify('画像を圧縮中...', 'info');
      const compressedImages = await compressImages(imageInput.files);
      const formData = new FormData();
      for (const f of compressedImages) formData.append('images', f);
      await apiFormData('/api/pins/' + editingPinId + '/images', formData);
    }

    closeEditPin();
    notify('ピンを更新しました');
    loadPins();
  } catch (err) { notify(err.message, 'error'); }
}

async function deletePin(pinId) {
  if (!confirm('このピンを削除しますか？')) return;
  try {
    await api('/api/pins/' + pinId, { method: 'DELETE' });
    notify('ピンを削除しました');
    await loadPins();
    await loadUsageData();
    renderSidebar();
  } catch (err) { notify(err.message, 'error'); }
}

async function removePinImage(pinId, imageId, btn) {
  if (!confirm('この画像を削除しますか？')) return;
  try {
    await api(`/api/pins/${pinId}/images/${imageId}`, { method: 'DELETE' });
    btn.parentElement.remove();
    loadPins();
  } catch (err) { notify(err.message, 'error'); }
}

// ==================== Geolocation ====================
function zoomToMyLocation() {
  if (!navigator.geolocation) { notify('位置情報が利用できません', 'error'); return; }
  navigator.geolocation.getCurrentPosition(
    (pos) => {
      const { latitude: lat, longitude: lng, accuracy } = pos.coords;
      updateMyLocation(lat, lng, accuracy);
      map.setView([lat, lng], 16);
    },
    (err) => { notify('位置情報の取得に失敗しました: ' + err.message, 'error'); },
    { enableHighAccuracy: true }
  );
}

function startWatchingLocation() {
  if (!navigator.geolocation) return;
  watchId = navigator.geolocation.watchPosition(
    (pos) => {
      const { latitude: lat, longitude: lng, accuracy } = pos.coords;
      updateMyLocation(lat, lng, accuracy);
    },
    () => {},
    { enableHighAccuracy: true, maximumAge: 10000 }
  );
}

function updateMyLocation(lat, lng, accuracy) {
  if (myLocationMarker) {
    myLocationMarker.setLatLng([lat, lng]);
    myLocationCircle.setLatLng([lat, lng]).setRadius(accuracy);
  } else {
    myLocationMarker = L.circleMarker([lat, lng], {
      radius: 8, fillColor: '#4285f4', fillOpacity: 1,
      color: 'white', weight: 3
    }).addTo(map).bindPopup('現在地');
    myLocationCircle = L.circle([lat, lng], {
      radius: accuracy, color: '#4285f4', fillColor: '#4285f4',
      fillOpacity: 0.1, weight: 1
    }).addTo(map);
  }
}

// ==================== Lightbox ====================
function openLightbox(src) {
  document.getElementById('lightbox-img').src = src;
  document.getElementById('lightbox').classList.add('active');
}

function closeLightbox() {
  document.getElementById('lightbox').classList.remove('active');
}

// ==================== Data Loading ====================
async function loadKmlFolders() {
  try {
    kmlFolders = await api('/api/kml-folders');
    kmlFiles = await api('/api/kml-files');
    updateKmlLayers();
    renderSidebar();
  } catch (err) {
    console.error('KML folder load error:', err);
    notify('KMLフォルダの読み込みに失敗しました', 'error');
  }
}

async function loadFolders() {
  if (!currentUser) { folders = []; return; }
  try {
    folders = await api('/api/folders');
    renderSidebar();
  } catch (err) {
    console.error('Folder load error:', err);
    notify('フォルダの読み込みに失敗しました', 'error');
  }
}

async function loadAll() {
  await Promise.all([loadUsers(), loadKmlFolders(), loadPins(), loadFolders(), loadPendingUsers(), loadUsageData()]);
}

// ==================== Service Worker ====================
function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js')
      .then((registration) => {
        console.log('Service Worker registered:', registration.scope);
      })
      .catch((err) => {
        console.log('Service Worker registration failed:', err);
      });
  }
}

async function clearTileCache() {
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    return new Promise((resolve) => {
      const messageChannel = new MessageChannel();
      messageChannel.port1.onmessage = (event) => {
        resolve(event.data.success);
      };
      navigator.serviceWorker.controller.postMessage(
        { action: 'clearTileCache' },
        [messageChannel.port2]
      );
    });
  }
  return false;
}

async function getTileCacheCount() {
  if ('serviceWorker' in navigator && navigator.serviceWorker.controller) {
    return new Promise((resolve) => {
      const messageChannel = new MessageChannel();
      messageChannel.port1.onmessage = (event) => {
        resolve(event.data.count);
      };
      navigator.serviceWorker.controller.postMessage(
        { action: 'getCacheSize' },
        [messageChannel.port2]
      );
    });
  }
  return 0;
}

// ==================== Passkeys (WebAuthn) ====================

// Check if WebAuthn is supported
function isPasskeySupported() {
  return window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential === 'function';
}

// Initialize passkey UI
function initPasskeyUI() {
  const loginBtn = document.getElementById('passkey-login-btn');
  const unsupported = document.getElementById('passkey-unsupported');
  const content = document.getElementById('passkey-content');
  const supported = isPasskeySupported();

  console.log('Passkey support:', supported, 'Login button found:', !!loginBtn);

  if (supported) {
    if (loginBtn) loginBtn.style.display = 'block';
    if (unsupported) unsupported.style.display = 'none';
    if (content) content.style.display = 'block';
  } else {
    if (loginBtn) loginBtn.style.display = 'none';
    if (unsupported) unsupported.style.display = 'block';
    if (content) content.style.display = 'none';
  }
}

// Ensure passkey UI is initialized when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initPasskeyUI);
} else {
  // DOM is already ready, but init() will call initPasskeyUI() later
}

// Base64URL encode/decode utilities
function base64urlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Register a new passkey
async function registerPasskey() {
  if (!isPasskeySupported()) {
    alert('このブラウザはパスキーに対応していません');
    return;
  }

  try {
    // Get device name
    const deviceName = prompt('このパスキーの名前を入力してください（例: iPhone, MacBook）', getDeviceName());
    if (deviceName === null) return;

    // Get registration options from server
    const options = await api('/api/auth/passkey/register/options', { method: 'POST' });

    // Convert options for WebAuthn API
    const publicKeyOptions = {
      challenge: base64urlDecode(options.challenge),
      rp: options.rp,
      user: {
        id: base64urlDecode(options.user.id),
        name: options.user.name,
        displayName: options.user.displayName
      },
      pubKeyCredParams: options.pubKeyCredParams,
      timeout: options.timeout,
      authenticatorSelection: options.authenticatorSelection,
      attestation: options.attestation,
      excludeCredentials: options.excludeCredentials.map(c => ({
        id: base64urlDecode(c.id),
        type: c.type
      }))
    };

    // Create credential
    const credential = await navigator.credentials.create({
      publicKey: publicKeyOptions
    });

    // Send credential to server for verification
    const response = await api('/api/auth/passkey/register/verify', {
      method: 'POST',
      body: JSON.stringify({
        credential: {
          id: credential.id,
          rawId: base64urlEncode(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
            attestationObject: base64urlEncode(credential.response.attestationObject)
          }
        },
        deviceName: deviceName || 'Unknown Device'
      })
    });

    alert('パスキーを登録しました');
    loadPasskeys();
  } catch (err) {
    console.error('Passkey registration error:', err);
    if (err.name === 'NotAllowedError') {
      alert('パスキーの登録がキャンセルされました');
    } else {
      alert('パスキーの登録に失敗しました: ' + (err.message || err));
    }
  }
}

// Get a friendly device name
function getDeviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Mac/.test(ua)) return 'Mac';
  if (/Android/.test(ua)) return 'Android';
  if (/Windows/.test(ua)) return 'Windows PC';
  return 'Unknown Device';
}

// Login with passkey
async function loginWithPasskey() {
  if (!isPasskeySupported()) {
    alert('このブラウザはパスキーに対応していません');
    return;
  }

  try {
    // Get login options from server
    const options = await api('/api/auth/passkey/login/options', { method: 'POST' });

    // Convert options for WebAuthn API
    const publicKeyOptions = {
      challenge: base64urlDecode(options.challenge),
      rpId: options.rpId,
      timeout: options.timeout,
      userVerification: options.userVerification,
      allowCredentials: options.allowCredentials.map(c => ({
        id: base64urlDecode(c.id),
        type: c.type
      }))
    };

    // Get credential
    const credential = await navigator.credentials.get({
      publicKey: publicKeyOptions
    });

    // Send credential to server for verification
    const result = await api('/api/auth/passkey/login/verify', {
      method: 'POST',
      body: JSON.stringify({
        credential: {
          id: credential.id,
          rawId: base64urlEncode(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: base64urlEncode(credential.response.clientDataJSON),
            authenticatorData: base64urlEncode(credential.response.authenticatorData),
            signature: base64urlEncode(credential.response.signature),
            userHandle: credential.response.userHandle ? base64urlEncode(credential.response.userHandle) : null
          }
        }
      })
    });

    currentUser = result;
    closeModal('modal-auth');
    await loadAll();
  } catch (err) {
    console.error('Passkey login error:', err);
    if (err.name === 'NotAllowedError') {
      alert('パスキーによるログインがキャンセルされました');
    } else {
      alert('パスキーによるログインに失敗しました: ' + (err.message || err));
    }
  }
}

// Load user's passkeys
async function loadPasskeys() {
  const container = document.getElementById('passkey-list');
  if (!container) return;

  if (!currentUser) {
    container.innerHTML = '';
    return;
  }

  try {
    const passkeys = await api('/api/auth/passkeys');

    if (passkeys.length === 0) {
      container.innerHTML = '<div style="color:#666;font-size:13px;">パスキーが登録されていません</div>';
    } else {
      container.innerHTML = passkeys.map(pk => `
        <div style="display:flex;align-items:center;justify-content:space-between;padding:8px;background:#f5f5f5;border-radius:4px;margin-bottom:4px;">
          <div>
            <i class="fas fa-key" style="color:#4CAF50;margin-right:8px;"></i>
            <span style="font-size:13px;">${escHtml(pk.device_name)}</span>
            <span style="color:#999;font-size:11px;margin-left:8px;">${new Date(pk.created_at).toLocaleDateString('ja-JP')}</span>
          </div>
          <button class="btn btn-sm btn-danger" onclick="deletePasskey(${pk.id})" title="削除">
            <i class="fas fa-trash"></i>
          </button>
        </div>
      `).join('');
    }
  } catch (err) {
    console.error('Load passkeys error:', err);
    container.innerHTML = '<div style="color:#dc3545;font-size:13px;">読み込みエラー</div>';
  }
}

// Delete a passkey
async function deletePasskey(id) {
  if (!confirm('このパスキーを削除しますか？')) return;

  try {
    await api(`/api/auth/passkey/${id}`, { method: 'DELETE' });
    loadPasskeys();
  } catch (err) {
    alert('パスキーの削除に失敗しました: ' + (err.message || err));
  }
}

// ==================== Prevent Leaflet Pointer Event Interference ====================
// Leaflet adds document-level pointer event listeners with capture:true
// This prevents them from interfering with form inputs in login screen and modals
function preventLeafletFormInterference() {
  const stopPropagationForForms = (e) => {
    const target = e.target;
    // Protect login screen forms
    const loginScreen = document.getElementById('login-screen');
    if (loginScreen && !loginScreen.classList.contains('hidden') &&
        loginScreen.contains(target)) {
      e.stopPropagation();
      return;
    }
    // Protect modal forms (they have class 'modal-overlay active')
    const activeModal = target.closest('.modal-overlay.active');
    if (activeModal) {
      e.stopPropagation();
      return;
    }
  };

  // Add listeners on window in capture phase (fires before document)
  ['pointerdown', 'pointermove', 'pointerup', 'pointercancel',
   'touchstart', 'touchmove', 'touchend', 'touchcancel',
   'mousedown', 'mousemove', 'mouseup'].forEach(eventType => {
    window.addEventListener(eventType, stopPropagationForForms, true);
  });
}

// ==================== Init ====================
async function init() {
  preventLeafletFormInterference();
  registerServiceWorker();
  initInstallPrompt();
  initPasskeyUI();
  checkPasswordSetup();
  await checkAuth();
  await loadAll();
  startWatchingLocation();
  initPushNotifications();
}

init();
