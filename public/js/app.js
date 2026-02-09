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

// ==================== Map Init ====================
const map = L.map('map', {
  center: [35.0, 135.0],
  zoom: 6,
  zoomControl: false
});

L.control.zoom({ position: 'bottomright' }).addTo(map);

// GSI Tiles
const gsiStd = L.tileLayer('https://cyberjapandata.gsi.go.jp/xyz/std/{z}/{x}/{y}.png', {
  attribution: '<a href="https://maps.gsi.go.jp/development/ichiran.html">国土地理院</a>',
  maxZoom: 18
});
const gsiPhoto = L.tileLayer('https://cyberjapandata.gsi.go.jp/xyz/seamlessphoto/{z}/{x}/{y}.jpg', {
  attribution: '<a href="https://maps.gsi.go.jp/development/ichiran.html">国土地理院</a>',
  maxZoom: 18
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
  document.getElementById('pin-public').checked = false;
  document.getElementById('pin-public').parentElement.style.display = currentUser?.is_admin ? '' : 'none';
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

// ==================== Auth ====================
async function checkAuth() {
  try {
    currentUser = await api('/api/auth/me');
    updateUI();
  } catch { currentUser = null; updateUI(); }
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
    currentUser = await api(endpoint, { method: 'POST', body: JSON.stringify(body) });
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
  notify('ログアウトしました');
  updateUI();
  loadAll();
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
    html += `<div class="user-info">
      <i class="fas fa-user"></i> <span>${escHtml(currentUser.display_name || currentUser.username)}</span>
      ${currentUser.is_admin ? ' <span class="badge badge-public">管理者</span>' : ''}
      <div style="float:right;display:flex;gap:4px;">
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
  const sharedBadge = folder.shared_with ? '<span class="badge badge-shared">共有</span>' : '';
  const publicBadge = folder.is_public ? '<span class="badge badge-public">公開</span>' : '';
  const totalCount = files.length + childFolders.length;

  let html = `<div class="kml-folder-item" style="margin-left:${depth * 12}px;" data-folder-id="${folder.id}">
    <div class="folder-name-row">${escHtml(folder.name)} ${publicBadge}${sharedBadge} <span class="folder-count">(${totalCount})</span></div>
    <div class="kml-folder-header" onclick="toggleKmlFolder(${folder.id})">
      <i class="fas fa-chevron-right toggle-icon"></i>
      <i class="fas fa-folder folder-icon"></i>
      <div class="kml-folder-actions" onclick="event.stopPropagation()">
        <button onclick="toggleKmlFolderVisibilityBtn(${folder.id})" title="表示切替" class="icon-btn ${isVisible ? 'active' : ''}"><i class="fas fa-eye"></i></button>
        ${isOwner ? `<button onclick="showRenameKmlFolderModal(${folder.id})" title="名前変更" class="icon-btn"><i class="fas fa-edit"></i></button>
        <button onclick="showMoveKmlFolderModal(${folder.id})" title="移動" class="icon-btn"><i class="fas fa-arrows-alt"></i></button>
        <button onclick="showKmlUploadModal(${folder.id})" title="追加" class="icon-btn"><i class="fas fa-plus"></i></button>
        <button onclick="showShareKmlFolderModal(${folder.id})" title="共有" class="icon-btn"><i class="fas fa-share-alt"></i></button>
        <button onclick="deleteKmlFolder(${folder.id})" title="削除" class="icon-btn delete"><i class="fas fa-trash"></i></button>` : ''}
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
    loadKmlFolders();
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
    loadKmlFolders();
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
  document.getElementById('kml-upload-public').checked = false;
  document.getElementById('kml-upload-public').parentElement.style.display = currentUser?.is_admin ? '' : 'none';
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
  formData.append('is_public', document.getElementById('kml-upload-public').checked);

  try {
    await apiFormData('/api/kml-files/upload', formData);
    closeModal('modal-kml-upload');
    notify('KMLをアップロードしました');
    loadKmlFolders();
  } catch (err) { notify(err.message, 'error'); }
}

async function deleteKmlFile(fileId) {
  if (!confirm('このKMLファイルを削除しますか？')) return;
  try {
    await api(`/api/kml-files/${fileId}`, { method: 'DELETE' });
    notify('KMLを削除しました');
    loadKmlFolders();
  } catch (err) { notify(err.message, 'error'); }
}

let shareKmlSharedWith = [];

function showShareKmlFolderModal(folderId) {
  document.getElementById('share-kml-folder-id').value = folderId;
  const folder = kmlFolders.find(f => f.id === folderId);
  shareKmlSharedWith = folder?.shared_with ? folder.shared_with.split(',').map(Number) : [];

  document.getElementById('share-kml-search').value = '';
  renderShareKmlUserList('');
  openModal('modal-share-kml');
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
    loadKmlFolders();
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
    if (newPassword.length < 4) {
      errEl.textContent = '新しいパスワードは4文字以上にしてください';
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
  const sharedBadge = folder.shared_with ? '<span class="badge badge-shared">共有</span>' : '';
  const publicBadge = folder.is_public ? '<span class="badge badge-public">公開</span>' : '';
  const totalCount = pinsInFolder.length + childFolders.length;

  let html = `<div class="pin-folder-section" style="margin-left:${depth * 12}px;" data-folder-id="${folder.id}">
    <div class="folder-name-row">${escHtml(folder.name)} ${publicBadge}${sharedBadge} <span class="folder-count">(${totalCount})</span></div>
    <div class="pin-folder-header" onclick="togglePinFolder(${folder.id})">
      <i class="fas fa-chevron-right toggle-icon"></i>
      <i class="fas fa-folder folder-icon"></i>
      <div class="folder-actions" onclick="event.stopPropagation()">
        <button onclick="toggleFolderVisibilityBtn(${folder.id})" title="表示切替" class="icon-btn ${isVisible ? 'active' : ''}"><i class="fas fa-eye"></i></button>
        ${isOwner ? `<button onclick="showRenameFolderModal(${folder.id})" title="名前変更" class="icon-btn"><i class="fas fa-edit"></i></button>
        <button onclick="showMoveFolderModal(${folder.id})" title="移動" class="icon-btn"><i class="fas fa-arrows-alt"></i></button>
        <button onclick="showShareFolderModal(${folder.id})" title="共有" class="icon-btn"><i class="fas fa-share-alt"></i></button>
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
  const vis = pin.is_public ? '<span class="badge badge-public">公開</span>' : '<span class="badge badge-private">非公開</span>';
  const canEdit = currentUser && (pin.user_id === currentUser.id || currentUser.is_admin);
  return `<div class="pin-item" data-pin-id="${pin.id}">
    <div class="pin-item-header" onclick="focusPin(${pin.id})">
      <h4>${escHtml(pin.title)} ${vis}</h4>
      <p>${escHtml(pin.description || '').substring(0, 60)}</p>
    </div>
    <div class="pin-meta">
      <span><i class="fas fa-user"></i> ${escHtml(pin.author || '')}</span>
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
    loadFolders();
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
    loadFolders();
    loadPins();
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

function showShareFolderModal(folderId) {
  document.getElementById('share-folder-id').value = folderId;
  const folder = folders.find(f => f.id === folderId);
  shareFolderSharedWith = folder?.shared_with ? folder.shared_with.split(',').map(Number) : [];

  document.getElementById('share-folder-search').value = '';
  renderShareFolderUserList('');
  openModal('modal-share-folder');
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
    loadFolders();
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
  function addOptions(parentId, depth) {
    const children = folders.filter(f => (f.parent_id || null) === parentId && f.is_owner);
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
  div.style.cssText = 'max-width:250px;';
  const vis = pin.is_public ? '<span class="badge badge-public">公開</span>' : '<span class="badge badge-private">非公開</span>';
  let html = `<h4 style="margin:0 0 4px;">${escHtml(pin.title)} ${vis}</h4>`;
  html += `<p style="font-size:12px;color:#666;margin:0 0 4px;">${escHtml(pin.description || '')}</p>`;
  html += `<p style="font-size:11px;color:#999;">作成者: ${escHtml(pin.author || '')}</p>`;

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
  div.innerHTML = html;
  return div;
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
      // Use FormData for multipart upload
      const formData = new FormData();
      formData.append('title', title);
      formData.append('description', document.getElementById('pin-desc').value.trim());
      formData.append('lat', pendingPinLatLng.lat);
      formData.append('lng', pendingPinLatLng.lng);
      formData.append('folder_id', document.getElementById('pin-folder').value || '');
      formData.append('is_public', document.getElementById('pin-public').checked);
      for (const file of imageInput.files) {
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
          folder_id: document.getElementById('pin-folder').value || null,
          is_public: document.getElementById('pin-public').checked
        })
      });
    }
    cancelPinMode();
    notify('ピンを作成しました');
    loadPins();
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
  document.getElementById('edit-pin-public').checked = !!pin.is_public;
  document.getElementById('edit-pin-public').parentElement.style.display = currentUser?.is_admin ? '' : 'none';
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
        folder_id: document.getElementById('edit-pin-folder').value || null,
        is_public: document.getElementById('edit-pin-public').checked
      })
    });

    // Upload new images
    const imageInput = document.getElementById('edit-pin-images');
    if (imageInput.files && imageInput.files.length > 0) {
      const formData = new FormData();
      for (const f of imageInput.files) formData.append('images', f);
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
    loadPins();
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
  await Promise.all([loadUsers(), loadKmlFolders(), loadPins(), loadFolders()]);
}

// ==================== Init ====================
async function init() {
  await checkAuth();
  await loadAll();
  startWatchingLocation();
}

init();
