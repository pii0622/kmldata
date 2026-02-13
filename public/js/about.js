// Hero gallery auto-rotation (every 2 seconds)
document.addEventListener('DOMContentLoaded', function() {
  var images = document.querySelectorAll('.hero__gallery-img');
  if (images.length > 0) {
    var currentIndex = 0;
    setInterval(function() {
      images[currentIndex].classList.remove('active');
      currentIndex = (currentIndex + 1) % images.length;
      images[currentIndex].classList.add('active');
    }, 2000);
  }
});

// ==================== Upgrade Flow ====================

// Show upgrade modal
function showUpgradeModal() {
  var modal = document.getElementById('upgrade-modal');
  var checkbox = document.getElementById('agree-checkbox');

  // Reset state
  checkbox.checked = false;
  updateUpgradeButton();

  // Check login status
  checkLoginAndShowModal(modal);
}

// Check if user is logged in and show appropriate content
async function checkLoginAndShowModal(modal) {
  try {
    var response = await fetch('/api/auth/session', {
      credentials: 'include'
    });

    if (response.ok) {
      var data = await response.json();
      if (data.user) {
        // User is logged in - check if already premium
        if (data.user.plan === 'premium') {
          showModalContent(modal, 'already-premium');
        } else {
          showModalContent(modal, 'upgrade');
        }
      } else {
        showModalContent(modal, 'login-required');
      }
    } else {
      showModalContent(modal, 'login-required');
    }
  } catch (err) {
    console.error('Failed to check login status:', err);
    showModalContent(modal, 'login-required');
  }
}

// Show modal with appropriate content
function showModalContent(modal, type) {
  var modalInner = modal.querySelector('.upgrade-modal');

  if (type === 'login-required') {
    modalInner.innerHTML = '\
      <button class="upgrade-modal__close" onclick="closeUpgradeModal()" aria-label="閉じる">&times;</button>\
      <h3 class="upgrade-modal__title">ログインが必要です</h3>\
      <div class="upgrade-modal__login-prompt">\
        <p>プレミアムプランへのアップグレードには、ログインが必要です。</p>\
        <a href="/" class="upgrade-modal__login-btn">ログインする</a>\
      </div>\
    ';
  } else if (type === 'already-premium') {
    modalInner.innerHTML = '\
      <button class="upgrade-modal__close" onclick="closeUpgradeModal()" aria-label="閉じる">&times;</button>\
      <h3 class="upgrade-modal__title">プレミアムプラン</h3>\
      <div class="upgrade-modal__login-prompt">\
        <p>すでにプレミアムプランをご利用中です。</p>\
        <a href="/" class="upgrade-modal__login-btn">アプリに戻る</a>\
      </div>\
    ';
  }
  // 'upgrade' type uses the default HTML

  modal.classList.add('active');
  document.body.style.overflow = 'hidden';
}

// Close upgrade modal
function closeUpgradeModal() {
  var modal = document.getElementById('upgrade-modal');
  modal.classList.remove('active');
  document.body.style.overflow = '';

  // Reset modal content for next open
  resetModalContent();
}

// Reset modal to default content
function resetModalContent() {
  var modal = document.getElementById('upgrade-modal');
  var modalInner = modal.querySelector('.upgrade-modal');

  modalInner.innerHTML = '\
    <button class="upgrade-modal__close" onclick="closeUpgradeModal()" aria-label="閉じる">&times;</button>\
    <h3 class="upgrade-modal__title">プレミアムプランへのアップグレード</h3>\
    <div class="upgrade-modal__info">\
      <div class="upgrade-modal__price">\
        <span class="upgrade-modal__price-amount">¥200</span>\
        <span class="upgrade-modal__price-period">/ 月</span>\
      </div>\
      <p class="upgrade-modal__desc">ピン・フォルダ・KML・共有がすべて無制限になります</p>\
    </div>\
    <div class="upgrade-modal__terms">\
      <div class="upgrade-modal__terms-scroll">\
        <h4>利用規約（要約）</h4>\
        <ul>\
          <li>本サービスはフィールドワークや探索の情報記録・共有ツールです</li>\
          <li>現地での安全性・合法性は保証しません。自己責任で行動してください</li>\
          <li>投稿データの著作権はユーザーに帰属します</li>\
          <li>サービス内容は予告なく変更・停止する場合があります</li>\
        </ul>\
        <h4>プライバシーポリシー（要約）</h4>\
        <ul>\
          <li>アカウント情報、投稿データ、位置情報を取得します</li>\
          <li>サービス提供・改善・セキュリティ目的で利用します</li>\
          <li>法令に基づく場合を除き、第三者に提供しません</li>\
        </ul>\
        <p class="upgrade-modal__terms-link">\
          <a href="#terms" target="_blank">利用規約全文</a> / <a href="#privacy" target="_blank">プライバシーポリシー全文</a>\
        </p>\
      </div>\
    </div>\
    <label class="upgrade-modal__checkbox">\
      <input type="checkbox" id="agree-checkbox" onchange="updateUpgradeButton()">\
      <span>利用規約とプライバシーポリシーに同意する</span>\
    </label>\
    <button class="upgrade-modal__submit" id="confirm-upgrade-btn" disabled onclick="proceedToPayment()">\
      お支払いへ進む\
    </button>\
    <p class="upgrade-modal__note">Stripeの安全な決済画面に移動します</p>\
  ';
}

// Update upgrade button state based on checkbox
function updateUpgradeButton() {
  var checkbox = document.getElementById('agree-checkbox');
  var button = document.getElementById('confirm-upgrade-btn');

  if (checkbox && button) {
    button.disabled = !checkbox.checked;
  }
}

// Proceed to Stripe payment
async function proceedToPayment() {
  var button = document.getElementById('confirm-upgrade-btn');
  var originalText = button.textContent;

  button.disabled = true;
  button.textContent = '処理中...';

  try {
    var response = await fetch('/api/stripe/create-checkout-session', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        success_url: window.location.origin + '?upgrade=success',
        cancel_url: window.location.origin + '/about.html#pricing'
      })
    });

    if (!response.ok) {
      var error = await response.json();
      throw new Error(error.error || 'チェックアウトセッションの作成に失敗しました');
    }

    var data = await response.json();

    if (data.url) {
      window.location.href = data.url;
    } else {
      throw new Error('チェックアウトURLの取得に失敗しました');
    }
  } catch (err) {
    console.error('Payment error:', err);

    // Show error in modal
    var modalInner = document.querySelector('.upgrade-modal');
    var existingError = modalInner.querySelector('.upgrade-modal__error');

    if (existingError) {
      existingError.textContent = err.message;
    } else {
      var errorEl = document.createElement('div');
      errorEl.className = 'upgrade-modal__error';
      errorEl.textContent = err.message;
      modalInner.insertBefore(errorEl, modalInner.querySelector('.upgrade-modal__checkbox'));
    }

    button.disabled = false;
    button.textContent = originalText;

    // Re-check checkbox state
    var checkbox = document.getElementById('agree-checkbox');
    if (checkbox && !checkbox.checked) {
      button.disabled = true;
    }
  }
}

// Close modal on overlay click
document.addEventListener('click', function(e) {
  if (e.target.classList.contains('upgrade-modal-overlay')) {
    closeUpgradeModal();
  }
});

// Close modal on escape key
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    var modal = document.getElementById('upgrade-modal');
    if (modal && modal.classList.contains('active')) {
      closeUpgradeModal();
    }
  }
});
