/**
 * 银狐木马检测 - Popup UI (v1.2)
 * SVG图标系统 + 优化排版 + 白名单极简模式
 */
(function () {
  'use strict';

  const SCORE_THRESHOLD = 100;

  const $ = (id) => document.getElementById(id);

  // ==================== SVG 图标定义 ====================
  const ICONS = {
    // 绿色勾（通过）
    check: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="#4CAF50"/><path d="M6 10l3 3 5-5" stroke="white" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    // 红色叉（触发）
    cross: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="#F44336"/><path d="M7 7l6 6M13 7l-6 6" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>',
    // 灰色横线（不适用）
    dash: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="none" stroke="#757575" stroke-width="1.5"/><path d="M7 10h6" stroke="#757575" stroke-width="2" stroke-linecap="round"/></svg>',
    // 橙色感叹号（部分可疑）
    warn: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="#FF9800"/><path d="M10 5v5M10 14v1" stroke="white" stroke-width="2.5" stroke-linecap="round"/></svg>',
    // 加载中（三点旋转）
    pending: '<svg viewBox="0 0 20 20" width="14" height="14"><circle cx="10" cy="10" r="9" fill="none" stroke="#757575" stroke-width="1.5" stroke-dasharray="4 3"/></svg>',
    // 白名单星标按钮
    star: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M12 2l3.1 6.3L22 9.3l-5 4.9 1.2 6.8-6.2-3.3-6.2 3.3 1.2-6.8-5-4.9 6.9-1z"/></svg>',
    // 白名单取消星标
    starOff: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="3" x2="21" y2="21"/><path d="M12 2l3.1 6.3L22 9.3l-5 4.9 1.2 6.8-6.2-3.3-6.2 3.3 1.2-6.8-5-4.9 6.9-1z"/></svg>',
    // 刷新
    refresh: '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.5 9a9 9 0 0114.8-3.7L23 10M.5 15a9 9 0 0014.8 3.7L20 15"/></svg>',
    // 绿色大勾（白名单/安全分数）
    checkLarge: '<svg viewBox="0 0 24 24" width="44" height="44"><circle cx="12" cy="12" r="11" fill="#4CAF50"/><path d="M7 12l3 3 7-7" stroke="white" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  };

  const els = {
    header: $('header'), loading: $('loading'),
    safePanel: $('safe-panel'), warningPanel: $('warning-panel'),
    whitelistPanel: $('whitelist-panel'),
    scoreValue: $('score-value'), statusText: $('status-text'),
    currentDomain: $('current-domain'),
    riskLevelText: $('risk-level-text'),
    warningScoreValue: $('warning-score-value'),
    warningStatusText: $('warning-status-text'),
    officialLinkSection: $('official-link-section'),
    officialLinkBtn: $('official-link-btn'),
    officialLinkText: $('official-link-text'),
    safetyTips: $('safety-tips'),
    detailsSection: $('details-section'),
    refreshBtn: $('refresh-btn'),
    whitelistBtn: $('whitelist-btn'),
    detailRules: {
      rule1: $('detail-rule1'), rule2: $('detail-rule2'),
      rule3: $('detail-rule3'), rule4: $('detail-rule4'),
      rule5: $('detail-rule5')
    }
  };

  // ==================== UI 状态切换 ====================

  function showLoading() {
    els.loading.style.display = 'block';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.detailsSection.style.display = 'block';
    els.header.className = 'header-safe';
    _resetDetailIcons();
  }

  function _resetDetailIcons() {
    for (const key of Object.keys(els.detailRules)) {
      const el = els.detailRules[key];
      if (!el) continue;
      const iconEl = el.querySelector('.detail-icon');
      const textEl = el.querySelector('.detail-text');
      iconEl.innerHTML = ICONS.pending;
      textEl.textContent = '待检测';
      textEl.className = 'detail-text neutral';
    }
  }

  function updateWhitelistButton(isWhitelisted) {
    if (isWhitelisted) {
      els.whitelistBtn.innerHTML = ICONS.starOff + '移出白名单';
      els.whitelistBtn.classList.add('active');
    } else {
      els.whitelistBtn.innerHTML = ICONS.star + '加入白名单';
      els.whitelistBtn.classList.remove('active');
    }
  }

  function showSafe(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'block';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.detailsSection.style.display = 'block';
    els.header.className = 'header-safe';
    els.scoreValue.textContent = data.score || 0;
    els.statusText.textContent = '安全';
    els.currentDomain.textContent = data.domain || '-';
    els.riskLevelText.textContent = '正常';
    els.riskLevelText.className = 'info-value safe-text';
  }

  function showWhitelisted(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'block';
    els.safetyTips.style.display = 'none';
    els.officialLinkSection.style.display = 'none';
    els.detailsSection.style.display = 'none';
    els.header.className = 'header-whitelist';
  }

  function showWarning(data) {
    els.loading.style.display = 'none';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'block';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'block';
    els.detailsSection.style.display = 'block';
    els.header.className = 'header-danger';
    els.warningScoreValue.textContent = data.score || 0;
    els.warningStatusText.textContent = '危险警告';

    if (data.correctUrl) {
      els.officialLinkSection.style.display = 'block';
      els.officialLinkBtn.href = data.correctUrl;
      els.officialLinkText.textContent = data.correctUrl;
    } else {
      els.officialLinkSection.style.display = 'none';
    }
  }

  // ==================== 检测详情更新（SVG图标 + 去重前缀） ====================

  function updateDetails(ruleResults) {
    if (!ruleResults) return;
    for (const key of Object.keys(els.detailRules)) {
      const rule = ruleResults[key];
      const el = els.detailRules[key];
      if (!el) continue;
      const iconEl = el.querySelector('.detail-icon');
      const textEl = el.querySelector('.detail-text');

      if (!rule || !rule.detailCN) {
        iconEl.innerHTML = ICONS.pending;
        textEl.textContent = '待检测';
        textEl.className = 'detail-text neutral';
        continue;
      }

      // 剥离 detailCN 前缀符号（✓ ✗ ⚠ - 等），避免与左侧SVG图标重复
      var cleanText = rule.detailCN.replace(/^(?:✓|✗|⚠️?|-)\s*/, '');

      if (rule.triggered) {
        iconEl.innerHTML = ICONS.cross;
        textEl.textContent = cleanText;
        textEl.className = 'detail-text triggered';
      } else if (rule.detailCN.startsWith('✓')) {
        iconEl.innerHTML = ICONS.check;
        textEl.textContent = cleanText;
        textEl.className = 'detail-text passed';
      } else if (rule.detailCN.startsWith('⚠')) {
        iconEl.innerHTML = ICONS.warn;
        textEl.textContent = cleanText;
        textEl.className = 'detail-text neutral';
      } else {
        iconEl.innerHTML = ICONS.dash;
        textEl.textContent = cleanText;
        textEl.className = 'detail-text neutral';
      }
    }
  }

  function showError(msg) {
    els.loading.innerHTML = '<div style="text-align:center;padding:20px;">' +
      '<p style="color:#F44336;font-size:14px;">' +
      '<svg viewBox="0 0 20 20" width="14" height="14" style="vertical-align:middle;margin-right:4px;"><path d="M10 2L1 18h18L10 2z" fill="#F44336"/><path d="M10 7v4M10 14.5v.5" stroke="white" stroke-width="2" stroke-linecap="round"/></svg>' +
      (msg || '无法获取检测结果') + '</p>' +
      '<p style="font-size:12px;color:#a0a0a0;margin-top:8px;">请确保已打开网页，点击"重新检测"重试</p></div>';
    els.loading.style.display = 'block';
    els.safePanel.style.display = 'none';
    els.warningPanel.style.display = 'none';
    els.whitelistPanel.style.display = 'none';
    els.safetyTips.style.display = 'none';
    els.detailsSection.style.display = 'none';
  }

  // ==================== 数据获取 ====================

  async function fetchState() {
    try {
      const resp = await chrome.runtime.sendMessage({ type: 'GET_TAB_STATE', payload: {} });
      return (resp && resp.success) ? resp.data : null;
    } catch (e) { return null; }
  }

  async function requestReanalysis() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length > 0) {
        await chrome.tabs.sendMessage(tabs[0].id, { type: 'REQUEST_PAGE_TEXT', payload: {} });
      }
      await new Promise(r => setTimeout(r, 1500));
    } catch (e) { /* content script may not be ready */ }
  }

  // ==================== 主渲染 ====================

  async function render() {
    showLoading();
    let data = await fetchState();
    if (!data || !data.isAnalyzed) {
      await requestReanalysis();
      data = await fetchState();
    }
    if (!data) { showError('无法获取页面分析结果'); return; }

    // 白名单优先显示（极简模式：仅绿色勾，无文字无详情）
    if (data.isWhitelisted) {
      showWhitelisted(data);
      updateWhitelistButton(true);
      return;
    }

    if (data.score >= SCORE_THRESHOLD) {
      showWarning(data);
    } else {
      showSafe(data);
    }
    updateDetails(data.ruleResults);
    updateWhitelistButton(false);
  }

  // ==================== 按钮事件 ====================

  els.refreshBtn.addEventListener('click', async () => {
    showLoading();
    els.refreshBtn.innerHTML = ICONS.pending + '检测中...';
    els.refreshBtn.disabled = true;
    await requestReanalysis();
    await render();
    els.refreshBtn.innerHTML = ICONS.refresh + '重新检测';
    els.refreshBtn.disabled = false;
  });

  // 白名单按钮
  els.whitelistBtn.addEventListener('click', async () => {
    showLoading();
    els.whitelistBtn.disabled = true;
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length === 0) return;
      const url = tabs[0].url || '';

      // 先检查当前白名单状态
      const checkResp = await chrome.runtime.sendMessage({
        type: 'CHECK_WHITELIST',
        payload: { url }
      });
      const isCurrentlyWhitelisted = checkResp?.isWhitelisted || false;

      if (isCurrentlyWhitelisted) {
        await chrome.runtime.sendMessage({
          type: 'REMOVE_FROM_WHITELIST',
          payload: { url }
        });
      } else {
        await chrome.runtime.sendMessage({
          type: 'ADD_TO_WHITELIST',
          payload: { url }
        });
      }

      // 等待后台处理完成
      await new Promise(r => setTimeout(r, 400));
      await render();
    } catch (e) {
      console.error('[Popup] 白名单操作失败:', e);
    }
    els.whitelistBtn.disabled = false;
  });

  // ==================== 初始化 ====================

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    render();
  } else {
    document.addEventListener('DOMContentLoaded', render);
  }
})();
