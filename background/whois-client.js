/**
 * Virus Detector — Whois 查询客户端 (Whois Client)
 *
 * 基于 WhoisCX 免费 API（http://whoiscx.com/apidoc/）的域名 Whois 信息查询模块。
 * 提供带内存缓存和速率限制的异步查询接口，供评分引擎和服务工作线程使用。
 *
 * @module whois-client
 * @version 2.2.2
 *
 * API 规范：
 *   - 接口地址：GET http://api.whoiscx.com/whois/?domain={domain}
 *   - ⚠️ 仅支持 HTTP（不支持 HTTPS），请注意网络环境是否允许 HTTP 请求
 *   - 响应格式：application/json
 *   - 频率限制：2 秒/次（本模块通过串行化请求保证）
 *   - 响应字段：status, data.domain, data.info.creation_days, data.info.valid_days,
 *               data.info.creation_time, data.info.expiration_time, data.info.is_expire 等
 *
 * 缓存策略：
 *   - 内存 Map 缓存，TTL = 24 小时（由 constants.js 中的 WHOIS_CACHE_TTL 配置）
 *   - 缓存命中直接返回，不消耗 API 配额
 *   - 查询失败不缓存，下次请求重试
 *
 * PSL 查询策略：
 *   - 通过 DNS-over-HTTPS 查询 publicsuffix.zone 获取域名的公共后缀
 *   - 查询结果缓存于内存 Map，服务 worker 生命周期内有效
 *   - DNS 不可用时回退到最小 TLD 集
 */

import {
  WHOIS_API_URL, WHOIS_CACHE_TTL, WHOIS_API_TIMEOUT
} from '../utils/constants.js';
import { refreshPublicSuffixDNS } from '../utils/url-utils.js';
import { UrlUtils } from '../utils/url-utils.js';

// ==================== 内存缓存 ====================

/**
 * @typedef {Object} WhoisCacheEntry
 * @property {WhoisResult} result   - 缓存的查询结果
 * @property {number}      timestamp - 缓存时间戳
 */

/** @type {Map<string, WhoisCacheEntry>} */
const _cache = new Map();

// ==================== 速率限制 ====================

/** 上次 API 请求完成的时间戳（用于速率限制） */
let _lastRequestTime = 0;

/** API 最小请求间隔（毫秒），保护免费 API 不被封禁 */
const MIN_REQUEST_INTERVAL = 2100; // 略大于 2 秒

/**
 * 等待直到满足速率限制要求
 * @returns {Promise<void>}
 */
async function _waitForRateLimit() {
  const now = Date.now();
  const elapsed = now - _lastRequestTime;
  if (elapsed < MIN_REQUEST_INTERVAL) {
    await new Promise(resolve => setTimeout(resolve, MIN_REQUEST_INTERVAL - elapsed));
  }
  _lastRequestTime = Date.now();
}

// ==================== 错误信息记录 ====================

/** @type {WhoisErrorInfo|null} 最近一次查询失败的错误详情 */
let _lastError = null;

/**
 * 记录错误信息并输出到控制台
 * @param {string} domain     - 查询的域名
 * @param {string} phase      - 失败阶段（如 "connect", "http_status", "parse", "timeout"）
 * @param {string} message    - 错误描述
 * @param {Object} [extra={}] - 附加调试信息
 */
function _recordError(domain, phase, message, extra = {}) {
  _lastError = {
    domain,
    phase,
    message,
    timestamp: Date.now(),
    ...extra
  };

  const phaseLabel = {
    'connect':    '网络连接失败',
    'http_status': 'HTTP 状态异常',
    'parse':      '响应解析失败',
    'timeout':    '请求超时',
    'invalid':    '参数无效'
  }[phase] || phase;

  console.error(`[WhoisClient] ${phaseLabel} (${domain}): ${message}`, extra);
}

// ==================== 辅助函数 ====================

/**
 * 从 creation_time 日期字符串计算已注册天数
 * WhoisCX API 返回格式如 "2012-04-25 12:36:40" 或 "2012-04-25"
 * @param {string} timeStr - 创建时间字符串
 * @returns {number} 天数，解析失败返回 -1
 */
function _parseDaysFromTime(timeStr) {
  if (!timeStr || typeof timeStr !== 'string') return -1;
  try {
    const match = timeStr.match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (!match) return -1;
    const creationDate = new Date(
      parseInt(match[1], 10),
      parseInt(match[2], 10) - 1,
      parseInt(match[3], 10)
    );
    if (isNaN(creationDate.getTime())) return -1;
    const diffMs = Date.now() - creationDate.getTime();
    if (diffMs < 0) return -1;
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  } catch (e) {
    return -1;
  }
}

// ==================== 公开接口 ====================

export class WhoisClient {
  /**
   * 查询域名的 Whois 信息
   *
   * @param {string} domain - 要查询的完整域名（如 "example.com"）
   * @returns {Promise<WhoisResult|null>} 查询结果，失败时返回 null
   *   （可通过 WhoisClient.lastError 获取失败详情）
   */
  static async lookup(domain) {
    // 参数校验
    if (!domain || typeof domain !== 'string') {
      _recordError(String(domain || ''), 'invalid', 'domain 参数为空或类型错误', { domain });
      return null;
    }

    // 规范化域名：基于 PSL 提取可注册域名
    // 例如 roms.lian86.top -> lian86.top, www.pc-sysceo.hl.cn -> pc-sysceo.hl.cn
    const rawDomain = domain.toLowerCase().trim();
    const normalizedDomain = UrlUtils.getMainDomain(rawDomain);

    if (!normalizedDomain || !normalizedDomain.includes('.')) {
      _recordError(normalizedDomain || domain, 'invalid', '域名格式无效', { domain });
      return null;
    }

    if (normalizedDomain !== rawDomain) {
      console.log(`[WhoisClient] PSL 域名提取: ${rawDomain} -> ${normalizedDomain}`);
    }

    // 异步触发 DoH PSL 查询（不阻塞当前请求，预填充缓存供后续使用）
    refreshPublicSuffixDNS(rawDomain).catch(() => {});

    // 1. 检查缓存
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      const ageLabel = cached.result.creationDays >= 0 ? `注册${cached.result.creationDays}天` : '注册天数未知';
      console.log(`[WhoisClient] 缓存命中: ${normalizedDomain} (${ageLabel})`);
      return cached.result;
    }

    // 2. 速率限制等待
    await _waitForRateLimit();

    // 3. 构建请求 URL
    const url = `${WHOIS_API_URL}?domain=${encodeURIComponent(normalizedDomain)}`;
    console.log(`[WhoisClient] 发起请求: ${url}`);

    // 4. 发起 API 请求
    let response;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), WHOIS_API_TIMEOUT);

      response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'Accept': 'application/json' }
      });

      clearTimeout(timeoutId);
    } catch (error) {
      if (error.name === 'AbortError') {
        _recordError(normalizedDomain, 'timeout',
          `请求超过 ${WHOIS_API_TIMEOUT}ms 超时`,
          { url, timeoutMs: WHOIS_API_TIMEOUT });
      } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
        _recordError(normalizedDomain, 'connect',
          `网络连接失败: ${error.message}`,
          { url, errorName: error.name });
      } else {
        _recordError(normalizedDomain, 'connect',
          `请求异常: ${error.message}`,
          { url, errorName: error.name, errorStack: error.stack });
      }
      return null;
    }

    // 5. 检查 HTTP 状态码
    if (!response.ok) {
      let responseBody = '';
      try { responseBody = await response.text(); } catch (e) { /* ignore */ }
      _recordError(normalizedDomain, 'http_status',
        `API 返回 HTTP ${response.status} ${response.statusText}`,
        { url, statusCode: response.status, statusText: response.statusText, responseBody: responseBody.substring(0, 500) });
      return null;
    }

    // 6. 解析 JSON 响应体
    let json;
    try {
      json = await response.json();
    } catch (parseError) {
      let responseBody = '';
      try { responseBody = await response.clone().text(); } catch (e) { /* ignore */ }
      _recordError(normalizedDomain, 'parse',
        `JSON 解析失败: ${parseError.message}`,
        { url, responseBody: responseBody.substring(0, 500) });
      return null;
    }

    // 7. 校验业务状态码
    if (json.status !== 1) {
      _recordError(normalizedDomain, 'parse',
        `API 业务状态码异常 (status=${json.status})，预期 status=1`,
        { url, responseJson: json });
      return null;
    }

    if (!json.data) {
      _recordError(normalizedDomain, 'parse',
        'API 响应缺少 data 字段',
        { url, responseKeys: Object.keys(json) });
      return null;
    }

    // 8. 提取并构建结果
    const info = json.data.info || {};
    const domainSuffix = json.data.domain_suffix || '';
    const creationTime = info.creation_time || info.registration_time || json.data.creation_time || json.data.registration_time || '';
    const expirationTime = info.expiration_time || info.registration_expiration_time || json.data.expiration_time || '';

    // 调试日志
    console.log(`[WhoisClient] API 原始响应结构 (${normalizedDomain}):`,
      `data keys: [${Object.keys(json.data).join(', ')}]`,
      `info keys: [${Object.keys(info).join(', ')}]`,
      `data.creation_days=${json.data.creation_days}`,
      `info.creation_days=${info.creation_days}`,
      `data.creation_time=${JSON.stringify(json.data.creation_time)}`,
      `info.creation_time=${JSON.stringify(info.creation_time)}`);

    // creation_days 多层回退读取
    let creationDaysRaw = info.creation_days;
    if (creationDaysRaw === undefined || creationDaysRaw === null) {
      creationDaysRaw = json.data.creation_days;
    }

    let creationDays = -1;
    let creationDaysSource = 'unknown';

    if (typeof creationDaysRaw === 'number' && creationDaysRaw > 0) {
      creationDays = creationDaysRaw;
      creationDaysSource = typeof info.creation_days === 'number' ? 'api_info' : 'api_data';
    } else if (typeof creationDaysRaw === 'number' && creationDaysRaw === 0) {
      console.warn(`[WhoisClient] API returned creation_days=0 (${normalizedDomain}), trying creation_time fallback`);
      const calculated = _parseDaysFromTime(creationTime);
      if (calculated > 0) {
        creationDays = calculated;
        creationDaysSource = 'calculated_from_time';
        console.log(`[WhoisClient] calculated ${creationDays} days from creation_time`);
      } else {
        console.warn(`[WhoisClient] creation_time fallback also failed (${normalizedDomain})`);
        creationDays = -1;
        creationDaysSource = 'unreliable_zero';
      }
    } else {
      console.warn(`[WhoisClient] creation_days missing (${normalizedDomain}), data=${typeof json.data.creation_days}, info=${typeof info.creation_days}`);
      creationDaysSource = 'missing';
    }

    // valid_days 同样采用多层回退
    let validDaysRaw = info.valid_days;
    if (validDaysRaw === undefined || validDaysRaw === null) {
      validDaysRaw = json.data.valid_days;
    }

    const result = {
      domain: json.data.domain || normalizedDomain,
      domainSuffix,
      creationDays,
      validDays: typeof validDaysRaw === 'number' ? validDaysRaw : -1,
      creationTime,
      expirationTime,
      isExpire: info.is_expire === 1,
      registrarName: info.registrar_name || '',
      domainStatus: Array.isArray(info.domain_status) ? info.domain_status : [],
      nameServer: Array.isArray(info.name_server) ? info.name_server : [],
      queryTime: json.data.query_time || ''
    };

    // 9. 写入缓存（仅当 creationDays 有效时缓存）
    if (creationDays > 0) {
      _cache.set(normalizedDomain, { result, timestamp: Date.now() });
      console.log(`[WhoisClient] cache write: ${normalizedDomain} (creationDays=${creationDays}, source=${creationDaysSource})`);
    } else {
      console.warn(`[WhoisClient] skip cache: ${normalizedDomain} (creationDays=${creationDays}, source=${creationDaysSource})`);
    }

    _lastError = null;

    const ageLabel = result.creationDays >= 0 ? `registered ${result.creationDays}d` : 'age unknown';
    const validLabel = result.validDays >= 0 ? `expires in ${result.validDays}d` : 'validity unknown';
    console.log(`[WhoisClient] lookup OK: ${normalizedDomain} (${ageLabel}, ${validLabel}, registrar: ${result.registrarName || 'unknown'})`);
    return result;
  }

  /**
   * 从缓存中获取 Whois 结果（不发起网络请求）
   * @param {string} domain - 域名
   * @returns {WhoisResult|null}
   */
  static getCached(domain) {
    if (!domain) return null;
    const normalizedDomain = UrlUtils.getMainDomain(domain.toLowerCase().trim());
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      return cached.result;
    }
    return null;
  }

  static get lastError() {
    return _lastError;
  }

  static clearLastError() {
    _lastError = null;
  }

  static clearCache(domain) {
    if (domain) {
      _cache.delete(UrlUtils.getMainDomain(domain.toLowerCase().trim()));
    }
  }

  static clearAllCache() {
    _cache.clear();
  }
}

// ==================== 类型定义 ====================

/**
 * @typedef {Object} WhoisResult
 * @property {string}   domain        - 查询的域名
 * @property {string}   domainSuffix  - 域名后缀（如 com, cn）
 * @property {number}   creationDays  - 域名已注册天数（-1 表示未知）
 * @property {number}   validDays     - 域名距离到期剩余天数（-1 表示未知）
 * @property {string}   creationTime  - 域名创建时间（如 "2012-04-25 12:36:40"）
 * @property {string}   expirationTime - 域名到期时间
 * @property {boolean}  isExpire      - 是否已过期
 * @property {string}   registrarName - 注册商名称
 * @property {string[]} domainStatus  - 域名状态列表
 * @property {string[]} nameServer    - DNS 服务器列表
 * @property {string}   queryTime     - 查询时间
 */

/**
 * @typedef {Object} WhoisErrorInfo
 * @property {string} domain    - 查询的域名
 * @property {string} phase     - 失败阶段
 * @property {string} message   - 错误描述
 * @property {number} timestamp - 错误发生时间戳
 * @property {string} [url]     - 请求的完整 URL
 * @property {number} [statusCode]     - HTTP 状态码
 * @property {string} [statusText]     - HTTP 状态文本
 * @property {string} [responseBody]   - 响应体（截取前 500 字符）
 * @property {Object} [responseJson]   - 已解析的 JSON 响应
 * @property {string} [errorName]      - 异常类型名称
 * @property {string} [errorStack]     - 异常堆栈
 * @property {number} [timeoutMs]      - 超时毫秒数
 */
