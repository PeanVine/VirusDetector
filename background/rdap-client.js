/**
 * Virus Detector — RDAP 查询客户端 (RDAP Client)
 *
 * 基于 IANA RDAP 协议（RFC 9082/9083）的域名注册信息查询模块。
 * 替代原有的 WhoisCX API，使用 IANA RDAP 引导文件 + RDAP 服务端查询。
 *
 * @module rdap-client
 * @version 2.2.3
 *
 * 查询流程：
 *   1. 从 IANA 下载 RDAP 引导文件 https://data.iana.org/rdap/dns.json
 *      获取 TLD 到 RDAP 服务器的映射关系
 *   2. 根据域名的 TLD 查找对应的 RDAP 服务器 URL
 *   3. 向 RDAP 服务器发送域名查询请求
 *   4. 解析 RDAP JSON 响应，提取注册信息
 *
 * 缓存策略：
 *   - 引导文件缓存 24 小时（该文件每日更新一次）
 *   - 域名查询结果不在此缓存（由 whois-client.js 缓存）
 *
 * RDAP 响应中的关键字段映射：
 *   events[eventAction=registration].eventDate  → 域名创建时间
 *   events[eventAction=expiration].eventDate    → 域名过期时间
 *   entities[roles=registrar].vcardArray        → 注册商名称
 *   nameservers[].ldhName                       → DNS 服务器列表
 *   status                                       → 域名状态列表
 */

// ==================== 引导文件缓存 ====================

/** IANA RDAP DNS 引导文件 URL */
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

/** 引导文件缓存有效期（毫秒），24小时。该文件通常每日 UTC 22:00 更新 */
const BOOTSTRAP_CACHE_TTL = 24 * 60 * 60 * 1000;

/** RDAP 请求超时（毫秒） */
const RDAP_REQUEST_TIMEOUT = 10000;

/**
 * @typedef {Object} BootstrapCache
 * @property {Map<string, string>} tldToServer - TLD → RDAP 基础 URL 映射
 * @property {number}             timestamp    - 缓存时间戳
 * @property {string}             publication  - 引导文件的 publication 时间
 * @property {boolean}            isFallback   - 是否正在使用硬编码回退映射
 */

/** @type {BootstrapCache|null} */
let _bootstrapCache = null;

/**
 * 硬编码的常用 gTLD → RDAP 服务器回退映射。
 *
 * 仅在 IANA 引导文件【下载失败】时使用，作为常用顶级域的应急兜底。
 * 正常情况下 IANA 引导文件覆盖全部 1200+ TLD，本表不会被用到。
 *
 * 重要：本表只包含【已从 IANA 引导文件验证过】的 gTLD 服务器地址。
 *   - 不含 ccTLD（如 .cn/.uk/.de）：多数 ccTLD 已在 IANA 引导文件中，
 *     且部分 ccTLD（如 .cn）根本没有公开 RDAP 服务，硬编码会导致无效请求。
 *   - 仅 gTLD 在 ICANN 合约下强制提供公开 RDAP，地址稳定可靠。
 */
const _FALLBACK_RDAP_SERVERS = new Map([
  ['com',  'https://rdap.verisign.com/com/v1/'],
  ['net',  'https://rdap.verisign.com/net/v1/'],
  ['org',  'https://rdap.publicinterestregistry.org/rdap/'],
  ['info', 'https://rdap.identitydigital.services/rdap/'],
  ['ai',   'https://rdap.identitydigital.services/rdap/'],
  ['biz',  'https://rdap.nic.biz/'],
  ['tv',   'https://rdap.nic.tv/'],
  ['cc',   'https://tld-rdap.verisign.com/cc/v1/'],
  ['xyz',  'https://rdap.centralnic.com/xyz/'],
  ['top',  'https://rdap.zdnsgtld.com/top/'],
  ['app',  'https://pubapi.registry.google/rdap/'],
  ['dev',  'https://pubapi.registry.google/rdap/'],
]);

/**
 * 已知【没有公开 RDAP 服务】的 ccTLD 集合。
 * 这些顶级域不在 IANA RDAP 引导文件中，且注册局未提供可访问的公开 RDAP 端点。
 * 命中时直接跳过查询，避免无效网络请求和错误刷屏。
 *
 * 注意：该列表用于优化体验（少打日志），不影响功能正确性——
 *   即使某 ccTLD 未列入此处，查询失败也会被优雅降级处理。
 */
const _NO_RDAP_TLDS = new Set([
  'cn',  // CNNIC 未提供公开 RDAP（不在 IANA 引导文件中）
]);

// ==================== 引导文件管理 ====================

/**
 * 从 IANA 下载并解析 RDAP 引导文件
 * @returns {Promise<BootstrapCache>}
 * @throws {Error} 下载失败或解析失败
 */
async function _fetchBootstrap() {
  console.log('[RdapClient] 正在下载 RDAP 引导文件...');

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), RDAP_REQUEST_TIMEOUT);

  let response;
  try {
    response = await fetch(RDAP_BOOTSTRAP_URL, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'Accept': 'application/json' }
    });
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    throw new Error(`引导文件下载失败: HTTP ${response.status} ${response.statusText}`);
  }

  let json;
  try {
    json = await response.json();
  } catch (e) {
    throw new Error(`引导文件 JSON 解析失败: ${e.message}`);
  }

  if (!json.services || !Array.isArray(json.services)) {
    throw new Error('引导文件缺少 services 数组');
  }

  // 构建 TLD → RDAP 服务器 URL 映射（从 IANA 加载）
  const tldToServer = new Map();
  for (const entry of json.services) {
    if (!Array.isArray(entry) || entry.length < 2) continue;
    const [tlds, urls] = entry;
    if (!Array.isArray(tlds) || !Array.isArray(urls) || urls.length === 0) continue;

    // 取第一个 RDAP 服务器 URL（通常只有一个）
    const baseUrl = urls[0].replace(/\/+$/, '/'); // 确保以 / 结尾
    for (const tld of tlds) {
      if (typeof tld === 'string') {
        tldToServer.set(tld.toLowerCase(), baseUrl);
      }
    }
  }

  // 用 IANA 数据覆盖回退映射中相同 TLD 的条目。
  // 回退映射中没有的 TLD 从 IANA 补充。
  for (const [tld, url] of _FALLBACK_RDAP_SERVERS) {
    if (!tldToServer.has(tld)) {
      tldToServer.set(tld, url);
    }
  }

  console.log(`[RdapClient] 引导文件加载完成: ${tldToServer.size} 个 TLD 映射 (含 fallback 补充)`);

  _bootstrapCache = {
    tldToServer,
    timestamp: Date.now(),
    publication: json.publication || '',
    isFallback: false
  };

  return _bootstrapCache;
}

/**
 * 构建纯回退的引导缓存（IANA 下载失败时使用）
 * @returns {BootstrapCache}
 */
function _buildFallbackCache() {
  const tldToServer = new Map(_FALLBACK_RDAP_SERVERS);
  console.warn(`[RdapClient] ⚠️ 回退到硬编码 RDAP 映射 (${tldToServer.size} 个 TLD)`);

  _bootstrapCache = {
    tldToServer,
    timestamp: Date.now(),
    publication: '(hardcoded fallback)',
    isFallback: true
  };

  return _bootstrapCache;
}

/**
 * 确保引导文件已加载且缓存有效。
 * IANA 下载失败时自动回退到硬编码映射。
 * @returns {Promise<BootstrapCache>}
 */
async function _ensureBootstrap() {
  // 已有缓存且在有效期内 → 直接返回
  if (_bootstrapCache && (Date.now() - _bootstrapCache.timestamp) < BOOTSTRAP_CACHE_TTL) {
    return _bootstrapCache;
  }

  // 尝试从 IANA 下载
  try {
    return await _fetchBootstrap();
  } catch (error) {
    console.error('[RdapClient] IANA 引导文件下载失败:', error.message);
    // 回退到硬编码映射
    return _buildFallbackCache();
  }
}

/**
 * 清空引导文件缓存（下次查询自动重新下载）
 */
function _clearBootstrapCache() {
  _bootstrapCache = null;
}

/**
 * 从引导文件中查找域名对应的 RDAP 基础 URL
 * @param {string} domain - 完整域名（如 "baidu.com"）
 * @returns {Promise<{baseUrl: string|null, isFallback: boolean, noRdap: boolean}>}
 *   baseUrl:    RDAP 基础 URL，未找到返回 null
 *   isFallback: 是否正在使用回退映射
 *   noRdap:     该 TLD 已知没有公开 RDAP 服务（直接跳过查询）
 */
async function _getRdapBaseUrl(domain) {
  // 提取 TLD（域名的最后一段）
  const parts = domain.toLowerCase().split('.');
  if (parts.length < 2) return { baseUrl: null, isFallback: false, noRdap: false };
  const tld = parts[parts.length - 1];

  // 已知无公开 RDAP 的 TLD → 直接跳过，不触发网络请求
  if (_NO_RDAP_TLDS.has(tld)) {
    return { baseUrl: null, isFallback: false, noRdap: true };
  }

  const bootstrap = await _ensureBootstrap();
  const baseUrl = bootstrap.tldToServer.get(tld) || null;
  return { baseUrl, isFallback: bootstrap.isFallback || false, noRdap: false };
}

// ==================== RDAP 响应解析 ====================

/**
 * 从 vcardArray（jCard 格式）中提取指定字段的值
 *
 * jCard 格式：[ "vcard", [ [fieldName, params, type, value], ... ] ]
 * 常用字段：
 *   fn    → 组织/个人全名
 *   email → 电子邮件地址
 *   tel   → 电话号码
 *
 * @param {Array} vcardArray - jCard 数组
 * @param {string} fieldName - 要提取的字段名（如 "fn", "email"）
 * @returns {string} 字段值，未找到返回空字符串
 */
function _extractVcardField(vcardArray, fieldName) {
  if (!Array.isArray(vcardArray)) return '';
  // vcardArray 格式：[ "vcard", [ [fieldName, {}, "text", value], ... ] ]
  const [, fields] = vcardArray;
  if (!Array.isArray(fields)) return '';

  for (const field of fields) {
    if (Array.isArray(field) && field[0] === fieldName && field.length >= 4) {
      return String(field[3] || '');
    }
  }
  return '';
}

/**
 * 从 entities 数组中查找指定角色的实体，并提取指定字段
 *
 * entities 角色类型：
 *   "registrar" → 注册商（域名注册服务提供商）
 *   "abuse"     → 滥用投诉联系人
 *   "administrative" → 管理联系人
 *   "technical"     → 技术联系人
 *   "registrant"    → 域名持有者
 *
 * @param {Array} entities - RDAP 响应中的 entities 数组
 * @param {string|string[]} role - 要找的角色（可以是字符串或数组）
 * @param {string} fieldName - 要提取的 jCard 字段名
 * @returns {string} 提取的值，未找到返回空字符串
 */
function _extractFromEntities(entities, role, fieldName = 'fn') {
  if (!Array.isArray(entities)) return '';

  const roles = Array.isArray(role) ? role : [role];

  for (const entity of entities) {
    if (!entity || typeof entity !== 'object') continue;
    const entityRoles = entity.roles || [];
    const hasRole = roles.some(r => entityRoles.includes(r));
    if (hasRole && entity.vcardArray) {
      const val = _extractVcardField(entity.vcardArray, fieldName);
      if (val) return val;
    }

    // 递归搜索子实体
    if (entity.entities && Array.isArray(entity.entities)) {
      const val = _extractFromEntities(entity.entities, role, fieldName);
      if (val) return val;
    }
  }

  return '';
}

/**
 * 从 events 数组中查找指定类型的事件日期
 *
 * 常用 eventAction 类型：
 *   "registration" → 域名注册日期
 *   "expiration"   → 域名过期日期
 *   "last changed" → 最后变更日期
 *
 * @param {Array} events - RDAP 响应中的 events 数组
 * @param {string} eventAction - 要找的事件类型
 * @returns {string} ISO 8601 日期字符串，未找到返回空字符串
 */
function _extractEventDate(events, eventAction) {
  if (!Array.isArray(events)) return '';
  for (const event of events) {
    if (event && event.eventAction === eventAction && event.eventDate) {
      return event.eventDate;
    }
  }
  return '';
}

/**
 * 从 ISO 8601 日期字符串计算天数差
 *
 * @param {string} dateStr - ISO 8601 日期字符串（如 "1999-10-11T11:05:17Z"）
 * @returns {number} 到当前时间的天数差（正数），解析失败返回 -1
 */
function _daysFromNow(dateStr) {
  if (!dateStr) return -1;
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) return -1;
    const diffMs = Date.now() - date.getTime();
    if (diffMs < 0 && Math.abs(diffMs) > 86400000) {
      // 如果日期在未来超过 1 天，视为过期时间且天数差为负
      return Math.ceil(-diffMs / (1000 * 60 * 60 * 24));
    }
    return Math.floor(Math.abs(diffMs) / (1000 * 60 * 60 * 24));
  } catch (e) {
    return -1;
  }
}

/**
 * 解析 RDAP JSON 响应，映射为 WhoisResult 兼容的格式
 *
 * @param {Object} json - RDAP 服务器返回的 JSON 对象
 * @param {string} domain - 查询的域名
 * @returns {Object} 兼容 WhoisResult 的对象
 */
function _parseRdapResponse(json, domain) {
  if (!json || json.objectClassName !== 'domain') {
    throw new Error(`RDAP 响应不是域名对象 (objectClassName=${json?.objectClassName})`);
  }

  // 1. 提取域名
  const ldhName = (json.ldhName || '').toLowerCase();

  // 2. 提取注册日期和过期日期
  const creationTime = _extractEventDate(json.events, 'registration');
  const expirationTime = _extractEventDate(json.events, 'expiration');

  // 3. 计算天数
  const creationDays = _daysFromNow(creationTime);
  const isExpire = !!(expirationTime && new Date(expirationTime).getTime() < Date.now());

  let validDays = -1;
  if (expirationTime) {
    try {
      const expDate = new Date(expirationTime);
      if (!isNaN(expDate.getTime())) {
        const diffMs = expDate.getTime() - Date.now();
        validDays = diffMs > 0 ? Math.ceil(diffMs / (1000 * 60 * 60 * 24)) : 0;
      }
    } catch (e) { /* ignore */ }
  }

  // 4. 提取注册商名称（从 entities 中查找角色为 registrar 的实体的 fn）
  const registrarName = _extractFromEntities(json.entities, 'registrar', 'fn');

  // 5. 提取域名状态列表
  const domainStatus = Array.isArray(json.status) ? json.status : [];

  // 6. 提取 DNS 服务器列表
  const nameServer = [];
  if (Array.isArray(json.nameservers)) {
    for (const ns of json.nameservers) {
      if (ns && ns.ldhName) {
        nameServer.push(ns.ldhName);
      }
    }
  }

  // 7. 提取域名后缀
  const parts = domain.split('.');
  const domainSuffix = parts.length >= 2 ? parts.slice(1).join('.') : (parts[0] || '');

  // 8. 组装结果（兼容 WhoisResult 格式）
  return {
    domain: ldhName || domain,
    domainSuffix,
    creationDays,
    validDays,
    creationTime,
    expirationTime,
    isExpire,
    registrarName,
    domainStatus,
    nameServer,
    queryTime: new Date().toISOString(),

    // RDAP 独有的额外信息（供调试使用）
    _rdap: {
      publication: _bootstrapCache?.publication || '',
      server: json.links?.[0]?.value || '',
      handle: json.handle || '',
      secureDNS: json.secureDNS?.delegationSigned || false
    }
  };
}

// ==================== 公开接口 ====================

export class RdapClient {
  /**
   * 查询域名的 RDAP 注册信息
   *
   * @param {string} domain - 要查询的完整域名（如 "baidu.com" 或 "example.co.uk"）
   * @returns {Promise<Object|null>}
   *   - 成功：返回与 WhoisResult 兼容的对象
   *   - 失败：返回 null（可通过 RdapClient.lastError 获取错误详情）
   */
  static async lookup(domain) {
    if (!domain || typeof domain !== 'string') {
      _lastError = { domain: String(domain || ''), phase: 'invalid', message: 'domain 参数为空' };
      return null;
    }

    const normalizedDomain = domain.toLowerCase().trim();

    // Step 1: 获取引导文件，查找 RDAP 服务器 URL
    const { baseUrl, isFallback, noRdap } = await _getRdapBaseUrl(normalizedDomain);

    // 该 TLD 已知没有公开 RDAP 服务（如 .cn）→ 返回「不支持」哨兵结果，优雅降级
    if (noRdap) {
      _lastError = {
        domain: normalizedDomain,
        phase: 'unsupported',
        message: `该 TLD 没有公开 RDAP 服务，跳过查询`
      };
      console.log(`[RdapClient] 跳过查询（无公开 RDAP）: ${normalizedDomain} (TLD: ${normalizedDomain.split('.').pop()})`);
      return {
        domain: normalizedDomain,
        domainSuffix: normalizedDomain.split('.').slice(1).join('.'),
        creationDays: -1, validDays: -1,
        creationTime: '', expirationTime: '',
        isExpire: false, registrarName: '',
        domainStatus: [], nameServer: [],
        queryTime: new Date().toISOString(),
        _rdap: { unsupported: true }
      };
    }

    if (!baseUrl) {
      _lastError = {
        domain: normalizedDomain,
        phase: 'bootstrap',
        message: `引导文件中未找到该域名的 TLD 对应 RDAP 服务器`
      };
      console.warn(`[RdapClient] ${_lastError.message}: ${normalizedDomain}`);
      return null;
    }

    if (isFallback) {
      console.log(`[RdapClient] 使用回退映射查询: ${normalizedDomain} (TLD: ${normalizedDomain.split('.').pop()})`);
    }

    // Step 2: 构造并尝试 RDAP 查询，支持协议回退
    // 有些 RDAP 服务器仅支持 HTTPS，有些仅支持 HTTP。
    // 先尝试配置的协议，失败则试另一种协议。
    const queryPaths = [
      baseUrl.replace(/\/+$/, '/') + 'domain/' + encodeURIComponent(normalizedDomain)
    ];

    // 生成协议回退 URL（http ↔ https）
    if (baseUrl.startsWith('https://')) {
      queryPaths.push(baseUrl.replace(/^https:/, 'http:') + 'domain/' + encodeURIComponent(normalizedDomain));
    } else if (baseUrl.startsWith('http://')) {
      queryPaths.push(baseUrl.replace(/^http:/, 'https:') + 'domain/' + encodeURIComponent(normalizedDomain));
    }

    /** @type {Object|null} */
    let lastFetchError = null;
    /** @type {Object|null} */
    let response = null;
    /** @type {string} */
    let lastUrl = '';

    for (let attempt = 0; attempt < queryPaths.length; attempt++) {
      const queryUrl = queryPaths[attempt];
      const isProtocolFallback = attempt > 0;
      const protocolLabel = isProtocolFallback
        ? (queryUrl.startsWith('https://') ? 'HTTPS' : 'HTTP')
        : '';

      lastUrl = queryUrl;
      if (isProtocolFallback) {
        console.log(`[RdapClient] 协议回退尝试 ${protocolLabel}: ${queryUrl}`);
      } else {
        console.log(`[RdapClient] 发起 RDAP 查询: ${queryUrl}`);
      }

      // Step 3: 发送查询请求
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), RDAP_REQUEST_TIMEOUT);

        const resp = await fetch(queryUrl, {
          method: 'GET',
          signal: controller.signal,
          headers: { 'Accept': 'application/rdap+json, application/json' }
        });

        clearTimeout(timeoutId);

        // Step 4: 检查 HTTP 状态码
        if (!resp.ok) {
          const msg = resp.status === 404
            ? '域名在 RDAP 中未找到（可能未注册）'
            : `RDAP 服务器返回 HTTP ${resp.status}`;
          console.warn(`[RdapClient] ${msg}: ${normalizedDomain} (HTTP ${resp.status})`);

          if (resp.status === 404) {
            return {
              domain: normalizedDomain,
              domainSuffix: normalizedDomain.split('.').slice(1).join('.'),
              creationDays: -1, validDays: -1,
              creationTime: '', expirationTime: '',
              isExpire: false, registrarName: '',
              domainStatus: [], nameServer: [],
              queryTime: new Date().toISOString(),
              _rdap: { notFound: true }
            };
          }

          // 非 404 仅在最后一次尝试时返回失败
          if (attempt === queryPaths.length - 1) {
            _lastError = { domain: normalizedDomain, phase: 'http_status', message: msg, statusCode: resp.status };
            return null;
          }
          continue;
        }

        response = resp;
        lastFetchError = null;
        break; // 成功，跳出循环
      } catch (error) {
        lastFetchError = error;
        if (error.name === 'AbortError') {
          console.warn(`[RdapClient] RDAP 查询超时 (${protocolLabel || 'primary'}): ${normalizedDomain}`);
        } else {
          console.warn(`[RdapClient] RDAP 查询失败 (${protocolLabel || 'primary'}): ${normalizedDomain} (${error.message})`);
        }
        // 继续尝试下一个 URL
      }
    }

    // 所有尝试均失败
    if (lastFetchError) {
      const error = lastFetchError;
      if (error.name === 'AbortError') {
        _lastError = { domain: normalizedDomain, phase: 'timeout', message: `请求超时 (${RDAP_REQUEST_TIMEOUT}ms)` };
      } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
        _lastError = { domain: normalizedDomain, phase: 'connect', message: `网络连接失败: ${error.message}` };
      } else {
        _lastError = { domain: normalizedDomain, phase: 'connect', message: `请求异常: ${error.message}` };
      }
      return null;
    }

    // 检查 response 非空（防御性编程）
    if (!response) {
      _lastError = { domain: normalizedDomain, phase: 'connect', message: 'RDAP 查询未知错误' };
      return null;
    }

    // Step 5: 解析 JSON 响应
    let json;
    try {
      json = await response.json();
    } catch (e) {
      _lastError = { domain: normalizedDomain, phase: 'parse', message: `JSON 解析失败: ${e.message}`, url: lastUrl };
      return null;
    }

    // Step 6: 解析并返回
    try {
      const result = _parseRdapResponse(json, normalizedDomain);
      _lastError = null;
      console.log(`[RdapClient] RDAP 查询成功: ${normalizedDomain} (注册: ${result.creationTime || '?'}, 过期: ${result.expirationTime || '?'}, 注册商: ${result.registrarName || '?'})`);
      return result;
    } catch (e) {
      _lastError = { domain: normalizedDomain, phase: 'parse', message: `RDAP 响应解析失败: ${e.message}`, url: lastUrl };
      return null;
    }
  }

  /**
   * 获取上次错误的详情
   * @returns {Object|null}
   */
  static get lastError() {
    return _lastError;
  }

  /**
   * 清空错误信息
   */
  static clearLastError() {
    _lastError = null;
  }

  /**
   * 重新加载 RDAP 引导文件（清除缓存）
   * @returns {Promise<void>}
   */
  static async refreshBootstrap() {
    _clearBootstrapCache();
    await _ensureBootstrap();
  }

  /**
   * 获取引导文件缓存状态
   * @returns {Object} { loaded, tldCount, publication, ageMs }
   */
  static getBootstrapStatus() {
    if (!_bootstrapCache) {
      return { loaded: false, tldCount: 0, publication: '', ageMs: -1 };
    }
    return {
      loaded: true,
      tldCount: _bootstrapCache.tldToServer.size,
      publication: _bootstrapCache.publication,
      ageMs: Date.now() - _bootstrapCache.timestamp
    };
  }
}

// ==================== 内部状态 ====================

/** @type {Object|null} 最近一次查询失败的错误详情 */
let _lastError = null;
