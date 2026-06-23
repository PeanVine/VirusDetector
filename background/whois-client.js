/**
 * Virus Detector — 域名注册信息查询客户端 (Whois Client)
 *
 * 基于 RDAP 协议（RFC 9082/9083）的域名注册信息查询模块。
 * 底层委托 RdapClient 进行 RDAP 查询，上层提供带内存缓存和错误管理的封装，
 * 供评分引擎和服务工作线程使用。
 *
 * 查询链路：
 *   WhoisClient.lookup(domain)
 *     → RdapClient.lookup(domain)        // RDAP 协议查询
 *       → IANA 引导文件 → RDAP 服务器 → 域名信息
 *     → 缓存管理 / 错误统一处理
 *
 * @module whois-client
 * @version 2.2.3
 *
 * 缓存策略：
 *   - 内存 Map 缓存，TTL = 24 小时（由 constants.js 中的 WHOIS_CACHE_TTL 配置）
 *   - 缓存命中直接返回，不发起 RDAP 查询
 *   - RDAP 查询失败（网络错误、超时、HTTP 异常）不缓存，下次请求重试
 *   - RDAP 查询返回 404（域名未注册）也不缓存
 *
 * 与旧版 WhoisCX API 的区别：
 *   - 无速率限制（RDAP 服务器无 2 秒间隔限制）
 *   - 数据来源于注册局官方 RDAP 服务，更准确可靠
 *   - 支持所有 TLD（只要 IANA 引导文件中有对应条目）
 *   - 使用 HTTPS（旧版 WhoisCX 仅支持 HTTP）
 */

import { WHOIS_CACHE_TTL } from '../utils/constants.js';
import { RdapClient } from './rdap-client.js';
import { UrlUtils } from '../utils/url-utils.js';

// ==================== 内存缓存 ====================

/**
 * @typedef {Object} WhoisCacheEntry
 * @property {WhoisResult} result    - 缓存的查询结果
 * @property {number}      timestamp - 缓存时间戳
 */

/** @type {Map<string, WhoisCacheEntry>} */
const _cache = new Map();

// ==================== 错误信息记录 ====================

/** @type {WhoisErrorInfo|null} 最近一次查询失败的错误详情 */
let _lastError = null;

/**
 * 记录错误信息并输出到控制台
 * @param {string} domain     - 查询的域名
 * @param {string} phase      - 失败阶段
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
    'bootstrap':  'RDAP 引导文件错误',
    'connect':    'RDAP 网络连接失败',
    'http_status': 'RDAP HTTP 状态异常',
    'parse':      'RDAP 响应解析失败',
    'timeout':    'RDAP 请求超时',
    'not_found':  '域名未注册',
    'invalid':    '参数无效'
  }[phase] || phase;

  const extraSummary = Object.keys(extra).length ? JSON.stringify(extra) : '';
  console.error(`[WhoisClient] ${phaseLabel} (${domain}): ${message}${extraSummary ? ' | ' + extraSummary : ''}`);
}

// ==================== 辅助函数 ====================

/**
 * 从 ISO 8601 日期字符串计算已注册天数
 * @param {string} timeStr - ISO 8601 日期字符串（如 "1999-10-11T11:05:17Z"）
 * @returns {number} 天数，解析失败返回 -1
 */
function _parseDaysFromTime(timeStr) {
  if (!timeStr || typeof timeStr !== 'string') return -1;
  try {
    const date = new Date(timeStr);
    if (isNaN(date.getTime())) return -1;
    const diffMs = Date.now() - date.getTime();
    if (diffMs < 0) return -1;
    return Math.floor(diffMs / (1000 * 60 * 60 * 24));
  } catch (e) {
    return -1;
  }
}

// ==================== 公开接口 ====================

export class WhoisClient {
  /**
   * 查询域名的注册信息（通过 RDAP 协议）
   *
   * @param {string} domain - 要查询的完整域名（如 "example.com"）
   * @returns {Promise<WhoisResult|null>} 查询结果，失败时返回 null
   *   （可通过 WhoisClient.lastError 获取失败详情）
   */
  static async lookup(domain) {
    // 1. 参数校验
    if (!domain || typeof domain !== 'string') {
      _recordError(String(domain || ''), 'invalid', 'domain 参数为空或类型错误', { domain });
      return null;
    }

    // 2. 规范化域名：基于 PSL 提取可注册域名
    const rawDomain = domain.toLowerCase().trim();
    const normalizedDomain = UrlUtils.getMainDomain(rawDomain);

    if (!normalizedDomain || !normalizedDomain.includes('.')) {
      _recordError(normalizedDomain || domain, 'invalid', '域名格式无效', { domain });
      return null;
    }

    if (normalizedDomain !== rawDomain) {
      console.log(`[WhoisClient] PSL 域名提取: ${rawDomain} -> ${normalizedDomain}`);
    }

    // 3. 检查缓存
    const cached = _cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.timestamp) < WHOIS_CACHE_TTL) {
      const ageLabel = cached.result.creationDays >= 0 ? `注册${cached.result.creationDays}天` : '注册天数未知';
      console.log(`[WhoisClient] 缓存命中: ${normalizedDomain} (${ageLabel})`);
      return cached.result;
    }

    // 4. 通过 RdapClient 发起 RDAP 查询
    console.log(`[WhoisClient] 发起 RDAP 查询: ${normalizedDomain}`);
    const rdapResult = await RdapClient.lookup(normalizedDomain);

    // 5. 处理 RDAP 查询失败
    if (!rdapResult) {
      const errInfo = RdapClient.lastError;
      const errPhase = errInfo ? ` [${errInfo.phase}]` : '';
      const errMsg = errInfo ? errInfo.message : '';
      _recordError(normalizedDomain, errInfo?.phase || 'connect', errMsg || 'RDAP 查询返回空结果');
      return null;
    }

    // 6. 处理「该 TLD 无公开 RDAP 服务」（如 .cn）→ 优雅降级，缓存避免重复查询
    if (rdapResult._rdap?.unsupported) {
      const suffix = normalizedDomain.split('.').slice(1).join('.');
      const tld = normalizedDomain.split('.').pop();
      const result = {
        domain: normalizedDomain, domainSuffix: suffix,
        creationDays: -1, validDays: -1,
        creationTime: '', expirationTime: '',
        isExpire: false, registrarName: '',
        domainStatus: [], nameServer: [],
        queryTime: rdapResult.queryTime || new Date().toISOString(),
        _unsupported: true
      };
      // 缓存哨兵结果，避免同一会话内对该 TLD 域名反复发起查询
      _cache.set(normalizedDomain, { result, timestamp: Date.now() });
      _lastError = null;
      console.log(`[WhoisClient] 跳过查询（.${tld} 无公开 RDAP 服务）: ${normalizedDomain}`);
      return result;
    }

    // 7. 处理 RDAP 404（域名在注册局 RDAP 中未找到）
    if (rdapResult._rdap?.notFound) {
      // 不缓存 404 结果（域名今后可能被注册）
      console.warn(`[WhoisClient] 域名在 RDAP 中未找到（可能未注册）: ${normalizedDomain}`);
      _recordError(normalizedDomain, 'not_found', '域名在 RDAP 中未找到（可能未注册）');
      return null;
    }

    // 8. 映射 RDAP 结果 → WhoisResult 格式
    const result = {
      domain: rdapResult.domain || normalizedDomain,
      domainSuffix: rdapResult.domainSuffix || '',
      creationDays: rdapResult.creationDays,
      validDays: rdapResult.validDays,
      creationTime: rdapResult.creationTime || '',
      expirationTime: rdapResult.expirationTime || '',
      isExpire: rdapResult.isExpire || false,
      registrarName: rdapResult.registrarName || '',
      domainStatus: rdapResult.domainStatus || [],
      nameServer: rdapResult.nameServer || [],
      queryTime: rdapResult.queryTime || ''
    };

    // 9. 写入缓存（仅当 creationDays 有效时缓存）
    if (result.creationDays > 0) {
      _cache.set(normalizedDomain, { result, timestamp: Date.now() });
      console.log(`[WhoisClient] 缓存写入: ${normalizedDomain} (creationDays=${result.creationDays})`);
    } else {
      console.log(`[WhoisClient] 跳过缓存: ${normalizedDomain} (creationDays=${result.creationDays})`);
    }

    _lastError = null;

    const ageLabel = result.creationDays >= 0 ? `注册 ${result.creationDays}d` : '注册时间未知';
    const validLabel = result.validDays >= 0 ? `到期 ${result.validDays}d` : '有效期未知';
    console.log(`[WhoisClient] RDAP 查询成功: ${normalizedDomain} (${ageLabel}, ${validLabel}, 注册商: ${result.registrarName || '未知'})`);
    return result;
  }

  /**
   * 从缓存中获取查询结果（不发起网络请求）
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

  /**
   * 获取上次查询失败的错误详情
   * @returns {WhoisErrorInfo|null}
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
   * 清除指定域名的缓存
   * @param {string} domain
   */
  static clearCache(domain) {
    if (domain) {
      _cache.delete(UrlUtils.getMainDomain(domain.toLowerCase().trim()));
    }
  }

  /**
   * 清空所有缓存
   */
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
 * @property {string}   creationTime  - 域名创建时间（ISO 8601 格式）
 * @property {string}   expirationTime - 域名到期时间（ISO 8601 格式）
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
