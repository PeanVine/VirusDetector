/**
 * Virus Detector — 全局常量配置
 *
 * 集中管理评分阈值、检测关键词、TLD 模式、消息类型、
 * 存储键名和缓存策略。所有模块通过 import 共用同一份配置。
 *
 * @module constants
 * @version 1.2.1
 */

// ==================== 评分体系 ====================
/** 触发警告的总分阈值 */
export const SCORE_THRESHOLD = 100;

// 新规则分值
export const SCORE_RULE_1 = 60;              // 规则一：域名仿冒
export const SCORE_RULE_2_HIGH = 40;         // 规则二：压缩包下载（域名已有≥30嫌疑）
export const SCORE_RULE_2_LOW = 10;          // 规则二：压缩包下载（弱信号）
export const SCORE_RULE_3 = 50;             // 规则三：ICP备案号缺失（所有网站）

// 规则四：链接分析（替代证书检测）
export const SCORE_RULE_4A_SAME_PAGE = 20;      // 规则四A-① ≥3个链接指向当前页本身（完全一致URL）
export const SCORE_RULE_4A_DEAD_LINK = 20;      // 规则四A-② ≥1个死链（指向不存在子页面的链接）
export const SCORE_RULE_4A_DUPLICATE_LINK = 20; // 规则四A-③ ≥4个不同元素指向同一个链接
export const SCORE_RULE_4A_DOWNLOAD_LINK_BONUS = 10; // 规则四A-③附加 该链接是下载链接（含download等字样）
export const SCORE_RULE_4B_DOWNLOAD_BTN = 10;   // 规则四B-a 外链绑在下载按钮上
export const SCORE_RULE_4B_FILE_LINK = 10;      // 规则四B-b 外链指向文件
export const SCORE_RULE_4B_ARCHIVE_LINK = 10;   // 规则四B-b附加 文件是压缩包格式

export const SCORE_RULE_5 = 30;              // 规则五：代码工程化 — 高度可疑（3/3信号）
export const SCORE_RULE_5_PARTIAL = 20;      // 规则五：代码工程化 — 中度可疑（2/3信号）

// 规则二触发阈值：域名嫌疑分达到此值才给高分
export const RULE_2_DOMAIN_SUSPICION_THRESHOLD = 30;

// ==================== 风险等级 ====================
export const RISK_LEVEL = {
  SAFE: 'safe',
  WARNING: 'warning'
};

// ==================== 压缩包扩展名 ====================
export const ARCHIVE_EXTENSIONS = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tar.gz', '.tgz',
  '.bz2', '.xz', '.z', '.iso', '.cab', '.arj', '.lzh',
  '.tar.bz2', '.tar.xz', '.gz2', '.zst'
]; 

// ==================== 可疑TLD模式 ====================
export const SUSPICIOUS_TLD_PATTERNS = [
  /\.cn\.com$/i,
  /\.cn\.org$/i,
  /\.cn\.net$/i,
  /\.com\.cn\.com$/i,
  /\.top\.com$/i,
  /\.xyz$/i,
  /\.top$/i,
  /\.work$/i,
  /\.click$/i,
  /\.link$/i,
  /\.download$/i,
  /\.zip$/i,
  /\.review$/i,
  /\.country$/i,
  /\.kim$/i,
  /\.cn\.[a-z]{2,}$/i,
  /\.gq$/i,
  /\.ml$/i,
  /\.cf$/i,
  /\.ga$/i,
  /\.tk$/i
];

// ==================== 规则四：链接分析 ====================
// 链接指向当前页的判断阈值
export const SAME_PAGE_LINK_THRESHOLD = 5;    // ≥5个同页链接 → 触发①

// 重复链接检测阈值（规则四A-③）
export const DUPLICATE_LINK_THRESHOLD = 4;    // ≥4个不同元素指向同一个链接 → 触发③

// 下载链接检测关键词（规则四A-③附加分）
export const DOWNLOAD_LINK_KEYWORDS = [
  'down', 'download', '下載', '下载', 'dl', 'get', 'setup', 'install',
  'free', 'app', 'exe', 'msi', 'dmg', 'apk', 'zip', 'rar', '7z'
];

// 下载语义关键词（判断链接是否绑在下载按钮上）
export const DOWNLOAD_BUTTON_KEYWORDS = [
  '下载', 'download', '下載', '立即下载', '免费下载', '高速下载',
  '安全下载', '点击下载', '直接下载', '本地下载', '官方下载',
  'Download Now', 'Free Download', 'Download Free',
  '立即安装', '一键安装', '安装包'
];

// 文件扩展名（规则四B-b）
export const FILE_EXTENSIONS = [
  '.exe', '.msi', '.dmg', '.apk', '.appx', '.deb', '.rpm',
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
  '.iso', '.cab', '.arj', '.lzh', '.z', '.zst',
  '.bat', '.cmd', '.ps1', '.vbs', '.scr', '.jar',
  '.bin', '.run', '.sh', '.pkg'
];

// 单独列出压缩包扩展名（用于规则四B-b的附加分）
export const ARCHIVE_EXTENSIONS_RULE4 = [
  '.zip', '.rar', '.7z', '.tar', '.gz', '.tgz', '.bz2', '.xz',
  '.iso', '.cab', '.arj', '.lzh', '.z', '.zst'
];

// ==================== 代码工程化检测（规则五） ====================
export const AI_PAGE_THRESHOLDS = {
  MIN_DOM_NODES: 100,             // DOM节点数低于此值为可疑（替代HTML行数，不受代码格式化影响）
  MIN_EXTERNAL_RESOURCES: 5,      // 外部资源去重总数（脚本+样式+图片+字体+媒体）低于此值为可疑
  MIN_TEXT_LENGTH: 500,           // 页面文本需大于此值才进入检测
  RULE_5_SIGNALS_FULL: 3,         // 命中3个信号 → 高度可疑 +30
  RULE_5_SIGNALS_PARTIAL: 2       // 命中2个信号 → 中度可疑 +20
};

// 主流框架标记 — HTML源码字符串匹配用（content-script 使用此列表做全文搜索）
export const FRAMEWORK_HTML_MARKERS = [
  'react', 'vue', 'angular', 'webpack', '__initial_state__',
  '_next/', 'nuxt', 'svelte', 'jquery', 'bootstrap',
  'node_modules', '.jsx', '.tsx', 'data-v-', 'ng-version',
  '__vue__', '__react', 'redux', 'react-dom', 'vue-router',
  'webpackjsonp', '__webpack_require__', '__nuxt', '__next'
];

// ==================== 消息类型 ====================
export const MSG_TYPES = {
  PAGE_ANALYSIS_RESULT: 'PAGE_ANALYSIS_RESULT',
  GET_TAB_STATE: 'GET_TAB_STATE',
  DOWNLOAD_DETECTED: 'DOWNLOAD_DETECTED',
  ICP_SCAN_RESULT: 'ICP_SCAN_RESULT',
  REQUEST_PAGE_TEXT: 'REQUEST_PAGE_TEXT',
  UPDATE_SCORE: 'UPDATE_SCORE',
  GET_OFFICIAL_LINK: 'GET_OFFICIAL_LINK',
  CLEAR_TAB_STATE: 'CLEAR_TAB_STATE',
  INJECT_DOWNLOAD_BLOCKER: 'INJECT_DOWNLOAD_BLOCKER',
  TRIGGER_WARNING_FLOW: 'TRIGGER_WARNING_FLOW',
  ADD_TO_WHITELIST: 'ADD_TO_WHITELIST',
  REMOVE_FROM_WHITELIST: 'REMOVE_FROM_WHITELIST',
  CHECK_WHITELIST: 'CHECK_WHITELIST'
};

// ==================== 存储键 ====================
export const STORAGE_KEYS = {
  TAB_STATE_PREFIX: 'tab_state_',
  DOMAIN_CACHE: 'domain_cache_',
  SSL_CACHE: 'ssl_cache_',
  GLOBAL_SETTINGS: 'global_settings',
  WHITELIST: 'whitelist'
};

// 缓存有效期（毫秒）
export const CACHE_TTL = 24 * 60 * 60 * 1000;  // 24小时
