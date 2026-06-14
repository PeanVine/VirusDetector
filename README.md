# Virus Detector - 银狐木马检测

> Chrome/Edge 浏览器扩展，实时检测银狐木马（Silver Fox Trojan）钓鱼与仿冒网站。

[![Manifest](https://img.shields.io/badge/Manifest-V3-blue)](https://developer.chrome.com/docs/extensions/mv3/)
[![Version](https://img.shields.io/badge/Version-1.2.2-orange)](https://github.com)

---

## 功能简介

通过 5 条评分规则对访问的网站进行实时安全评估。当总分达到 100 分阈值时，自动触发红色警告、桌面通知、下载拦截和警告弹窗。

| 规则 | 最高加分 | 检测内容 |
| ---- | -------- | -------- |
| 域名仿冒 | **60** | 5 层递进匹配（子串包含、段级关键词、可疑 TLD、关键词堆叠、编辑距离） |
| 压缩包下载 | **40** | 从可疑站点下载压缩包（`.zip` `.rar` `.7z` 等）自动取消并加分 |
| ICP 备案缺失 | **50** | 对所有网站检测 ICP 备案号（含 beian.gov.cn 等政府链接提取） |
| 链接分析 | **70** | Part A（同页链接/死链/重复链接）+ Part B（下载按钮/压缩包链接） |
| 代码工程化 | **30** | 无外部资源（静态空壳）或 有外部资源但代码质量差 |

**附加功能**：

- **白名单** — 信任的网站可加入白名单，跳过所有检测
- **官方网站早期退出** — 域名+ICP 均通过检测后自动跳过后续规则
- **下载拦截** — 危险网站自动注入拦截脚本，禁用下载按钮和危险链接
- **警告弹窗** — 独立窗口展示风险详情，支持一键跳转官方网站并关闭危险页面

---

## 安装方式

### Chrome

1. 下载本项目源码或 `git clone`
2. 打开 `chrome://extensions/`
3. 开启右上角「开发者模式」
4. 点击「加载已解压的扩展程序」
5. 选择项目根目录 `ViriusDetector/`

### Edge

1. 下载本项目源码或 `git clone`
2. 打开 `edge://extensions/`
3. 开启「开发人员模式」
4. 点击「加载解压缩的扩展」
5. 选择项目根目录 `ViriusDetector/`

---

## 项目结构

```text
ViriusDetector/
├── manifest.json                      # Manifest V3 扩展清单
├── README.md
├── icons/                             # 盾牌图标（16/32/48/128 px）
├── background/
│   ├── service-worker.js              # 主协调器 —— 导航监听、下载拦截、消息路由、弹窗调度
│   ├── scoring-engine.js              # 5 规则评分引擎 —— 综合评估与风险定级
│   ├── domain-database.js             # 121 品牌域名数据库 + 仿冒检测（4 层匹配）
│   ├── cache-manager.js               # chrome.storage.local 缓存管理（24h TTL）
│   ├── similarity.js                  # SimHash 64 位文本相似度 + 海明距离
│   └── icp-utils.js                   # ICP 备案号正则匹配（覆盖 34 个省级行政区简称）
├── content/
│   └── content-script.js              # 内容脚本 —— 链接采集、ICP 扫描、页面度量采集
├── popup/
│   ├── popup.html                     # 工具栏弹窗 UI
│   ├── popup.css                      # 弹窗样式（深色主题、SVG 图标系统）
│   └── popup.js                       # 弹窗控制逻辑 —— 状态渲染、白名单操作
├── warning/
│   ├── warning.html                   # 独立警告窗口 UI
│   ├── warning.css                    # 警告窗口样式
│   └── warning.js                     # 警告窗口控制 —— 关闭危险页面、跳转安全页面
└── utils/
    ├── constants.js                   # 评分常量、可疑 TLD 模式、下载关键词、阈值配置
    ├── url-utils.js                   # 域名解析、主域提取、嵌套 TLD 检测
    └── messaging.js                   # chrome.runtime 消息通信封装
```

### 技术特点

- **零依赖**：纯原生 JavaScript（ES Modules），无需 Node.js 构建
- **Manifest V3**：使用 Service Worker 事件驱动架构
- **通信模型**：Background (Service Worker) ↔ Content Script ↔ Popup 三方消息传递
- **算法**：SimHash 64 位 + Levenshtein 编辑距离用于文本相似度与域名仿冒检测

---

## 实现方式

### 防御策略

#### 1. 域名仿冒检测（规则一 | 60 分）

采用 5 层递进式匹配，任一层命中即判定为仿冒：

```text
策略1   子串包含   → pc-huorong.com.cn 包含 huorong.com → 命中
策略2   段级关键词 → deepseek-go.com 拆分 → "deepseek" 命中品牌关键词
策略3   可疑TLD    → huorong-download.xyz → .xyz 为可疑 TLD + 含品牌关键词
策略3.5 关键词堆叠 → google-google-cn-google.hl.cn → "google" 在段中出现 3 次
策略4   编辑距离   → qq.om 与 qq.com 的 Levenshtein 距离 = 1 → 命中
```

域名数据库覆盖 **121 个**品牌，包含 19 个类别：安全软件、浏览器、即时通讯、输入法、办公、视频、音乐、云存储、AI Chat、下载工具、压缩工具、电商、地图出行、支付、开发者工具、系统工具、游戏平台、游戏加速器、新闻资讯。

#### 2. 下载拦截（规则二 | 最高 40 分）

通过 `chrome.downloads.onCreated` 监听下载事件：

- 检测到压缩包文件（含 33 种扩展名）→ 规则二触发
- 若域名已有 >= 30 分嫌疑 → **+40 分**并取消下载
- 弱信号 → **+10 分**（仅记录，不取消）

高危时自动注入拦截脚本到页面：

- 禁用所有含"下载 / Download"文本的按钮和链接
- 拦截指向 `.exe` `.zip` `.rar` `.msi` `.apk` 等危险文件的点击
- 移除 `<a download>` 属性
- 页面顶部注入红色警告横幅
- 使用 `MutationObserver` 持续监控动态加载的按钮（30 秒窗口）

#### 3. ICP 备案号检测（规则三 | 50 分）

对所有网站进行 ICP 备案号检测，使用正则匹配覆盖中国全部 34 个省级行政区简称：

- 完整的 ICP 备案号格式：`{省份}ICP{备|证}{6-8位数字}号`
- 同时识别公安备案号：`{省份}公网安备{10+位数字}号`
- Content Script 通过 6 层扫描获取页面中所有可能包含备案号的文本：footer 元素、ICP/beian 命名元素、底部 30% 区域、所有 `<a>` 链接（含 beian.gov.cn / beian.miit.gov.cn 等政府备案链接）、position:fixed 底部固定栏、TreeWalker 全文本节点遍历（上限 50000 节点）

#### 4. 链接分析（规则四 | 最高 70 分）

Part A（先执行，可叠加）：

| 子规则 | 触发条件 | 加分 |
| ------ | -------- | ---- |
| A-1 同页链接 | >= 3 个链接指向当前页（完整 URL 完全一致） | +20 |
| A-2 死链 | >= 1 个指向不存在子页面的链接（HEAD 请求验证） | +20 |
| A-3 重复链接 | >= 4 个不同元素指向同一个链接 | +20 |
| A-3 附加 | 该重复链接为下载链接（含 download/down 等关键词） | +10 |

Part B（仅当 Part A 为 0 时执行）：

| 子规则 | 触发条件 | 加分 |
| ------ | -------- | ---- |
| B-a 下载按钮 | 外链绑定在下载按钮上 | +10 |
| B-b 压缩包链接 | 外链指向压缩包格式文件 | +10 |

#### 5. 代码工程化检测（规则五 | 30 分）

前提：页面文本 > 500 字符（排除空白/占位页面）。

两步递进判定：

1. **无外部资源** — 页面不含任何云上/服务器资源（外部脚本、样式、图片、字体、媒体均为零）→ 直接判定为静态空壳钓鱼页（+30）
2. **有外部资源但代码质量差** — 存在外部资源前提下，满足以下任一条件即触发（+30）：
   - HTML 行数 < 300
   - 无主流框架痕迹（React/Vue/Angular/jQuery 等）
   - 外部资源总数 < 5（脚本 + 样式 + 图片 + 字体 + 媒体）

### 评分体系

```text
规则一  域名仿冒        +60 ──→
规则二  压缩包下载      +40 ──→
规则三  ICP 备案缺失    +50 ──→ 总分 >= 100 ?
规则四  链接分析        +70 ──→   ├── YES → 红色徽章 + 桌面通知 + 警告弹窗 + 下载拦截注入
规则五  代码工程化      +30 ──→   └── NO  → 绿色徽章显示分数

优化：规则一 + 规则三均安全 → 跳过规则四/五（官方网站早期退出）
```

### 插件功能

#### 白名单系统

用户可将信任的网站加入白名单：

- 工具栏弹窗中点击「加入白名单」→ 域名被持久化到 `chrome.storage.local`
- 白名单中的网站**完全跳过所有 5 条规则检测**
- 工具栏图标右下角显示蓝色对勾徽章
- 弹窗显示绿色对勾 + 提示文字
- 支持一键移出白名单并立即重新触发检测

#### 缓存策略

- 检测结果缓存于 `chrome.storage.local`，TTL = 24 小时
- Content Script 发回新数据时自动绕过缓存更新
- 清除白名单时同步清除对应域名的缓存

#### 弹窗去重

- 同一标签页 5 秒冷却期，避免重复弹窗
- 同域名不重复弹出警告窗口

#### 消息通信

12 种消息类型覆盖 Background ↔ Content Script ↔ Popup 三方通信：

| 消息类型 | 方向 | 用途 |
| -------- | ---- | ---- |
| `PAGE_ANALYSIS_RESULT` | Content → Background | 页面分析数据上报 |
| `REQUEST_PAGE_TEXT` | Background → Content | 请求重新采集页面数据 |
| `GET_TAB_STATE` | Popup → Background | 查询当前标签页状态 |
| `ADD_TO_WHITELIST` | Popup → Background | 添加域名到白名单 |
| `REMOVE_FROM_WHITELIST` | Popup → Background | 从白名单移除域名 |
| `CHECK_WHITELIST` | Popup → Background | 查询域名是否在白名单 |

---

## 所需权限

| 权限 | 用途 |
| ---- | ---- |
| `activeTab` | 读取当前活跃标签页信息 |
| `storage` | 持久化评分状态、白名单、缓存 |
| `downloads` | 监听下载事件、取消危险下载 |
| `scripting` | 注入 Content Script 与下载拦截脚本 |
| `alarms` | 定时任务支持 |
| `notifications` | 桌面风险通知 |
| `webNavigation` | 监听页面导航以触发分析 |
| `<all_urls>` | 全部网站覆盖（检测与注入所需） |

---

## 开发说明

### 代码注释规范

所有模块均包含文件级 JSDoc 注释块，说明模块职责与核心逻辑。关键函数包含参数、返回值和使用说明。

### 扩展调试

1. 打开 `chrome://extensions/`
2. 找到本扩展，点击「Service Worker」链接查看后台日志
3. 右键扩展图标 →「检查弹出内容」查看弹窗调试信息

### 图标系统

弹窗 UI 使用内联 SVG 图标系统，定义在 `popup/popup.js` 的 `ICONS` 常量中。所有图标均可通过修改对应 SVG 字符串来更换，无需依赖外部资源。

---

## License

MIT
