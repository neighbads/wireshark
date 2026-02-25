# Wireshark 增强版

基于 Wireshark 官方源码的定制增强版本，专注于改善日常抓包分析的操作效率和用户体验。

> 原始 README 已保存至 [README.md.old](README.md.old)。

## 说明

本分支在上游 Wireshark 基础上，针对 Qt GUI 进行了一系列实用性增强，主要方向包括：

- 为高频操作添加工具栏快捷按钮，减少右键菜单层级
- 改进 Conversation / Expert Info 等对话框的交互体验
- 添加中文（zh_CN）翻译
- 完善 GitHub Actions CI/CD 流程，支持自动构建和发布

## 功能计划

- [x] 工具栏常用按钮
  - [x] 追踪流按钮、追踪流新窗口开关按钮
  - [x] 内容拷贝按钮（Copy CSV / Hex Stream / Detailed Text）
  - [x] 会话着色按钮（Colorize Conversation 1-5）
  - [x] 多选数据包批量复制
  - [ ] 自定义工具栏按钮配置界面
- [x] 分析 - 专家信息窗口增强
  - [x] 双击展开/折叠、Follow Stream 右键菜单、双击跟踪流
  - [x] 显示过滤器与主窗口同步
- [x] 统计 - 会话窗口增强
  - [x] Follow Stream 右键菜单、双击跟踪流、忽略外部 retap
  - [x] 显示过滤器与主窗口同步
- [x] 默认配置文件（TCP Analysis）
  - [x] StreamId 列 + YYYY-MM-DD 时间格式
  - [x] 默认显示过滤器按钮（TCP Reset / Retrans / TLS Alert）
- [x] GitHub Actions 版本发布
  - [x] 自动构建与 tag 自动发布
  - [x] PortableApps 便携版打包
  - [x] 可配置软件更新地址
- [x] 中英文翻译
  - [x] 部分界面元素 zh_CN 翻译
  - [ ] 完整的 zh_CN 翻译覆盖

## 功能详细说明

### 1. 常用按钮添加

在主工具栏添加了常用数据包操作的快捷按钮，无需通过右键菜单即可快速执行。

#### 1.1 追踪流按钮

- **Follow Stream** — 一键跟踪当前数据包所属的流
- **Follow Stream Window 开关** — 可切换按钮，控制是否弹出流跟踪窗口：
  - 按钮按下时，Follow Stream 操作正常弹出流跟踪窗口
  - 按钮弹起时，仅应用过滤器而不弹出窗口，适合只想快速过滤的场景
  - 提供独立的 `x-follow-stream-window` 图标，与普通 Follow Stream 图标区分

#### 1.2 内容拷贝按钮

- **Copy as CSV** — 将选中数据包信息复制为 CSV 格式
- **Copy Hex Stream** — 复制数据包的十六进制流
- **Copy Detailed Text** — 复制数据包的详细协议树文本，支持多选数据包批量复制
  - 自动折叠 Frame 和链路层顶层节点，只显示摘要行，减少冗余

#### 1.3 会话着色按钮

- **Colorize Conversation (1-5)** — 快速为会话着色标记
- 着色按钮图标在颜色过滤器加载完成后自动刷新，确保显示正确的颜色

### 2. 分析 - 专家信息窗口增强

对 Expert Information（分析 → 专家信息）对话框进行了交互改进：

- **双击展开/折叠** — 双击严重级别分组行可切换展开/折叠状态
- **Follow Stream 右键菜单** — 右键点击专家信息条目，根据当前数据包的协议层动态构建 Follow Stream 子菜单
- **双击跟踪流** — 双击非分组行的专家信息条目，自动跳转到对应数据包并执行 Follow Stream；若目标数据包被当前过滤器过滤，会自动清除过滤器后重试
- **显示过滤器同步** — 主窗口过滤器变更时，对话框的过滤器标签和"Limit to display filter"状态自动更新

### 3. 统计 - 会话窗口增强

对 Conversation（统计 → 会话）对话框进行了多项交互改进：

- **Follow Stream 右键菜单** — 右键点击会话行，动态显示该会话支持的 Follow 协议（TCP/UDP/TLS 等），点击即可跟踪对应流
- **双击跟踪流** — 双击会话行直接触发 Follow Stream，自动选择匹配的协议
- **忽略外部 retap** — 当"Limit to display filter"未勾选时，外部操作触发的 retap 不会清空对话框数据
- **默认绝对时间** — 会话对话框默认勾选绝对时间显示
- **显示过滤器同步** — 主窗口过滤器变更时，对话框的过滤器标签自动更新

### 4. 默认配置文件（TCP Analysis）

- 新增 **TCP Analysis** 配置文件（Profile），包含：
  - `tcp.stream` 自定义列（StreamId）
  - `YYYY-MM-DD` 绝对时间格式
- 添加默认显示过滤器按钮：**TCP_Reset**、**TCP_Retrans**、**TLS_Alert**，方便快速过滤常见问题流量

### 5. GitHub Actions 版本发布

- **自动发布** — tag 推送时自动创建 GitHub Release，包含安装包、PortableApps 便携包和 `stable.xml` appcast
- **PortableApps 构建** — 在 CI 中集成 PortableApps 便携版打包
- **可配置更新地址** — 支持通过 `SOFTWARE_UPDATE_FULL_URL` / `SOFTWARE_UPDATE_BASE_URL` 环境变量配置自定义更新服务器
- **多平台发布上传** — Ubuntu、macOS、MSYS2 工作流均添加了 release 上传步骤

### 6. 中英文翻译

补充了以下界面元素的中文（zh_CN）翻译：

- "Display raw data"（显示原始数据）
- "Follow Stream…"（跟踪流…）
- "Graph…"（图表…）
- "I/O Graphs"（I/O 图表）
- Follow Stream 相关工具提示
- 工具栏按钮提示文本

## 构建

```bash
mkdir build && cd build
cmake -GNinja ..
ninja
```

详细构建说明请参考 [INSTALL](INSTALL) 和 [Developer's Guide](https://www.wireshark.org/docs/wsdg_html_chunked/)。

## 许可证

Wireshark 基于 GNU GPLv2 发布，详见 [COPYING](COPYING)。
