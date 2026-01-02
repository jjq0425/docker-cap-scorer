# Docker Capabilities Scorer

一个基于 React + Vite 的前端工具，用于评估容器（Docker / Kubernetes / Compose）中授予的 Linux capabilities 对安全性的影响。该工具基于**“最小权限”**原则和评分表，可以交互式选择能力并生成相应的 Docker / K8s / Compose 配置片段。

> 评分表参考public文件夹下内容

## 功能

- 列出常见的 Linux capabilities 并标注风险等级（Critical / High / Medium / Low）。
- 支持恢复 Docker 默认能力集合。
- 计算安全评分并按扣分项汇总风险明细。
- 生成可复制的配置：Docker CLI、Docker Compose、Kubernetes Pod 安全上下文。
- 搜索并按需选择/移除能力项。

## 项目结构（重要文件）

- `src/App.jsx`：主 UI 与评分、生成逻辑实现。
- `index.html`, `src/main.jsx`：应用入口。
- 其余为前端配置：`vite.config.js`, `package.json`, `tailwind.config.js` 等。

## 本地运行

建议使用 `yarn`（仓库中已用 `yarn build` 成功构建），也支持 `npm`。

安装依赖：

```bash
yarn install
# 或
npm install
```

启动开发服务器（热重载）：

```bash
yarn dev
# 或
npm run dev
```

在浏览器打开：

```
http://localhost:5173
```

构建生产包：

```bash
yarn build
# 或
npm run build
```

## 使用说明（简要）

- 页面左侧设置目标镜像名称（示例：`nginx:latest`）。
- 中间面板用于搜索并选择/移除 capabilities；已选项会影响安全评分与详细扣分。
- 右侧显示评分卡、关键风险提示与生成的配置代码。可切换输出格式为 `Docker`、`Compose`、`K8s` 并一键复制。

## 开发说明

- 若需调整评分规则或风险元数据，请编辑 `src/App.jsx` 中的 `RISK_META` 与生成模板逻辑。
- 使用 Tailwind CSS 进行样式，相关配置在 `tailwind.config.js` 与 `postcss.config.js`。

建议工作流：

```bash
# 新分支
git checkout -b feat/update-risks
# 开发、测试后提交
git add .
git commit -m "chore: update risk metadata"
git push origin feat/update-risks
```

## 贡献

欢迎提交 issue 或 PR：

- 补充或修正 capability 风险描述与扣分值；
- 增加导入/导出配置、API 集成或自动化测试。
