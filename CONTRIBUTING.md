# 贡献指南

感谢参与！请遵循以下流程：

1. Fork 并新建分支：`git checkout -b feat/your-feature`。
2. 开发环境：Python 3.10 – 3.14（已在 3.14 验证）。
   ```bash
   python -m venv .venv
   .venv\Scripts\activate        # Windows
   pip install -r requirements.txt
   pip install pytest ruff
   ```
3. 提交前请确保：
   ```bash
   ruff check . && ruff format --check .
   set QT_QPA_PLATFORM=offscreen && pytest -q
   ```
4. 涉及加密或文件格式的改动，**必须**补充/更新 `tests/`，并说明向后兼容策略。
5. 提交信息建议使用 `feat: / fix: / docs: / refactor: / test:` 前缀。
6. 发起 PR，描述动机、改动点与测试方式。

## 代码约定
- 面向对象职责单一：`model`（数据/加密）、`controller`（流程）、`view`（界面）。
- 不要在 `view` 中写业务逻辑；不要在 `model` 中 import PySide6。
- 新文件一律使用 v3 格式写入；读取端必须保持对 v1/v2 的兼容。
