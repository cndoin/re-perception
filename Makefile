# 逆向工程工具箱 —— 常用命令入口
#
# 有意不依赖任何构建系统：这个项目的卖点就是"零依赖、clone 下来就能跑"，
# 引入 make 之外的东西会自相矛盾。Windows 上用 Git Bash 自带的 make，
# 或者直接照抄下面的命令行手动执行。
#
# Python 解释器可通过 PY 覆盖：make test PY=python3.11

PY ?= python
SCRIPTS := scripts

.DEFAULT_GOAL := help
.PHONY: help test test-fast lint undefined e2e check all audit version clean clean-all

help:  ## 显示本帮助
	@echo "逆向工程工具箱 —— 可用目标："
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- 测试
test:  ## 全量自检（约 170 秒）
	cd $(SCRIPTS) && $(PY) selftest.py

test-fast:  ## 只跑正确性相关的用例（实机 + 各格式）
	cd $(SCRIPTS) && $(PY) selftest.py --only 实机

# ---------------------------------------------------------------- 静态检查
lint:  ## 静态体检（语法/静默吞异常/硬编码路径/工程护栏）
	cd $(SCRIPTS) && $(PY) _dev/_lint.py

undefined:  ## 找函数体里写错的变量名（零依赖版 pyflakes）
	cd $(SCRIPTS) && $(PY) _dev/_undefined.py

# ---------------------------------------------------------------- 集成
e2e:  ## 端到端：26 个子命令在真实二进制上全跑一遍
	cd $(SCRIPTS) && $(PY) _dev/_e2e.py

audit:  ## 开源合规自审（有高危项时非零退出）
	cd $(SCRIPTS) && $(PY) _dev/_ossaudit.py

# ---------------------------------------------------------------- 组合
check: lint undefined test  ## 提交前必跑：lint + 未定义名 + 全量自检

all: check e2e audit  ## 完整的发布前检查

version:  ## 打印版本号
	cd $(SCRIPTS) && $(PY) re.py --version

# ---------------------------------------------------------------- 清理
clean:  ## 删掉运行产物（__pycache__ / 自检报告）
	$(PY) -c "import pathlib,shutil;[shutil.rmtree(p,ignore_errors=True) for p in pathlib.Path('.').rglob('__pycache__')]"
	$(PY) -c "import pathlib;[p.unlink() for p in pathlib.Path('.').rglob('*.re-report.md')]"
	$(PY) -c "import pathlib;[p.unlink() for p in pathlib.Path('.').rglob('_st*.log')]"

clean-all: clean  ## 同上，并额外清掉自检临时目录
	$(PY) -c "import shutil,os;shutil.rmtree(os.path.join(os.environ.get('TEMP','/tmp'),'re-selftest'),ignore_errors=True)"
