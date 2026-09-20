#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""发布前的一次性收尾：把 OWNER/REPO 占位符替换成真实账号/仓库名。

用法：
    python _prep_publish.py <GitHub账号> <仓库名>

它会：
  1) 替换 .github/ISSUE_TEMPLATE/config.yml 里的 OWNER/REPO
  2) 复核替换结果
  3) 打印 PUBLISHING.md 里待用户确认的项

不碰 git，不改历史，只在工作区改文件。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    owner, repo = sys.argv[1].strip(), sys.argv[2].strip()
    if not owner or not repo or "/" in owner or "/" in repo:
        print("参数不合法：owner/repo 不能为空、不能含 /")
        return 2

    p = os.path.join(ROOT, ".github", "ISSUE_TEMPLATE", "config.yml")
    s = io.open(p, encoding="utf-8").read()

    n = s.count("OWNER/REPO")
    if n == 0:
        print("已经是替换过的状态，无需处理。")
        return 0

    s = s.replace("OWNER/REPO", "%s/%s" % (owner, repo))
    # 占位符替换完成后，顶部那条"发布前必改"的注记就该撤掉
    s = s.replace(
        "# ⚠️ 发布前必改：把下面两处 OWNER/REPO 换成真实的 GitHub 账号/仓库名，\n"
        "#    否则这两个链接在仓库里就是 404。PUBLISHING.md 的发布检查单里有这一项。\n",
        "")
    if s.startswith("\n"):
        s = s.lstrip("\n")

    io.open(p, "w", encoding="utf-8", newline="\n").write(s)

    chk = io.open(p, encoding="utf-8").read()
    print("=" * 62)
    print("  替换 %d 处 OWNER/REPO -> %s/%s" % (n, owner, repo))
    print("  [复核] 占位符残留: %s" % ("OWNER/REPO" in chk))
    print("  [复核] 新地址已写入: %s" % (("%s/%s" % (owner, repo)) in chk))
    print("  [复核] 注记已撤: %s" % ("发布前必改" not in chk))
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
