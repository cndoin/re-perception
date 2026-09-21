#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键推送到 GitHub —— 交互式，自己跑，不需要 AI。

用法：
    python 一键推送.py

它会依次问你：
  1) GitHub 账号名
  2) 仓库名（默认 re-perception）
  3) 公开还是私有
然后自动完成：替换占位符 -> 建仓 -> 推送 -> 打 tag -> 建 Release。
凭证走 `gh auth login`（若未登录会先引导你登录）。
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GH = os.path.expandvars(r"%USERPROFILE%\.local\bin\gh.exe")
if not os.path.isfile(GH):
    GH = "gh"          # 回退到 PATH 上的 gh


def run(args, check=True, capture=False):
    r = subprocess.run(args, cwd=HERE, text=True, encoding="utf-8",
                       errors="replace", capture_output=capture)
    if check and r.returncode != 0:
        print("\n[失败] 命令：%s" % " ".join(args))
        if capture:
            print((r.stderr or "")[-1500:])
        sys.exit(1)
    return r


def ask(prompt, default=None):
    d = (" [默认 %s]" % default) if default else ""
    v = input("%s%s: " % (prompt, d)).strip()
    return v or default


def main():
    print("=" * 66)
    print("  逆向工程工具箱 · 一键推送到 GitHub")
    print("=" * 66)
    print()

    # ---- 0) 凭证 ----
    st = run([GH, "auth", "status"], check=False, capture=True)
    if st.returncode != 0:
        print("还没登录 GitHub。现在开始登录流程（跟着提示走，浏览器点一下即可）。")
        print()
        run([GH, "auth", "login", "--git-protocol", "https",
             "--web"], check=True)
        print()
    print("[OK] GitHub 已登录")

    # ---- 1) 收集信息 ----
    owner = run([GH, "api", "user", "--jq", ".login"],
                capture=True).stdout.strip()
    print("[OK] 当前账号：%s" % owner)
    print()
    repo = ask("仓库名", "re-perception")
    vis = ask("公开还是私有？(public/private)", "public")
    private = vis.lower().startswith("p") and not vis.lower().startswith("pub")

    print()
    print("即将创建：https://github.com/%s/%s （%s）"
          % (owner, repo, "私有" if private else "公开"))
    if input("确认？(y/N): ").strip().lower() not in ("y", "yes"):
        print("已取消。")
        return

    # ---- 2) 替换占位符 ----
    prep = os.path.join(HERE, "scripts", "_dev", "_prep_publish.py")
    if os.path.isfile(prep):
        r = subprocess.run([sys.executable, prep, owner, repo], cwd=HERE,
                           text=True, encoding="utf-8", errors="replace")
        if r.returncode != 0:
            print("[警告] 占位符替换脚本返回非 0，继续但请留意。")

    # 顺手把 doc 里的 <你的GitHub账号> 也换掉
    for fn in ("README.md", "README.en.md", "PUBLISHING.md"):
        p = os.path.join(HERE, fn)
        if not os.path.isfile(p):
            continue
        s = open(p, encoding="utf-8").read()
        n = s
        n = n.replace("<你的GitHub账号>", owner)
        n = n.replace("<你的账号>", owner)
        if n != s:
            open(p, "w", encoding="utf-8", newline="\n").write(n)
            print("  [OK] %s 里的账号占位符已替换" % fn)

    # ---- 3) 提交占位符替换 ----
    run(["git", "add", "-A"])
    d = run(["git", "diff", "--cached", "--quiet"], check=False)
    if d.returncode != 0:
        run(["git", "commit", "-m",
             "chore: 填入真实仓库地址 %s/%s" % (owner, repo)])
        print("[OK] 占位符替换已提交")
    else:
        print("[OK] 无需提交（占位符可能本来就是对的）")

    # ---- 4) 分支改名 + 建仓 + 推送 ----
    run(["git", "branch", "-M", "main"])
    print("[OK] 分支已改为 main")

    args = ["gh", "repo", "create", "%s/%s" % (owner, repo),
            "--public" if not private else "--private",
            "--source", HERE, "--remote", "origin", "--push"]
    r = subprocess.run([GH, "repo", "create", "%s/%s" % (owner, repo),
                        "--public" if not private else "--private",
                        "--source", HERE, "--remote", "origin", "--push"],
                       cwd=HERE, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        print("\n[!] 建仓/推送失败。可能仓库已存在。试试手动：")
        print("    git remote add origin https://github.com/%s/%s.git" % (owner, repo))
        print("    git push -u origin main")
        return
    print("[OK] 已推送")

    # ---- 5) 打 tag + 发 Release ----
    ver = "1.3.8"
    run(["git", "tag", "-a", "v%s" % ver, "-m", "v%s" % ver], check=False)
    run(["git", "push", "origin", "v%s" % ver], check=False)
    run([GH, "release", "create", "v%s" % ver,
         "--title", "v%s" % ver,
         "--notes-file", os.path.join(HERE, "CHANGELOG.md")],
        check=False)
    print("[OK] 已打 tag v%s 并创建 Release" % ver)

    print()
    print("=" * 66)
    print("  完成！仓库地址：https://github.com/%s/%s" % (owner, repo))
    print("=" * 66)
    print()
    print("别忘了在仓库 Settings 里填 Description 和 Topics ——")
    print("内容见 PUBLISHING.md 第 2 节，照着复制即可。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n已取消。")
