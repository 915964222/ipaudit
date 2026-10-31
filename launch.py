"""PyInstaller 打包入口（顶层绝对导入，避开 __main__.py 的相对导入限制）。"""

from ipaudit.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
