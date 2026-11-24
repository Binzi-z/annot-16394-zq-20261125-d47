# -*- coding: utf-8 -*-
"""统一入口：依次运行冒烟、小账本穷举、八万行大规模测试。"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import smoke_test  # noqa: E402,F401  （导入即执行其主流程脚本式断言）


def main():
    # smoke_test 在导入时执行；随后显式运行两套测试套件
    import audit_exhaustive
    import audit_large

    print("=" * 64)
    print("小账本穷举测试")
    print("=" * 64)
    audit_exhaustive.main()

    print()
    print("=" * 64)
    print("八万行大规模测试")
    print("=" * 64)
    t = time.perf_counter()
    audit_large.main()
    print(f"(run_all 总墙钟 {time.perf_counter() - t:.2f}s)")


if __name__ == "__main__":
    main()
