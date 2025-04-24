#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
示例脚本: 使用 JWXT 完成登录并获取用户信息
"""
import argparse
import json
import logging
import sys
import time

import requests  # type: ignore

from scau_jwxt_auth import JWXT, JWXTLoginError


def fetch_user_info(client: JWXT) -> dict:
    """
    调用教务系统接口获取用户信息

    Args:
        client: 已完成登录的 JWXT 实例
    Returns:
        解析后的 JSON 字典
    """
    url = (
        f"{client.base_url}/secService/assert.json?"
        "resourceCode=resourceCode&"
        "apiCode=framework.sign.controller.SignController.asserts&"
        f"t={int(time.time()*1000)}&sf_request_type=ajax"
    )
    session = client.get_session()
    response = session.get(url, timeout=15)
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="JWXT 登录示例脚本")
    parser.add_argument("user_code", help="学号")
    parser.add_argument("password", help="教务系统密码")
    parser.add_argument("--sso-password", help="SSO 密码（夜间模式）", default=None)
    parser.add_argument("--debug", action="store_true", help="启用调试日志")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    start = time.time()
    try:
        logging.info("开始登录")
        client = JWXT(args.user_code, args.password, args.sso_password)
        logging.info("登录成功，开始获取用户信息")
        user_info = fetch_user_info(client)
        print(json.dumps(user_info, ensure_ascii=False, indent=2))
    except JWXTLoginError as e:
        logging.error(f"登录失败: {e}")
        sys.exit(1)
    except requests.RequestException as e:
        logging.error(f"请求失败: {e}")
        sys.exit(1)
    except Exception:
        logging.exception("出现未知错误")
        sys.exit(1)
    finally:
        elapsed = time.time() - start
        logging.info(f"脚本结束，耗时 {elapsed:.2f} 秒")


if __name__ == "__main__":
    main()
