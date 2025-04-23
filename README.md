# SCAU JWXT Auth

用于华南农业大学教务系统（SCAU JWXT）的身份认证库，可以一键获取鉴权所需的 Cookie 和 Headers，全天可用，自动处理夜间需要 VPN 的情况。

## 安装

```bash
pip install scau-jwxt-auth
```

## 使用方法

```python

from scau_jwxt_auth import JWXT

# 初始化 JWXT 实例
client = JWXT(user_code="your_student_id", password="your_password",  sso_password="your_sso_password")

import time
import requests

# 获取用户信息
url = (f"{client.base_url}/secService/assert.json?"
"resourceCode=resourceCode&"
"apiCode=framework.sign.controller.SignController.asserts&"
f"t={int(time.time()*1000)}&sf_request_type=ajax"
)
session = requests.Session()
session.verify = False
session.cookies.update(client.get_cookies())
session.headers.update(client.get_headers())
response = session.get(url, timeout=15)
response.raise_for_status()

# 打印用户信息
print(response.json())

```

## 许可证

[AGPLv3](LICENSE)
