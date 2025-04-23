# SCAU JWXT Auth

这个包用于华南农业大学教务系统（SCAU JWXT）的身份认证。

## 安装

```bash
pip install scau-jwxt-auth
```

## 使用方法

```python

from scau_jwxt_auth import JWXT

client = JWXT(user_code="your_student_id", password="your_password",  sso_password="your_sso_password")

```

## 许可证

[AGPLv3](LICENSE)
