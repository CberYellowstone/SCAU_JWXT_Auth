import logging
import time
from datetime import datetime
from datetime import time as dt_time
from datetime import timedelta, timezone
from io import BytesIO
from typing import Dict, Optional, Tuple

import ddddocr
import requests
from PIL import Image
from playwright.sync_api import sync_playwright

# 配置常量
# 常用请求头、超时、时区、夜间时间段等
JWXT_URL = "https://jwxt.scau.edu.cn"
JWXT_URL_BACKUP = "https://jwxt-scau-edu-cn-s.vpn.scau.edu.cn"  # SSO/夜间URL
LOGIN_ENDPOINT = "/secService/login"
CAPTCHA_ENDPOINT = "/secService/kaptcha"
CAPTCHA_CHECK_ENDPOINT = "/secService/kaptcha/check"

REQUEST_TIMEOUT = 15
TZ_UTC8 = timezone(timedelta(hours=8))
NIGHT_START = dt_time(0, 0)
NIGHT_END = dt_time(7, 0)

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "app": "PCWEB",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "zh-CN,zh;q=0.9",
    "Connection": "keep-alive",
}


# 动态生成 KAPTCHA 头，避免全局定义多个相似字典
def get_kaptcha_headers(base_url: str) -> Dict[str, str]:
    """根据 base_url 生成 KAPTCHA 请求头"""
    return {
        "KAPTCHA-KEY-GENERATOR-REDIS": "securityKaptchaRedisServiceAdapter",
        "Origin": base_url,
        "Referer": f"{base_url}/",
    }


logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class JWXTLoginError(Exception):
    """教务系统登录错误"""
    def __init__(self, message: str, stage: str = "未知阶段"):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage


# HTTP 会话工厂与客户端封装
def create_session(
    base_url: str,
    extra_headers: Optional[Dict[str, str]] = None,
    initial_cookies: Optional[Dict[str, str]] = None,
) -> requests.Session:
    """
    生成并配置 HTTP 会话。

    Args:
        base_url: 服务基础 URL。
        extra_headers: 额外的请求头。
        initial_cookies: 初始 Cookies。
    Returns:
        配置好的 requests.Session 对象。
    """
    session = requests.Session()
    session.verify = False
    session.headers.update(COMMON_HEADERS)
    logger.debug(
        f"create_session: base_url={base_url}, extra_headers={list(extra_headers.keys()) if extra_headers else None}, initial_cookies_keys={list(initial_cookies.keys()) if initial_cookies else None}"
    )
    if extra_headers:
        session.headers.update(extra_headers)
    if initial_cookies:
        session.cookies.update(initial_cookies)
    return session


class SSOClient:
    """
    SSO 登录客户端，通过 Playwright 自动化获取初始认证 Cookies。
    """

    base_url: str

    def __init__(self, sso_base_url: str) -> None:
        self.base_url = sso_base_url

    def get_initial_cookies(
        self, user_code: str, sso_password: Optional[str]
    ) -> Dict[str, str]:
        """
        执行 SSO 登录流程，并返回获取到的 Cookie。

        Args:
            user_code: 用户学号。
            sso_password: 统一身份认证密码。
        Returns:
            初始 Cookies 字典。
        """
        logger.info(f"SSOClient: 开始 SSO 登录 user_code={user_code}")
        if not sso_password:
            raise JWXTLoginError("未提供 SSO 密码", stage="SSO登录")
        with sync_playwright() as p:
            try:
                browser = p.firefox.launch(headless=True)
            except Exception:
                browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.goto(f"{self.base_url}/", wait_until="networkidle", timeout=90000)
            page.locator('//*[@id="username"]').fill(user_code)
            page.locator('//*[@id="password"]').fill(sso_password)
            page.locator('input.btn-submit[name="submit"]').click()
            page.wait_for_selector('img[src*="/secService/kaptcha"]', timeout=60000)
            cookies_list = context.cookies()
            logger.debug(f"SSOClient: 获取到 Cookie 列表 count={len(cookies_list)}")
            page.close()
            context.close()
            browser.close()
            return {cookie["name"]: cookie["value"] for cookie in cookies_list}


class PasswordClient:
    """
    密码登录客户端，负责验证码拉取、校验及表单提交，获取登录凭证。
    """

    base_url: str

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url

    def login(
        self,
        user_code: str,
        password: str,
        initial_cookies: Optional[Dict[str, str]] = None,
    ) -> Tuple[str, Dict[str, str], Optional[str], Dict[str, str]]:
        """
        执行密码登录：拉取验证码、校验、提交表单，并返回认证信息。

        Args:
            user_code: 学号。
            password: 教务系统密码。
            initial_cookies: SSO 获取的初始 Cookies。
        Returns:
            token: 登录令牌。
            cookies: 登录后 Cookies。
            session_id: SESSION ID。
            headers: 含 TOKEN 的请求头。
        """
        logger.info(f"PasswordClient: 开始密码登录 user_code={user_code}")
        session = create_session(
            self.base_url,
            extra_headers=get_kaptcha_headers(self.base_url),
            initial_cookies=initial_cookies,
        )
        # 如果未传入 initial_cookies，先访问首页以获取 SESSION
        if not initial_cookies:
            try:
                session.get(
                    f"{self.base_url}/", timeout=REQUEST_TIMEOUT
                ).raise_for_status()
            except Exception:
                pass
        # --- 获取并识别验证码 ---
        timestamp = int(time.time() * 1000)
        captcha_url = f"{self.base_url}{CAPTCHA_ENDPOINT}?t={timestamp}&KAPTCHA-KEY-GENERATOR-REDIS=securityKaptchaRedisServiceAdapter"
        logger.debug("PasswordClient: 拉取验证码")
        r = session.get(captcha_url, verify=False, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        img = Image.open(BytesIO(r.content))
        captcha_text = ddddocr.DdddOcr(beta=True, show_ad=False).classification(img)
        logger.debug(f"PasswordClient: 识别验证码文本={captcha_text}")
        # --- 校验验证码 ---
        verify_url = f"{self.base_url}{CAPTCHA_CHECK_ENDPOINT}/{captcha_text}/false"
        rep = session.post(
            verify_url,
            headers=get_kaptcha_headers(self.base_url),
            verify=False,
            timeout=REQUEST_TIMEOUT,
        )
        rep.raise_for_status()
        res = rep.json()
        if res.get("errorCode") != "success":
            raise JWXTLoginError(
                f"验证码校验失败: {res.get('errorMessage')}", stage="密码登录"
            )
        logger.debug("PasswordClient: 校验验证码成功")
        # --- 提交登录表单 ---
        login_url = f"{self.base_url}{LOGIN_ENDPOINT}"
        login_data = {
            "userCode": user_code,
            "password": password,
            "kaptcha": captcha_text,
            "userCodeType": "account",
        }
        response = session.post(login_url, json=login_data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        result = response.json()
        if result.get("errorCode") != "success":
            raise JWXTLoginError(
                result.get("errorMessage", "登录失败"), stage="密码登录"
            )
        token = result.get("data", {}).get("token")
        if not token or not isinstance(token, str):
            raise JWXTLoginError("登录成功但未获取 token", stage="密码登录")
        cookies = session.cookies.get_dict()
        session_id: Optional[str] = cookies.get("SESSION")
        headers = {**COMMON_HEADERS, "TOKEN": token}
        logger.info(f"PasswordClient: 密码登录成功，token 长度={len(token)}")
        return token, cookies, session_id, headers


class JWXT:
    """
    教务系统登录器，根据时段选择 SSO 或账号密码登录，完成认证并提供 Token/Cookie。
    """

    # 实例属性类型注解，便于 MyPy 检查
    user_code: str
    password: str
    sso_password: Optional[str]
    _token: Optional[str]
    _cookies: Dict[str, str]
    _headers: Dict[str, str]
    _session_id: Optional[str]
    _base_url: str

    def __init__(
        self,
        user_code: str,
        password: str,
        sso_password: Optional[str] = None,
    ) -> None:
        """
        初始化并执行登录认证。

        Args:
            user_code: 学号
            password: 教务系统密码
            sso_password: 统一身份认证密码（可选，夜间登录需要）
        """
        self.user_code = user_code
        self.password = password
        self.sso_password = sso_password

        # 初始化内部状态
        self._token = None
        self._cookies = {}
        self._headers = {}
        self._session_id = None
        self._base_url = ""  # 将在 _authenticate 中设置

        self._authenticate()

    def _is_night_time(self) -> bool:
        """
        判断当前是否处于夜间（00:00 - 07:00）。

        Returns:
            True 表示夜间，否则日间。
        """
        current_time = datetime.now(TZ_UTC8).time()
        is_night = NIGHT_START <= current_time <= NIGHT_END
        if is_night:
            logger.info("当前为夜间时段 (00:00-07:00)，将尝试SSO登录")
        else:
            logger.info("当前为日间时段，将尝试密码登录")
        return is_night

    def _perform_password_login(
        self, initial_cookies: Optional[Dict[str, str]] = None
    ) -> None:
        """
        使用账号密码登录，获取 Token、Cookies、Session ID 和请求头。
        """
        # 使用 PasswordClient 完成密码登录，获取 Token、Cookies、Headers
        logger.info(f"JWXT: 执行密码登录 user_code={self.user_code}")
        client = PasswordClient(self._base_url)
        token, cookies, session_id, headers = client.login(
            self.user_code, self.password, initial_cookies
        )
        self._token = token
        self._cookies = cookies
        self._session_id = session_id
        self._headers = headers

    def _perform_sso_login(self) -> Dict[str, str]:
        """
        夜间模式下通过 SSO 获取初始 Cookies。

        Returns:
            SSO 登录后获取的 Cookie 字典。
        """
        # 使用 SSOClient 完成 SSO 登录并获取初始 Cookies
        logger.info(f"JWXT: 执行 SSO 登录 user_code={self.user_code}")
        client = SSOClient(JWXT_URL_BACKUP)
        cookies = client.get_initial_cookies(self.user_code, self.sso_password)
        logger.debug(f"JWXT: SSO 登录返回 cookies keys={list(cookies.keys())}")
        return cookies

    def _authenticate(self) -> None:
        """
        认证主流程：
        - 夜间(00:00-07:00)：先 SSO 登录获取 Cookies，再密码登录获取 Token。
        - 日间：直接密码登录获取 Token。
        """
        logger.info(f"JWXT: 开始认证流程 user_code={self.user_code}")
        initial_cookies: Optional[Dict[str, str]] = None

        try:
            # 步骤 1: 判断模式并执行 SSO (如果需要)
            if self._is_night_time():
                logger.info("进入夜间 SSO 登录流程...")
                self._base_url = JWXT_URL_BACKUP  # 夜间模式始终使用备用 URL
                try:
                    initial_cookies = self._perform_sso_login()
                    logger.info(
                        f"SSO 获取初始 Cookie 完成，将使用 {self._base_url} 进行后续密码登录"
                    )
                except JWXTLoginError as sso_error:
                    logger.error(f"SSO 登录阶段失败: {sso_error}。认证流程终止。")
                    raise  # SSO 失败则终止整个认证
            else:
                logger.info("进入日间密码登录流程...")
                self._base_url = JWXT_URL  # 日间模式使用主 URL

            # 步骤 2: 执行密码登录 (获取最终 Token 和 Cookie)
            # 无论日间还是夜间（SSO成功之后），都需要执行这一步
            logger.info(f"准备在 {self._base_url} 执行密码登录...")
            self._perform_password_login(
                initial_cookies
            )  # 传入 SSO 的 cookies (如果夜间模式)

            logger.info(f"认证流程成功完成。最终使用 Base URL: {self._base_url}")

        except JWXTLoginError as e:
            logger.error(f"认证失败: {e}")
            # 清理状态，表示未登录
            self._token = None
            self._cookies = {}
            self._session_id = None
            self._headers = {}
            self._base_url = ""  # 清空 base_url
            raise  # 将登录错误向上抛出
        except Exception as e:
            # 捕获未预料的异常
            logger.error(f"认证过程中发生未处理的异常: {e}", exc_info=True)
            self._token = None
            self._cookies = {}
            self._session_id = None
            self._headers = {}
            self._base_url = ""
            # 将未知错误包装成 JWXTLoginError 抛出
            raise JWXTLoginError(f"未知错误: {e}", stage="认证主流程") from e

    def get_cookies(self) -> Dict[str, str]:
        """获取认证成功后的 Cookies"""
        if not self._cookies:
            raise JWXTLoginError("尚未成功登录或登录已失败", stage="获取Cookies")
        return self._cookies.copy()  # 返回副本防止外部修改

    def get_headers(self) -> Dict[str, str]:
        """获取包含认证 TOKEN 的请求头"""
        if not self._headers:
            raise JWXTLoginError("尚未成功登录或登录已失败", stage="获取Headers")
        return self._headers.copy()  # 返回副本

    @property
    def token(self) -> Optional[str]:
        """获取认证令牌 (TOKEN)"""
        return self._token

    @property
    def session_id(self) -> Optional[str]:
        """获取会话 ID (通常是 'SESSION' cookie)"""
        return self._session_id

    @property
    def base_url(self) -> str:
        """获取本次认证最终使用的基础 URL"""
        if not self._base_url:
            logger.warning("尝试在登录失败或未开始时获取 base_url")
        return self._base_url
