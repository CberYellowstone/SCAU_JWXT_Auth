import json
import logging
import time
from datetime import datetime
from datetime import time as dt_time
from datetime import timedelta, timezone
from io import BytesIO
from typing import Dict, Optional, Tuple
from urllib import response

import ddddocr
import requests
from PIL import Image
from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

# --- 配置常量 ---
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


class JWXT:
    """
    简化的教务系统接口类，用于登录并获取认证信息。
    """

    def __init__(
        self,
        userCode: str,
        jwxt_password: str,
        sso_password: Optional[str] = None,
        disable_sso: bool = False,
    ):
        """
        初始化并执行登录认证。

        Args:
            userCode: 学号
            jwxt_password: 教务系统密码
            sso_password: 统一身份认证密码（可选，夜间登录需要）
            disable_sso: 强制禁用SSO模式（即使在夜间）
        """
        self.userCode = userCode
        self.jwxt_password = jwxt_password
        self.sso_password = sso_password
        self.disable_sso = disable_sso

        self._token: Optional[str] = None
        self._cookies: Dict[str, str] = {}
        self._headers: Dict[str, str] = {}
        self._session_id: Optional[str] = None
        self._base_url: str = ""  # 将在 _authenticate 中设置

        self._authenticate()

    def _is_night_time(self) -> bool:
        """判断当前是否为夜间时段（0点至7点）并检查SSO条件"""
        if self.disable_sso:
            logger.info("SSO模式已被强制禁用")
            return False
        # 检查 Playwright 是否可用，如果不可用则无法进行 SSO
        try:
            import playwright.sync_api

            playwright_available = True
        except ImportError:
            playwright_available = False

        if not playwright_available:
            logger.warning("Playwright库不可用，无法使用SSO模式，将强制使用密码登录")
            return False

        current_time = datetime.now(TZ_UTC8).time()
        is_night = NIGHT_START <= current_time <= NIGHT_END
        if is_night:
            logger.info("当前为夜间时段 (00:00-07:00)，将尝试SSO登录")
        else:
            logger.info("当前为日间时段，将尝试密码登录")
        return is_night

    def _get_captcha(self, session: requests.Session, headers: Dict[str, str]) -> str:
        """获取并识别验证码 (使用 self._base_url)"""
        if ddddocr is None or Image is None:
            raise JWXTLoginError("ddddocr 或 Pillow 库未安装", stage="验证码获取")

        ocr = ddddocr.DdddOcr(beta=True, show_ad=False)
        timestamp = int(time.time() * 1000)
        # 使用 self._base_url
        captcha_url = f"{self._base_url}{CAPTCHA_ENDPOINT}?t={timestamp}&KAPTCHA-KEY-GENERATOR-REDIS=securityKaptchaRedisServiceAdapter"

        try:
            # 注意：session 已经包含了 base_url 对应的 KAPTCHA 头
            r = session.get(
                captcha_url,
                # headers=headers, # Headers are already in session
                verify=False,
                timeout=REQUEST_TIMEOUT,
            )
            r.raise_for_status()
            img = Image.open(BytesIO(r.content))
            captcha_text = ocr.classification(img)
            if not captcha_text:
                raise ValueError("OCR 识别验证码失败")
            logger.info(f"识别出的验证码: {captcha_text}")
            return captcha_text
        except requests.exceptions.Timeout:
            raise JWXTLoginError(
                f"获取验证码超时 ({REQUEST_TIMEOUT}秒)", stage="验证码获取"
            )
        except requests.exceptions.RequestException as e:
            raise JWXTLoginError(f"网络请求失败: {e}", stage="验证码获取")
        except (Image.UnidentifiedImageError, ValueError, Exception) as e:
            raise JWXTLoginError(f"验证码处理失败: {e}", stage="验证码获取")

    def _verify_captcha(
        self,
        session: requests.Session,
        captcha: str,
        headers: Dict[
            str, str
        ],  # headers 参数保留，因为 session headers 可能不完全等于 KAPTCHA 头
    ) -> bool:
        """验证验证码 (使用 self._base_url)"""
        # 使用 self._base_url
        verify_url = f"{self._base_url}{CAPTCHA_CHECK_ENDPOINT}/{captcha}/false"
        try:
            # 发送验证请求时，确保使用正确的 KAPTCHA 相关 headers
            rep = session.post(
                verify_url,
                headers=headers,  # 使用传入的特定 KAPTCHA 头
                verify=False,
                timeout=REQUEST_TIMEOUT,
            )
            rep.raise_for_status()
            result = rep.json()
            if result.get("errorCode") != "success":
                error_message = result.get("errorMessage", "验证码校验API返回失败")
                logger.error(f"验证码 '{captcha}' 校验失败: {error_message}")
                return False
            logger.info("验证码校验成功")
            return True
        except requests.exceptions.Timeout:
            logger.error(f"验证验证码请求超时 ({REQUEST_TIMEOUT}秒)")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"验证验证码请求失败: {e}")
            return False
        except json.JSONDecodeError:
            logger.error(f"无法解析验证验证码响应为 JSON: {rep.text}")
            return False

    def _perform_password_login(
        self, initial_cookies: Optional[Dict[str, str]] = None
    ) -> None:
        """
        执行密码登录流程 (使用 self._base_url)。

        Args:
            initial_cookies: 可选的初始 Cookies，用于从 SSO 登录过渡。
        """
        logger.info(f"尝试为用户 {self.userCode} 在 {self._base_url} 执行密码登录...")
        session = requests.Session()
        session.verify = False  # 禁用 SSL 验证

        # 准备 KAPTCHA 相关请求头
        current_kaptcha_headers = get_kaptcha_headers(self._base_url)
        # 合并通用头和 KAPTCHA 头到 session
        session.headers.update({**COMMON_HEADERS, **current_kaptcha_headers})

        # 如果提供了初始 Cookies (来自 SSO)，先设置到 Session 中
        if initial_cookies:
            logger.debug(f"使用 SSO 提供的初始 Cookies: {initial_cookies}")
            session.cookies.update(initial_cookies)
            # 确保 SSO 的 cookie 优先，特别是 SESSION
            logger.debug(
                f"更新 Cookies 后的 Session Cookies: {session.cookies.get_dict()}"
            )

        # 1. 访问首页获取/更新 SESSION (仅在未使用 initial_cookies 时执行)
        if not initial_cookies:
            try:
                logger.debug(f"访问首页 {self._base_url}/ 获取初始 SESSION")
                home_resp = session.get(f"{self._base_url}/", timeout=REQUEST_TIMEOUT)
                home_resp.raise_for_status()
                logger.debug(f"访问首页后的 Cookies: {session.cookies.get_dict()}")
            except requests.exceptions.RequestException as e:
                # 首页访问失败可能是网络问题或服务器临时不可用，但不一定阻止后续登录
                logger.warning(
                    f"访问教务系统首页 {self._base_url}/ 失败: {e} (尝试继续)"
                )

        # 2. 获取并验证验证码
        try:
            # 验证码请求使用 session 的 headers (已包含 KAPTCHA 头)
            captcha_text = self._get_captcha(session, session.headers)
            # 验证请求也需要 KAPTCHA 头，这里直接传递 current_kaptcha_headers 确保一致性
            if not self._verify_captcha(session, captcha_text, current_kaptcha_headers):
                raise JWXTLoginError("验证码校验失败", stage="密码登录")
        except JWXTLoginError as e:
            # 直接重新抛出，保留 stage 信息
            raise e from e
        except Exception as e:
            # 包装其他可能的异常
            raise JWXTLoginError(
                f"验证码处理过程中发生意外错误: {e}", stage="密码登录"
            ) from e

        # 3. 提交登录表单
        login_url = f"{self._base_url}{LOGIN_ENDPOINT}"
        login_data = {
            "userCode": self.userCode,
            "password": self.jwxt_password,
            "kaptcha": captcha_text,
            "userCodeType": "account",
        }

        try:
            logger.debug(
                f"向 {login_url} 提交登录请求 (Cookies: {session.cookies.get_dict()})..."
            )
            # 登录请求的 Headers 已经在 session 中设置好了
            response = session.post(
                login_url,
                json=login_data,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            result = response.json()
            logger.debug(f"收到登录响应: {result}")

            if result.get("errorCode") != "success":
                raise JWXTLoginError(
                    result.get("errorMessage", "登录API返回失败"), stage="密码登录"
                )

            token = result.get("data", {}).get("token")
            if not token or not isinstance(token, str):  # 确保 token 是非空字符串
                raise JWXTLoginError("登录成功但未能获取有效 token", stage="密码登录")

            # 登录成功，更新最终的 token, cookies, session_id, headers
            self._token = token
            self._cookies = session.cookies.get_dict()
            self._session_id = self._cookies.get("SESSION")
            # 构建最终 Headers，包含通用头和 TOKEN
            self._headers = {**COMMON_HEADERS, "TOKEN": self._token}
            logger.info(f"用户 {self.userCode} 在 {self._base_url} 密码登录成功！")

        except requests.exceptions.Timeout:
            raise JWXTLoginError(
                f"登录请求 {login_url} 超时 ({REQUEST_TIMEOUT}秒)", stage="密码登录"
            )
        except requests.exceptions.RequestException as e:
            raise JWXTLoginError(f"登录请求 {login_url} 失败: {e}", stage="密码登录")
        except json.JSONDecodeError:
            raise JWXTLoginError(
                f"无法解析登录响应为 JSON: {response.text}", stage="密码登录"
            )
        except JWXTLoginError:
            raise  # 重新抛出特定登录错误
        except Exception as e:
            raise JWXTLoginError(f"登录过程中发生意外错误: {e}", stage="密码登录")

    def _perform_sso_login(self) -> Dict[str, str]:
        """
        执行 SSO 登录流程，仅获取初始 Cookies。
        SSO 总是使用备用 URL (JWXT_URL_BACKUP)。

        Returns:
            SSO 登录后获取到的初始 Cookies 字典。

        Raises:
            JWXTLoginError: 如果 SSO 登录失败。
        """
        if sync_playwright is None:
            raise JWXTLoginError("Playwright 库未安装", stage="SSO登录")
        if not self.sso_password:
            raise JWXTLoginError("未提供 SSO 密码", stage="SSO登录")

        logger.info(f"尝试为用户 {self.userCode} 执行 SSO 登录以获取初始 Cookie...")
        sso_base_url = JWXT_URL_BACKUP  # SSO 固定使用备用 URL

        try:
            with sync_playwright() as p:
                browser = None  # 初始化 browser 变量
                try:
                    logger.debug("尝试启动 Firefox (headless)...")
                    browser = p.firefox.launch(headless=True)
                except Exception as firefox_err:
                    logger.warning(
                        f"启动 Firefox 失败: {firefox_err}。尝试启动 Chromium..."
                    )
                    try:
                        logger.debug("尝试启动 Chromium (headless)...")
                        browser = p.chromium.launch(headless=True)
                    except Exception as chromium_err:
                        raise JWXTLoginError(
                            f"无法启动浏览器 (Firefox 或 Chromium): {chromium_err}",
                            stage="SSO登录",
                        )

                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                try:
                    sso_login_url = f"{sso_base_url}/"
                    logger.debug(f"访问 SSO 登录页面: {sso_login_url}")
                    # 增加 networkidle 超时时间，应对慢速网络
                    page.goto(
                        sso_login_url, wait_until="networkidle", timeout=90000
                    )  # 增加到 90s

                    # --- 尝试处理两种可能的登录页面 ---
                    is_on_sso_page = False
                    try:
                        # 检查是否存在标准的 SSO 用户名输入框
                        page.wait_for_selector(
                            '//*[@id="username"]', timeout=10000
                        )  # 缩短超时，快速判断
                        logger.info("检测到统一认证登录页面，填写凭据...")
                        page.locator('//*[@id="username"]').fill(self.userCode)
                        page.locator('//*[@id="password"]').fill(self.sso_password)
                        page.locator('input.btn-submit[name="submit"]').click()
                        is_on_sso_page = True
                    except PlaywrightError:
                        logger.info(
                            "未在10秒内找到标准 SSO 登录框，可能已自动登录或页面结构变化。"
                        )
                        # 这里可以添加对其他可能的登录状态或页面的检查，如果需要的话
                        # 例如，检查是否已经直接跳转到了教务系统页面
                        try:
                            page.wait_for_selector(
                                'img[src*="/secService/kaptcha"]', timeout=5000
                            )
                            logger.info(
                                "已直接跳转到教务系统页面 (可能之前已登录SSO)。"
                            )
                        except PlaywrightError:
                            logger.warning("也未直接跳转到教务系统页面，流程可能中断。")
                            # 如果两种情况都不是，可能需要抛出错误或采取其他策略

                    # --- 等待跳转到教务系统 ---
                    if is_on_sso_page or not page.query_selector(
                        'img[src*="/secService/kaptcha"]'
                    ):  # 只有在明确点击登录后才需要长时间等待跳转
                        logger.debug("等待登录成功跳转到教务系统页面...")
                        try:
                            # 等待教务系统页面的验证码图片作为成功标志
                            page.wait_for_selector(
                                'img[src*="/secService/kaptcha"]',
                                timeout=60000,  # 增加等待时间
                            )
                            logger.info("检测到教务系统验证码，SSO 步骤成功")
                        except PlaywrightError as wait_error:
                            page_content = page.content()
                            logger.error(
                                f"等待教务系统页面标志超时。当前 URL: {page.url}\n页面内容(前1000字符):\n{page_content[:1000]}..."
                            )
                            raise JWXTLoginError(
                                f"SSO登录后等待教务系统页面超时: {wait_error}",
                                stage="SSO登录",
                            )
                    else:
                        logger.info("似乎已在教务系统页面，跳过等待跳转步骤。")

                    all_cookies = context.cookies()
                    if not all_cookies:
                        # 尝试再次获取，有时可能需要一点时间同步
                        time.sleep(1)
                        all_cookies = context.cookies()
                        if not all_cookies:
                            raise JWXTLoginError(
                                "SSO 登录后未能获取到 Cookies", stage="SSO登录"
                            )

                    # 提取关键 Cookie (通常 SESSION 是最重要的)
                    initial_cookies = {}
                    required_cookie_names = [
                        "SESSION"
                    ]  # 可以根据需要添加其他关键 cookie
                    for cookie in all_cookies:
                        initial_cookies[cookie["name"]] = cookie["value"]
                    # if cookie["name"] in required_cookie_names:
                    #     initial_cookies[cookie["name"]] = cookie["value"]

                    # 检查是否获取到了必要的 Cookie
                    missing_cookies = [
                        name
                        for name in required_cookie_names
                        if name not in initial_cookies
                    ]
                    if missing_cookies:
                        logger.warning(
                            f"SSO 后缺少关键 Cookies: {missing_cookies}。获取到的 Cookies: {initial_cookies}"
                        )
                        # 这里可以选择是抛出错误还是继续尝试
                        # raise JWXTLoginError(f"SSO 后缺少关键 Cookies: {missing_cookies}", stage="SSO登录")

                    logger.info(f"SSO 登录成功获取到初始 Cookies: {initial_cookies}")
                    return initial_cookies

                except PlaywrightError as e:
                    page_content_on_error = "无法获取页面内容"
                    try:
                        page_content_on_error = page.content()
                    except Exception:
                        pass  # 忽略获取内容时的错误
                    logger.error(
                        f"Playwright 操作失败: {e}\n当前 URL: {page.url}\n页面内容(前1000字符):\n{page_content_on_error[:1000]}..."
                    )
                    raise JWXTLoginError(
                        f"浏览器自动化操作失败: {e}", stage="SSO登录"
                    ) from e
                except JWXTLoginError:  # 捕获内部抛出的 JWXTLoginError
                    raise
                except Exception as e:
                    page_content_on_error = "无法获取页面内容"
                    try:
                        page_content_on_error = page.content()
                    except Exception:
                        pass
                    logger.error(
                        f"SSO 登录过程中发生意外错误: {e}\n当前 URL: {page.url}\n页面内容(前1000字符):\n{page_content_on_error[:1000]}..."
                    )
                    raise JWXTLoginError(
                        f"SSO 登录意外失败: {e}", stage="SSO登录"
                    ) from e
                finally:
                    if "page" in locals() and page:
                        page.close()
                    if "context" in locals() and context:
                        context.close()
                    if "browser" in locals() and browser:
                        browser.close()

        except PlaywrightError as e:
            raise JWXTLoginError(
                f"Playwright 初始化或执行出错: {e}", stage="SSO登录"
            ) from e

    def _authenticate(self) -> None:
        """
        执行认证流程。
        根据时间决定登录策略：
        - 夜间 (00:00-07:00 且 SSO 未禁用且 Playwright 可用):
            1. 使用 Playwright 进行 SSO 登录 (访问 JWXT_URL_BACKUP)，获取初始 cookies。
            2. 使用获取到的 cookies，通过 requests 进行密码登录 (访问 JWXT_URL_BACKUP)，获取最终 token 和 cookies。
        - 日间 (其他时间 或 SSO 被禁用 或 Playwright 不可用):
            1. 直接使用 requests 进行密码登录 (访问 JWXT_URL)。
        """
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
            # 可以选择抛出错误或返回空字符串
            # raise JWXTLoginError("尚未成功登录或登录已失败", stage="获取BaseURL")
            logger.warning("尝试在登录失败或未开始时获取 base_url")
        return self._base_url

# --- 使用示例 ---
if __name__ == "__main__":
    # --- !! 请在此处填入你的凭据 !! ---
    TEST_USERCODE = "你的学号"  # 替换为你的学号
    TEST_JWXT_PASSWORD = "你的教务系统密码"  # 替换为你的教务系统密码
    # 夜间测试 (约 00:00 - 07:00) 需要 SSO 密码
    TEST_SSO_PASSWORD = "你的统一认证密码"  # 如果不需要 SSO 或在日间测试，可以留空 None

    print("\n--- 开始登录测试 ---")
    start_time = time.time()
    try:
        # 初始化 JWXT 类，会自动尝试登录
        # disable_sso=True 可以强制使用密码登录（即使在夜间）
        # 例如，强制日间模式： disable_sso=True
        # 例如，强制夜间模式（需要设置好 sso_password）： disable_sso=False （并且在夜间运行）
        jwxt_session = JWXT(
            TEST_USERCODE, TEST_JWXT_PASSWORD, TEST_SSO_PASSWORD, disable_sso=False
        )

        # 登录成功，打印关键信息
        print("\n--- 登录成功！认证信息 ---")
        print(f"模式判断后使用的 Base URL: {jwxt_session.base_url}")
        print(f"Token: {jwxt_session.token}")
        print(f"Session ID: {jwxt_session.session_id}")
        # 为了简洁，只打印部分 Cookie
        cookies_to_print = {
            k: v
            for k, v in jwxt_session.get_cookies().items()
            if k in ["SESSION", "token"]
        }
        print(f"关键 Cookies: {cookies_to_print}")
        # print(f"完整 Cookies: {jwxt_session.get_cookies()}")
        print(
            f"请求 Headers (部分): {{'TOKEN': '{jwxt_session.get_headers().get('TOKEN')}', ...}}"
        )
        # print(f"完整 Headers: {jwxt_session.get_headers()}")

        # 尝试获取并打印用户信息 (作为 API 调用示例)
        try:
            user_info_url = f"{jwxt_session.base_url}/secService/assert.json?resourceCode=resourceCode&apiCode=framework.sign.controller.SignController.asserts&t={int(time.time() * 1000)}&sf_request_type=ajax"
            client = requests.Session()
            # 应用获取到的 cookies 和 headers
            client.cookies.update(jwxt_session.get_cookies())
            client.headers.update(jwxt_session.get_headers())
            client.verify = False  # 禁用 SSL 验证

            print(f"\n--- 尝试调用 API 获取用户信息: {user_info_url} ---")
            _response = client.get(user_info_url, timeout=REQUEST_TIMEOUT)
            _response.raise_for_status()
            user_info = _response.json()
            print("--- 获取用户信息成功 ---")
            print(json.dumps(user_info, indent=2, ensure_ascii=False))
        except requests.exceptions.RequestException as api_err:
            print(f"--- 调用API获取用户信息失败: {api_err} ---")
            if hasattr(api_err, "response") and api_err.response is not None:
                print(f"    响应状态码: {api_err.response.status_code}")
                print(
                    f"    响应内容: {api_err.response.text[:500]}..."
                )  # 打印部分响应内容
        except Exception as api_err:
            print(f"--- 调用API时发生其他错误: {api_err} ---")

    except JWXTLoginError as e:
        print(f"\n--- 登录测试失败 ---")
        print(f"错误信息: {e}")
    except ImportError as e:
        print(f"\n--- 发生导入错误 ---")
        print(f"错误信息: {e}")
        if "playwright" in str(e):
            print("请确保已安装 playwright 库。运行:")
            print("pip install playwright")
            print("playwright install")  # 安装浏览器驱动
        elif "ddddocr" in str(e):
            print("请确保已安装 ddddocr 库。运行: pip install ddddocr")
        elif "PIL" in str(e):
            print("请确保已安装 Pillow 库。运行: pip install Pillow")
        else:
            print(
                "请确保已安装所有依赖: pip install requests ddddocr Pillow playwright"
            )
    except Exception as e:
        print(f"\n--- 发生未知错误 ---")
        print(f"错误类型: {type(e).__name__}")
        print(f"错误信息: {e}", exc_info=True)  # 打印 traceback

    end_time = time.time()
    print(f"\n--- 登录测试结束 (耗时: {end_time - start_time:.2f} 秒) ---")
