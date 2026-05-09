"""
MCP SSH Manager - 支持多因素认证（密码/密钥/OTP 任意组合）
私钥支持本地文件路径，私钥密码复用键盘交互认证方法体
"""
import os
import uuid
from typing import Optional, List, Tuple

import paramiko
from paramiko import SSHClient, Transport, AuthenticationException, BadAuthenticationType
from mcp.server.fastmcp import FastMCP, Context

# ------------------------------------------------------------
# MCP 应用
# ------------------------------------------------------------
app = FastMCP("SSH Manager")

# 会话存储：session_id -> paramiko.SSHClient
sessions: dict[str, SSHClient] = {}

# ------------------------------------------------------------
# 支持的私钥类型（Paramiko >= 3.x 已移除 DSSKey）
# ------------------------------------------------------------
_SUPPORTED_KEY_CLASSES = []

# 按优先顺序检测可用密钥类型
for _cls_name in ("RSAKey", "ECDSAKey", "Ed25519Key"):
    _cls = getattr(paramiko, _cls_name, None)
    if _cls is not None:
        _SUPPORTED_KEY_CLASSES.append(_cls)

# 兼容旧版本 Paramiko（可选支持 DSSKey）
_old_dss = getattr(paramiko, "DSSKey", None)
if _old_dss is not None:
    _SUPPORTED_KEY_CLASSES.append(_old_dss)


def _load_private_key(
    private_key_path: Optional[str] = None,
    private_key_passphrase: Optional[str] = None,
) -> Optional[paramiko.PKey]:
    """
    从本地文件路径加载私钥，支持密码短语。
    若私钥是加密的且未提供密码短语，则抛出异常。
    若路径不存在，返回 None。
    """
    if not private_key_path:
        return None

    if not os.path.isfile(private_key_path):
        raise FileNotFoundError(f"私钥文件不存在: {private_key_path}")

    last_exception = None

    # 尝试多种私钥格式
    for key_class in _SUPPORTED_KEY_CLASSES:
        try:
            with open(private_key_path) as f:
                return key_class.from_private_key(f, password=private_key_passphrase)
        except paramiko.SSHException:
            # 格式不匹配，尝试下一种
            continue
        except Exception as e:
            # 密码错误或文件损坏等，保存异常后继续尝试
            last_exception = e
            continue

    # 所有格式都试过了
    if last_exception:
        raise last_exception

    raise ValueError(f"无法识别的私钥格式或私钥已加密但未提供密码: {private_key_path}")


def _authenticate(
    transport: Transport,
    username: str,
    auth_methods: List[str],
    password: Optional[str] = None,
    private_key: Optional[paramiko.PKey] = None,
    otp: Optional[str] = None,
) -> None:
    """
    按照 auth_methods 列表顺序进行多步认证。
    核心逻辑：
        - 每一步认证成功后，立即检查 transport.is_authenticated()
        - 如果已认证，跳过后续所有步骤
        - 避免多余步骤破坏已建立的认证状态

    支持组合：
        - ["key"]                    : 仅密钥
        - ["password"]               : 仅密码
        - ["password", "otp"]        : 密码 + OTP（键盘交互）
        - ["key", "otp"]             : 密钥 + OTP（先密钥认证，再键盘交互提供 OTP）
        - ["key", "password", "otp"] : 密钥 + 密码 + OTP（部分服务器需要）
    """
    for method in auth_methods:
        # 如果已经认证成功，跳过后续步骤
        if transport.is_authenticated():
            break

        if method == "password":
            if not password:
                raise ValueError("密码认证需要提供 password 参数")
            try:
                transport.auth_password(username, password)
            except AuthenticationException:
                # 密码认证失败，检查后续是否有 otp 需要键盘交互
                # 但注意：这里捕获异常后继续，不终止
                if not transport.is_authenticated():
                    raise

        elif method == "key":
            if not private_key:
                raise ValueError("密钥认证需要提供有效的 private_key_path 参数")
            try:
                transport.auth_publickey(username, private_key)
            except BadAuthenticationType as e:
                # 密钥认证后服务器要求键盘交互（如 OTP）
                remaining = auth_methods[auth_methods.index(method) + 1:]
                if "otp" in remaining:
                    if not otp:
                        raise ValueError("密钥认证成功，但服务器需要 2FA 验证码（OTP），请提供 otp 参数后再试")
                    _keyboard_interactive_auth(transport, username, otp, password)
                else:
                    raise e
            except AuthenticationException as e:
                # 密钥被服务器拒绝（可能原因是密钥不匹配、需要密码短语或需要 OTP）
                remaining = auth_methods[auth_methods.index(method) + 1:]
                if "otp" in remaining and not transport.is_authenticated():
                    if not otp:
                        raise ValueError(f"密钥认证失败，且服务器可能需要 2FA 验证码（OTP）。\n错误: {e}\n请提供 otp 参数后再试")
                    _keyboard_interactive_auth(transport, username, otp, password)
                else:
                    raise AuthenticationException(f"密钥认证失败: {e}")

        elif method == "otp":
            # 执行键盘交互认证
            # 注意：只有在未认证时才执行
            if not transport.is_authenticated():
                if not otp:
                    raise ValueError("认证需要 2FA 验证码（OTP），请提供 otp 参数后再试")
                _keyboard_interactive_auth(transport, username, otp, password)

        else:
            raise ValueError(f"不支持的认证方法: {method}")

    # 最终检查认证状态
    if not transport.is_authenticated():
        raise AuthenticationException("认证未完成，认证方法组合可能不满足服务器要求")


def _keyboard_interactive_auth(
    transport: Transport,
    username: str,
    otp: Optional[str] = None,
    password: Optional[str] = None,
) -> None:
    """
    执行键盘交互认证（通常用于 OTP / 2FA / 密码短语）。
    回调收到的 prompt 是 (prompt_text, echo_flag) 元组。
    """

    def handler(title: str, instructions: str, prompt_list: list) -> list:
        answers = []
        for prompt_item in prompt_list:
            # prompt_item 是 (prompt_text, echo_flag) 元组
            if isinstance(prompt_item, tuple):
                prompt_text, echo_flag = prompt_item
            else:
                prompt_text = str(prompt_item)
                echo_flag = True

            prompt_lower = prompt_text.lower() if prompt_text else ""

            # 根据提示内容智能判断
            if "password" in prompt_lower and password:
                answers.append(password)
            elif "otp" in prompt_lower or "code" in prompt_lower or "verification" in prompt_lower:
                answers.append(otp if otp else "")
            elif "passphrase" in prompt_lower or "key" in prompt_lower:
                # 私钥密码短语也可以在这里处理
                answers.append(password if password else (otp if otp else ""))
            else:
                # 未知提示，按顺序尝试 password 或 otp
                if password and not any(p in prompt_lower for p in ["optional", "skip"]):
                    answers.append(password)
                elif otp:
                    answers.append(otp)
                else:
                    answers.append("")

        return answers

    transport.auth_interactive(username, handler)


# ------------------------------------------------------------
# MCP 工具: connect_ssh
# ------------------------------------------------------------
@app.tool(
    description="连接到 SSH 服务器，支持认证方法列表组合。"
                "private_key_path 为本地私钥文件路径。"
                "auth_methods 示例: ['key'], ['password'], ['password','otp'], ['key','otp'], ['key','password','otp']"
                "返回 session_id 用于后续操作。"
)
def connect_ssh(
    host: str,
    username: str,
    auth_methods: List[str] = ["password"],
    port: int = 22,
    password: Optional[str] = None,
    private_key_path: Optional[str] = None,
    private_key_passphrase: Optional[str] = None,
    otp: Optional[str] = None,
) -> str:
    """
    建立 SSH 连接并返回会话 ID。
    private_key_path 为本地文件路径。
    """
    if not auth_methods:
        raise ValueError("auth_methods 不能为空")

    # 加载私钥（如果提供了路径）
    private_key = None
    if private_key_path:
        try:
            private_key = _load_private_key(private_key_path, private_key_passphrase)
        except paramiko.SSHException as e:
            if "password" in str(e).lower() or "passphrase" in str(e).lower():
                raise ValueError(
                    f"私钥文件 {private_key_path} 已加密，请提供 private_key_passphrase 参数"
                )
            else:
                raise e

    # 创建 Transport 进行手动认证
    transport = Transport((host, port))
    transport.start_client()

    try:
        # 执行多步认证
        _authenticate(
            transport,
            username,
            auth_methods,
            password=password,
            private_key=private_key,
            otp=otp,
        )

        # 将 Transport 挂接到 SSHClient
        client = SSHClient()
        client._transport = transport
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # 生成 session_id 并存储
        session_id = str(uuid.uuid4())
        sessions[session_id] = client
        return session_id

    except Exception as e:
        transport.close()
        raise RuntimeError(f"SSH 连接失败: {e}")


# ------------------------------------------------------------
# MCP 工具: execute_command
# ------------------------------------------------------------
@app.tool(
    description="在已连接的 SSH 会话上执行命令并返回输出。"
)
def execute_command(
    session_id: str,
    command: str,
    timeout: Optional[float] = 30.0,
) -> str:
    """在指定会话中执行命令，返回 stdout + stderr。"""
    client = sessions.get(session_id)
    if not client:
        raise LookupError(f"未找到会话: {session_id}，请先调用 connect_ssh")

    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode("utf-8")
        error = stderr.read().decode("utf-8")
        if error:
            output += f"\n[STDERR]\n{error}"
        if exit_status != 0:
            output += f"\n[EXIT CODE: {exit_status}]"
        return output
    except Exception as e:
        raise RuntimeError(f"命令执行失败: {e}")


# ------------------------------------------------------------
# MCP 工具: close_ssh
# ------------------------------------------------------------
@app.tool(
    description="关闭指定 SSH 会话并清理资源。"
)
def close_ssh(
    session_id: str,
) -> str:
    """关闭 SSH 连接并移除会话。"""
    client = sessions.pop(session_id, None)
    if not client:
        raise LookupError(f"未找到会话: {session_id}，请先调用 connect_ssh")

    try:
        client.close()
        return f"会话 {session_id} 已关闭"
    except Exception as e:
        raise RuntimeError(f"关闭连接时出错: {e}")


# ------------------------------------------------------------
# 启动 MCP 服务
# ------------------------------------------------------------
if __name__ == "__main__":
    app.run()
