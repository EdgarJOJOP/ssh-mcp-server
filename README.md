使用 mcp.server.fastmcp 创建一个 MCP 服务器，实现 SSH 远程连接、命令执行与连接关闭的功能。支持密码、密钥、2FA 等多种认证方式，且所有凭证仅内存中保持，不会持久化。

# 1.安装依赖和运行验证


`pip install mcp paramiko`

运行服务

`python ssh_manager.py`

# 2.添加进mcp

采用studio模式所以配置填：
【python环境地址】(空格)【python文件地址】

然后就能正常使用了。

# 示例调用
## 提示词：

`你使用ssh_mcp连接我的服务器，ip：192.168.1.10，端口：22，用户名：root,密钥路径：D:\XXXXXXXX.pem，带2fa验证，需要输入2fa验证码通知我.`

## 1. 密码认证连接

Json
{
  "method": "tools/call",
  "params": {
    "name": "connect_ssh",
    "arguments": {
      "host": "192.168.1.100",
      "username": "admin",
      "password": "secure_pass"
    }
  }
}

返回 session_id，如 "a1b2c3d4-e5f6-7890-abcd-ef1234567890"。

## 2. 密钥认证连接

Json
{
  "name": "connect_ssh",
  "arguments": {
    "host": "example.com",
    "username": "user",
    "auth_method": "key",
    "private_key_content": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...\n-----END RSA PRIVATE KEY-----"
  }
}

## 3. 密码+2FA 连接

Json
{
  "name": "connect_ssh",
  "arguments": {
    "host": "server.io",
    "username": "user",
    "auth_method": "password_otp",
    "password": "pass123",
    "otp": "123456"
  }
}

## 4. 执行命令

Json
{
  "name": "execute_command",
  "arguments": {
    "session_id": "a1b2c3d4-...",
    "command": "whoami && hostname"
  }
}

返回合并后的输出。

## 5. 关闭连接

Json
{
  "name": "close_ssh",
  "arguments": {
    "session_id": "a1b2c3d4-..."
  }
}
