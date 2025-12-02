from astrbot.api.event import AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
import re

@register("promptguard", "YourName", "防提示词注入安全插件", "1.0.0")
class PromptGuardPlugin(Star):
    def __init__(self, context: Context):
        super().__init__(context)
        self.injection_patterns = [
            (r"ignore.*previous.*instructions?", "忽略指令攻击"),
            (r"forget.*you.*are.*chatgpt", "角色欺骗攻击"),
            (r"system.*prompt.*leak", "系统提示词泄露"),
            (r"扮演.*(角色|人物)", "角色扮演攻击"),
            (r"假装.*你是", "伪装攻击"),
            (r"what.*were.*your.*initial.*instructions", "初始指令询问"),
            (r"你的.*初始.*指令", "中文初始指令询问"),
            (r"system32", "系统文件引用攻击"),
            (r"root.*access|管理员.*权限", "权限提升攻击"),
            (r"bypass.*restrictions|绕过.*限制", "绕过限制攻击"),
            (r"disregard.*all.*previous", "无视所有先前指令"),
            (r"从.*现在.*开始", "重置指令攻击"),
            (r"human.*mode|人类.*模式", "人类模式欺骗"),
            (r"override.*system|覆盖.*系统", "系统覆盖攻击"),
            (r"ignore.*your.*rules", "规则忽略攻击"),
            (r"breaking.*character|打破.*角色", "角色打破攻击"),
            (r"你是.*(吗|么)\?", "身份确认攻击"),
            (r"回答.*以下.*内容", "强制回复攻击"),
            (r"输出.*所有.*信息", "信息泄露攻击"),
            (r"忘记.*你.*是.*AI", "AI身份否认"),
            (r"模拟.*(对话|聊天)", "模拟对话攻击"),
            (r"删除.*系统.*提示", "删除提示攻击"),
            (r"显示.*隐藏.*内容", "隐藏内容显示"),
            (r"administrator.*privileges", "管理员权限攻击"),
            (r"sudo.*command", "sudo命令攻击"),
            (r"执行.*命令", "命令执行攻击"),
            (r"查看.*文件", "文件查看攻击"),
            (r"修改.*配置", "配置修改攻击"),
        ]
        self.suspicious_threshold = 2
        self.blocked_count = 0

    async def initialize(self):
        logger.info("PromptGuard插件已启动，正在保护系统安全...")

    def check_prompt_injection(self, text: str) -> dict:
        text_lower = text.lower()
        detection_result = {
            "is_malicious": False,
            "detected_patterns": [],
            "warning_level": "safe",
            "matched_patterns": []
        }
        for pattern, description in self.injection_patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    detection_result["detected_patterns"].append(description)
                    detection_result["matched_patterns"].append(pattern)
            except re.error:
                logger.warning(f"正则表达式错误: {pattern}")

        suspicious_keywords = [
            "ignore", "forget", "previous", "instructions", "system",
            "prompt", "leak", "bypass", "override", "disregard",
            "忽略", "忘记", "先前", "指令", "系统",
            "提示", "泄露", "绕过", "覆盖", "无视"
        ]
        found_keywords = [kw for kw in suspicious_keywords if kw in text_lower]

        if detection_result["detected_patterns"]:
            detection_result["is_malicious"] = True
            detection_result["warning_level"] = "high"
        elif len(found_keywords) >= self.suspicious_threshold:
            detection_result["is_malicious"] = True
            detection_result["warning_level"] = "medium"
            detection_result["detected_patterns"].append(f"多个可疑关键词: {', '.join(found_keywords)}")
        return detection_result

    def sanitize_message(self, text: str) -> str:
        sanitized = text
        sanitized = re.sub(r'[\x00-\x1F\x7F\u200B-\u200F\u2028-\u202F\u205F-\u206F]', '', sanitized)
        sanitized = re.sub(r'(.)\1{10,}', r'\1\1\3', sanitized)
        return sanitized

    def log_injection_attempt(self, event: AstrMessageEvent, detection_result: dict):
        user_id = getattr(event, 'sender_id', "未知")
        user_name = event.get_sender_name()
        message = event.message_str[:100]
        logger.warning(
            f"检测到提示词注入尝试！\n"
            f"用户: {user_name} (ID: {user_id})\n"
            f"消息: {message}\n"
            f"检测模式: {', '.join(detection_result['detected_patterns'])}\n"
            f"危险等级: {detection_result['warning_level']}"
        )
        self.blocked_count += 1

    async def on_message(self, event: AstrMessageEvent):
        """4.7.4 全局消息拦截必须实现 Star 的 on_message 方法"""
        try:
            message_text = event.message_str
            if not message_text or message_text.strip() == "":
                return
            sanitized_text = self.sanitize_message(message_text)
            detection_result = self.check_prompt_injection(sanitized_text)
            if detection_result["is_malicious"]:
                self.log_injection_attempt(event, detection_result)
                blocked_msg = (
                    "⚠️ 安全警告 ⚠️\n"
                    "检测到可能的提示词注入攻击！\n"
                    "您的输入内容不合规，已被拦截。\n"
                    f"检测到的威胁类型: {', '.join(detection_result['detected_patterns'][:3])}\n"
                    "如有疑问，请联系管理员。"
                )
                await event.reply(blocked_msg)
                return MessageEventResult(blocked=True)
        except Exception as e:
            logger.error(f"防护插件处理消息时出错: {str(e)}")

    async def terminate(self):
        logger.info(f"PromptGuard插件已停止，总共拦截了 {self.blocked_count} 次攻击")
