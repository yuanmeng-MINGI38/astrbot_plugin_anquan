from astrbot.api.event import filter, AstrMessageEvent, MessageEventResult
from astrbot.api.star import Context, Star, register
from astrbot.api import logger
import re

@register("PromptInjectionGuard", "YourName", "防止提示词注入攻击", "1.0.0")
class PromptInjectionGuard(Star):
    def __init__(self, context: Context):
        super().__init__(context)

        # 常见提示词注入攻击关键词
        self.injection_patterns = [
            r"忽略之前的要求",
            r"忽略上面的内容",
            r"你现在的规则是",
            r"无视前面的规则",
            r"请你扮演",
            r"越狱模式",
            r"我希望你假装",
            r"现在不要遵守",
            r"禁止遵守规则",
            r"摆脱限制",
            r"绕过限制",
            r"你必须服从",
            r"现在开始你是",
            r"我要求你执行",
            r"覆盖你的指令",
            r"你被解除限制",
        ]

    async def initialize(self):
        logger.info("🛡️ Prompt Injection Guard 启动成功")

    @filter.message()
    async def filter_prompt_injection(self, event: AstrMessageEvent):
        msg = event.message_str
        
        # 扫描是否包含注入关键句
        for pattern in self.injection_patterns:
            if re.search(pattern, msg, re.IGNORECASE):
                logger.warning(f"⚠️ 检测到疑似提示词注入攻击: {msg}")

                yield event.plain_result("⚠️ 你输入的内容不合规，已拦截")
                
                return MessageEventResult.IGNORE  # 阻止后续插件执行

        return MessageEventResult.CONTINUE

    async def terminate(self):
        logger.info("🛡️ Prompt Injection Guard 插件已卸载")
