import abc
from typing import List

import httpx


class Channel(abc.ABC):
    """Delivery backend. Subclasses self-register; declare required_env and build_channels() picks them up."""

    name = "channel"
    required_env: tuple = ()
    registry: list = []

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        Channel.registry.append(cls)

    @classmethod
    def from_env(cls, env):
        # __init__ parameters must line up with required_env order.
        return cls(*(env[var] for var in cls.required_env))

    @abc.abstractmethod
    async def send(self, message: str) -> None: ...


class SlackChannel(Channel):
    name = "slack"
    required_env = ("SLACK_WEBHOOK_URL",)

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send(self, message: str) -> None:
        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(self.webhook_url, json={"text": message}, timeout=10.0)
            response.raise_for_status()


class TelegramChannel(Channel):
    name = "telegram"
    required_env = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID")

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id

    async def send(self, message: str) -> None:
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(url, json={"chat_id": self.chat_id, "text": message}, timeout=10.0)
            response.raise_for_status()


class StdoutChannel(Channel):
    name = "stdout"

    async def send(self, message: str) -> None:
        print(f"[ALERT] {message}", flush=True)


def build_channels(env) -> List[Channel]:
    # Stdout is always on so the log shows every alert, delivered or not.
    channels = [cls.from_env(env) for cls in Channel.registry
                if cls.required_env and all(env.get(var) for var in cls.required_env)]
    channels.append(StdoutChannel())
    return channels
