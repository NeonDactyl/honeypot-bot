import asyncio
import logging
import os

import discord
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

HONEYPOT_CHANNEL_NAME = "do-not-use"
HONEYPOT_CATEGORY_NAME = "Server Security"
DELETE_MESSAGE_SECONDS = 3600  # delete last 1 hour of messages on ban

intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True
intents.members = True

bot = discord.Client(intents=intents)


async def ensure_honeypot_channel(guild: discord.Guild) -> discord.TextChannel:
    existing = discord.utils.get(guild.text_channels, name=HONEYPOT_CHANNEL_NAME)
    if existing:
        return existing

    category = discord.utils.get(guild.categories, name=HONEYPOT_CATEGORY_NAME)
    if not category:
        category = await guild.create_category(HONEYPOT_CATEGORY_NAME)
        log.info("Created category '%s' in guild '%s'", HONEYPOT_CATEGORY_NAME, guild.name)

    channel = await guild.create_text_channel(
        HONEYPOT_CHANNEL_NAME,
        category=category,
        topic=(
            "WARNING: Do not send messages in this channel. "
            "Sending a message here will result in an automatic ban."
        ),
    )
    log.info("Created honeypot channel in guild '%s'", guild.name)
    return channel


@bot.event
async def on_ready():
    log.info("Logged in as %s (id=%s)", bot.user, bot.user.id)
    for guild in bot.guilds:
        try:
            await ensure_honeypot_channel(guild)
        except discord.Forbidden:
            log.warning("Missing permissions to create channel in guild '%s'", guild.name)
        except discord.HTTPException as exc:
            log.error("HTTP error setting up guild '%s': %s", guild.name, exc)


@bot.event
async def on_guild_join(guild: discord.Guild):
    log.info("Joined guild '%s'", guild.name)
    try:
        await ensure_honeypot_channel(guild)
    except discord.Forbidden:
        log.warning("Missing permissions to create channel in guild '%s'", guild.name)
    except discord.HTTPException as exc:
        log.error("HTTP error setting up guild '%s': %s", guild.name, exc)


@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return
    if not message.guild:
        return
    if message.channel.name != HONEYPOT_CHANNEL_NAME:
        return

    guild = message.guild
    user = message.author

    log.warning(
        "Honeypot triggered by %s (id=%s) in guild '%s'",
        user,
        user.id,
        guild.name,
    )

    try:
        await guild.ban(
            user,
            reason="Honeypot channel triggered — possible compromised account",
            delete_message_seconds=DELETE_MESSAGE_SECONDS,
        )
        log.info("Banned %s from guild '%s'", user, guild.name)
    except discord.Forbidden:
        log.error("Missing ban permission in guild '%s'", guild.name)
        return
    except discord.HTTPException as exc:
        log.error("Failed to ban %s: %s", user, exc)
        return

    bans_channel = discord.utils.get(guild.text_channels, name="bans")
    if bans_channel:
        try:
            content_preview = f'\n> {message.content}' if message.content else "(no text)"
            await bans_channel.send(f"{user.name} ({user.id}) - {HONEYPOT_CHANNEL_NAME}{content_preview}")
        except discord.HTTPException as exc:
            log.error("Failed to log to #bans in guild '%s': %s", guild.name, exc)

    # Brief pause so the ban audit log entry is written before unban
    await asyncio.sleep(2)

    try:
        await guild.unban(
            user,
            reason="Automatic unban after honeypot detection — account may have been compromised",
        )
        log.info("Unbanned %s from guild '%s'", user, guild.name)
    except discord.Forbidden:
        log.error("Missing unban permission in guild '%s'", guild.name)
    except discord.HTTPException as exc:
        log.error("Failed to unban %s: %s", user, exc)


token = os.environ.get("DISCORD_TOKEN")
if not token:
    raise RuntimeError("DISCORD_TOKEN environment variable is not set")

bot.run(token)
