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

# max_ratelimit_timeout=None (the default) makes discord.py wait out any HTTP
# rate limit and retry, rather than raising. We set it explicitly to document
# that 429s are handled by the SDK; the dedupe below keeps us from generating
# the request bursts that triggered rate limiting in the first place.
bot = discord.Client(intents=intents, max_ratelimit_timeout=None)

# Guild+user IDs currently being banned. A compromised account often spams the
# honeypot channel, and each message arrives as its own on_message event. Without
# this guard a single spammer triggers N ban/unban cycles back-to-back, which is
# what got us rate limited by Discord.
_processing: set[tuple[int, int]] = set()


# Per-guild locks so overlapping on_ready / on_guild_join runs (on_ready fires
# again on every gateway reconnect) can't both decide to create the channel.
_setup_locks: dict[int, asyncio.Lock] = {}


async def ensure_honeypot_channel(guild: discord.Guild) -> discord.TextChannel | None:
    if guild.unavailable:
        log.warning("Guild %s is unavailable; skipping honeypot setup", guild.id)
        return None

    lock = _setup_locks.setdefault(guild.id, asyncio.Lock())
    async with lock:
        return await _ensure_honeypot_channel(guild)


async def _ensure_honeypot_channel(guild: discord.Guild) -> discord.TextChannel:
    # Ask the API rather than trusting the gateway cache, which can be empty or
    # partial right after a (re)connect — that's how we ended up with duplicates.
    channels = await guild.fetch_channels()

    # If earlier runs left duplicates behind, keep the oldest (lowest snowflake
    # ID) and delete the rest.
    honeypots = sorted(
        (c for c in channels if c.name == HONEYPOT_CHANNEL_NAME and c.type == discord.ChannelType.text),
        key=lambda c: c.id,
    )
    categories = sorted(
        (c for c in channels if c.name == HONEYPOT_CATEGORY_NAME and c.type == discord.ChannelType.category),
        key=lambda c: c.id,
    )

    for dup in honeypots[1:]:
        await dup.delete(reason="Duplicate honeypot channel")
        log.info("Deleted duplicate honeypot channel %s in guild '%s'", dup.id, guild.name)

    removed = {c.id for c in honeypots[1:]}
    for dup in categories[1:]:
        # Only remove the category if nothing else lives in it, so we never
        # orphan channels an admin put there.
        if any(c.category_id == dup.id and c.id not in removed for c in channels):
            log.warning(
                "Duplicate category %s in guild '%s' is not empty; leaving it",
                dup.id,
                guild.name,
            )
            continue
        await dup.delete(reason="Duplicate honeypot category")
        log.info("Deleted duplicate category %s in guild '%s'", dup.id, guild.name)

    if honeypots:
        return honeypots[0]

    category = categories[0] if categories else None
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

    # Skip if we're already banning this user (e.g. they spammed the channel).
    key = (guild.id, user.id)
    if key in _processing:
        return
    _processing.add(key)

    try:
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
    finally:
        _processing.discard(key)


token = os.environ.get("DISCORD_TOKEN")
if not token:
    raise RuntimeError("DISCORD_TOKEN environment variable is not set")

bot.run(token)
