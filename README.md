# honeypot-bot

A Discord bot that catches compromised user accounts via a honeypot channel.

When any user sends a message in `#do-not-use`, the bot immediately bans them (deleting their last hour of messages) and then automatically unbans them. The ban/unban cycle cleans up spam while allowing the legitimate account owner to rejoin once they've regained control.

The bot creates the `#do-not-use` channel under a **Server Security** category in every guild it joins, if the channel doesn't already exist.

## Setup

### Prerequisites

- Python 3.12+
- A Discord bot token with **Ban Members** and **Manage Channels** permissions
- The bot's role must be positioned above any roles you want it to be able to ban

### Running locally

```bash
cp .env.example .env
# Add your bot token to .env
pip install -r requirements.txt
python bot.py
```

### Running with Docker

```bash
docker build -t honeypot-bot .
docker run --env-file .env honeypot-bot
```

## Environment variables

| Variable | Description |
|---|---|
| `DISCORD_TOKEN` | Your Discord bot token |

## Bot permissions required

| Permission | Reason |
|---|---|
| Ban Members | Ban and unban triggered users |
| Manage Channels | Create `#do-not-use` on guild join |
| Read Messages / View Channels | Detect messages in the honeypot channel |

## License

[MIT](LICENSE)
