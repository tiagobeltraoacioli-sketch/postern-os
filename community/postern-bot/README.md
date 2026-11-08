# Vestnik — community Telegram bot

A minimal, honest FAQ bot for the Postern Labs community group. Answers questions
about **Postern products** (and the ownerless protocol as context), grounded in
`system-prompt.md`, with hard guardrails:

- **Refuses price / investment questions** (up-front keyword filter **and** the
  system prompt) — the coin is not a security and not an asset, by design.
- **Never overclaims** security/privacy beyond the honest, audit-gated status.
- **Does not speak for the protocol** (it's ownerless) — only for Postern Labs.
- **Never asks for secrets** (seed/password/keys) and warns that the team never does.

Zero dependencies (Node 18+ built-in `fetch`). **Nothing is hardcoded**; bring your
own tokens via env, and no secret is ever logged.

## Run

```bash
export TELEGRAM_BOT_TOKEN=...        # from @BotFather
export ANTHROPIC_API_KEY=...         # your Claude API key (BYO-key model)
export ANTHROPIC_MODEL=claude-haiku-4-5-20251001   # optional; sonnet for richer answers
node community/postern-bot/bot.mjs
```

## Behaviour

- **Groups:** answers only messages that start with `/ask` (or `/postern`), or
  that reply to / @-mention the bot. Ordinary chatter is ignored.
- **Private chats:** answers any text.
- Splits long replies to Telegram's 4096-char limit; shows a typing indicator.

## Set-up notes (@BotFather)

1. Create the bot, get the token.
2. Recommended: `/setprivacy` → **Enable** (so in groups it only sees `/` commands
   and replies/@-mentions — less metadata, matches the honest posture).
3. Add the bot to the group; pin `../TELEGRAM-DISCLAIMER.md` as the rules.

## Honesty / privacy caveats

- **Telegram is not E2E** for groups and collects metadata. This bot is a
  reach/convenience tool, **not** a privacy recommendation — say so if asked.
- The bot sends each question to the Anthropic API (your key). Don't paste
  secrets to it; it will refuse and warn.
- Answers are only as current as `system-prompt.md` — update it when the honest
  status changes (e.g. after an audit, or when the k-ramp actually activates).

## License

MIT OR Apache-2.0.

## /announce (admins)

Group creator/administrators can post + pin an official notice: `/announce <text>`. Vestnik must be a group admin with **Pin Messages** rights. The command message is deleted after posting so only the clean pinned notice remains. Anyone else is refused.
