# Vestnik — Postern Labs community Telegram bot. A long-poller (no inbound port).
# SPDX-License-Identifier: MIT OR Apache-2.0
FROM node:20-slim
WORKDIR /app
# Only the two files the bot needs — no deps to install (Node built-in fetch).
COPY bot.mjs system-prompt.md ./
# Run unprivileged.
USER node
CMD ["node", "bot.mjs"]
