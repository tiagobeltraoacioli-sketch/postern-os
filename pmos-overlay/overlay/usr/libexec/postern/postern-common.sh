# Shared shell helpers for the Postern OpenRC services.
# POSIX sh. Sourced (not executed) by the init scripts in /etc/init.d.
# UNBOOTED: written against Alpine busybox adduser/addgroup semantics; never
# run on a device yet (see overlay/README.md).

# Least-privilege identity the node/wallet/tor services run as.
POSTERN_USER="postern"
POSTERN_GROUP="postern"
POSTERN_HOME="/var/lib/postern"

# Create the dedicated system user/group if missing. Idempotent: safe to call
# from every service's start_pre(). Uses busybox adduser/addgroup flags
# (Alpine): -S system account, -D no password, -H no home create here (we make
# the dir ourselves with tight perms), -s nologin shell, -G primary group.
postern_ensure_user() {
	if ! getent group "$POSTERN_GROUP" >/dev/null 2>&1; then
		addgroup -S "$POSTERN_GROUP"
	fi
	if ! getent passwd "$POSTERN_USER" >/dev/null 2>&1; then
		adduser -S -D -H -h "$POSTERN_HOME" -s /sbin/nologin \
			-G "$POSTERN_GROUP" "$POSTERN_USER"
	fi
}

# Create a data directory owned by the postern user with 0700 perms.
# Usage: postern_ensure_dir /var/lib/postern/arti
postern_ensure_dir() {
	dir="$1"
	checkpath -d -m 0700 -o "$POSTERN_USER":"$POSTERN_GROUP" "$dir"
}
