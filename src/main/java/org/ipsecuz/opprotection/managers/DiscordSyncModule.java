package org.ipsecuz.opprotection.managers;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.security.AttemptLimiter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/** One-time Discord verification requests with expiry, attempt limits and authorized approvers. */
public final class DiscordSyncModule {
    /** Discord snowflake IDs are 17-20 digit numeric strings. */
    private static final Pattern DISCORD_ID_PATTERN = Pattern.compile("\\d{17,20}");

    private final OPProtection plugin;
    private final SecureRandom random = new SecureRandom();
    private final AttemptLimiter codeLimiter = new AttemptLimiter(5, 60, 180);
    private final Set<String> protectedCommands = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Long> verifiedUntil = new ConcurrentHashMap<>();
    private final Map<UUID, Request> requestsByPlayer = new ConcurrentHashMap<>();
    private final Map<String, UUID> playerByRequestId = new ConcurrentHashMap<>();
    private volatile boolean enabled;
    private volatile long verificationTimeoutMillis;
    private volatile long requestTimeoutMillis;
    private volatile String unauthorizedAction;
    private volatile Set<Long> allowedApproverUsers = Set.of();
    private volatile Set<Long> allowedApproverRoles = Set.of();

    public DiscordSyncModule(OPProtection plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        enabled = plugin.getConfig().getBoolean("discord-sync.enabled", false);
        verificationTimeoutMillis = Math.max(30L,
                plugin.getConfig().getLong("discord-sync.verification-timeout-seconds", 300L)) * 1000L;
        requestTimeoutMillis = Math.max(30L,
                plugin.getConfig().getLong("discord-sync.request-timeout-seconds", 120L)) * 1000L;
        unauthorizedAction = plugin.getConfig().getString("discord-sync.unauthorized-action", "kick");
        allowedApproverUsers = Set.copyOf(parseIds(plugin.getConfig().getStringList("discord-sync.allowed-discord-user-ids"),
                "discord-sync.allowed-discord-user-ids"));
        allowedApproverRoles = Set.copyOf(parseIds(plugin.getConfig().getStringList("discord-sync.allowed-discord-role-ids"),
                "discord-sync.allowed-discord-role-ids"));
        protectedCommands.clear();
        for (String raw : plugin.getConfig().getStringList("discord-sync.commands")) {
            String value = normalizeCommand(raw);
            if (!value.isBlank()) protectedCommands.add(value);
        }
        codeLimiter.reload(plugin.getConfig().getInt("discord-sync.max-code-attempts", 5), 60,
                plugin.getConfig().getLong("discord-sync.code-lockout-seconds", 180));
        requestsByPlayer.clear();
        playerByRequestId.clear();
        verifiedUntil.clear();
        if (enabled) plugin.getLogger().info("[Discord-Sync] Bảo vệ " + protectedCommands.size() + " lệnh.");
    }

    public boolean commandRequiresSync(String command) {
        if (!enabled) return false;
        return protectedCommands.contains(normalizeCommand(command));
    }

    public boolean isPlayerVerified(Player player) {
        if (!enabled) return true;
        Long until = verifiedUntil.get(player.getUniqueId());
        if (until == null) return false;
        if (until <= System.currentTimeMillis()) {
            verifiedUntil.remove(player.getUniqueId(), until);
            return false;
        }
        return true;
    }

    public void verifyPlayer(Player player) {
        if (!enabled || player == null) return;
        verifiedUntil.put(player.getUniqueId(), System.currentTimeMillis() + verificationTimeoutMillis);
        removeRequest(player.getUniqueId());
        plugin.getSchedulerService().runEntity(player, () -> plugin.msg(player, "discord_sync_verified",
                Map.of("minutes", String.valueOf(verificationTimeoutMillis / 60_000L))));
        plugin.getAuditLog().write("DISCORD_SYNC_VERIFIED", player.getName(), player.getUniqueId().toString(), ip(player), "OK");
    }

    public void unverifyPlayer(Player player) {
        if (player == null) return;
        verifiedUntil.remove(player.getUniqueId());
        removeRequest(player.getUniqueId());
    }

    public void sendVerificationRequest(Player player) {
        if (!enabled || !plugin.isDiscordEnabled()) {
            plugin.msg(player, "discord_sync_unavailable");
            return;
        }
        removeRequest(player.getUniqueId());
        String requestId = randomHex(16);
        String code = String.format(Locale.ROOT, "%08d", random.nextInt(100_000_000));
        long expiresAt = System.currentTimeMillis() + requestTimeoutMillis;
        Request request = new Request(requestId, hash(code), expiresAt);
        requestsByPlayer.put(player.getUniqueId(), request);
        playerByRequestId.put(requestId, player.getUniqueId());

        String timestamp = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")
                .withZone(ZoneId.systemDefault()).format(Instant.now());
        Map<String, String> placeholders = new HashMap<>();
        placeholders.put("player", player.getName());
        placeholders.put("uuid", player.getUniqueId().toString());
        placeholders.put("ip", ip(player));
        placeholders.put("timestamp", timestamp);
        placeholders.put("code", code);
        placeholders.put("timeout", String.valueOf(requestTimeoutMillis / 60_000L));
        placeholders.put("request_id", requestId);
        plugin.getDiscord().sendEmbed("discord-sync-request", placeholders, true);
        plugin.msg(player, "discord_verify_request_sent");
        plugin.getAuditLog().write("DISCORD_SYNC_REQUEST", player.getName(), player.getUniqueId().toString(), ip(player), "request=" + requestId);
    }

    public void verifyCodeAsync(String targetName, String code, String issuer,
                                Consumer<VerificationResult> callback) {
        plugin.getSchedulerService().runGlobal(() -> {
            Player target = Bukkit.getPlayerExact(targetName);
            if (target == null) {
                callback.accept(VerificationResult.failure("Người chơi không online"));
                return;
            }
            plugin.getSchedulerService().runEntity(target,
                    () -> callback.accept(verifyCodeForPlayer(target, code, issuer)));
        });
    }

    private VerificationResult verifyCodeForPlayer(Player target, String code, String issuer) {
        if (!enabled || target == null || code == null) return VerificationResult.failure("Yêu cầu không hợp lệ");
        if (!target.isOnline()) return VerificationResult.failure("Người chơi không còn online");
        Request request = activeRequest(target.getUniqueId());
        if (request == null) return VerificationResult.failure("Không có yêu cầu đang chờ hoặc yêu cầu đã hết hạn");
        String limiterKey = target.getUniqueId() + ":discord-sync";
        AttemptLimiter.Result gate = codeLimiter.check(limiterKey);
        if (gate.locked()) return VerificationResult.failure("Tạm khóa do nhập sai quá nhiều lần");
        if (!MessageDigest.isEqual(request.codeHash, hash(code.trim()))) {
            AttemptLimiter.Result failure = codeLimiter.failure(limiterKey);
            plugin.getAuditLog().write("DISCORD_SYNC_CODE_FAILURE", target.getName(), target.getUniqueId().toString(), ip(target),
                    "issuer=" + issuer + ", locked=" + failure.locked());
            return VerificationResult.failure(failure.locked()
                    ? "Tạm khóa do nhập sai quá nhiều lần"
                    : "Mã không chính xác; còn " + failure.remainingAttempts() + " lần thử");
        }
        codeLimiter.success(limiterKey);
        verifyPlayer(target);
        return VerificationResult.approved(target.getName());
    }

    public void verifyFromDiscordAsync(String requestId, long userId, Set<Long> roleIds,
                                       Consumer<VerificationResult> callback) {
        UUID uuid = playerByRequestId.get(requestId);
        if (uuid == null) {
            callback.accept(VerificationResult.failure("Yêu cầu không tồn tại hoặc đã hết hạn"));
            return;
        }
        plugin.getSchedulerService().runGlobal(() -> {
            Player target = Bukkit.getPlayer(uuid);
            if (target == null) {
                removeRequest(uuid);
                callback.accept(VerificationResult.failure("Người chơi không còn online"));
                return;
            }
            plugin.getSchedulerService().runEntity(target,
                    () -> callback.accept(verifyFromDiscordForPlayer(requestId, userId, roleIds, target)));
        });
    }

    private VerificationResult verifyFromDiscordForPlayer(String requestId, long userId, Set<Long> roleIds,
                                                           Player target) {
        UUID uuid = target.getUniqueId();
        if (!target.isOnline()) {
            removeRequest(uuid);
            return VerificationResult.failure("Người chơi không còn online");
        }
        if (!isAuthorizedApprover(userId, roleIds)) {
            plugin.getAuditLog().write("DISCORD_APPROVER_DENIED", target.getName(), uuid.toString(), ip(target),
                    "discordUser=" + userId);
            return VerificationResult.failure("Tài khoản Discord này không được phép xác minh quản trị viên");
        }
        Request request = activeRequest(uuid);
        if (request == null || !request.requestId.equals(requestId)) {
            return VerificationResult.failure("Yêu cầu đã hết hạn hoặc bị thay thế");
        }
        verifyPlayer(target);
        plugin.getAuditLog().write("DISCORD_BUTTON_APPROVED", target.getName(), uuid.toString(), ip(target),
                "discordUser=" + userId);
        return VerificationResult.approved(target.getName());
    }

    private boolean isAuthorizedApprover(long userId, Set<Long> roleIds) {
        Set<Long> allowedUsers = allowedApproverUsers;
        Set<Long> allowedRoles = allowedApproverRoles;
        if (allowedUsers.isEmpty() && allowedRoles.isEmpty()) return false;
        if (allowedUsers.contains(userId)) return true;
        for (Long roleId : roleIds) if (allowedRoles.contains(roleId)) return true;
        return false;
    }

    public void handleUnauthorizedCommand(Player player, String command) {
        plugin.getAuditLog().write("DISCORD_SYNC_COMMAND_BLOCK", player.getName(), player.getUniqueId().toString(), ip(player), command);
        plugin.msg(player, "discord_sync_required");
        if (plugin.isDiscordEnabled()) {
            plugin.getDiscord().sendEmbed("discord-sync-alert", Map.of(
                    "player", player.getName(), "command", command, "action", "KICK"), false);
        }
        String action = unauthorizedAction.toLowerCase(Locale.ROOT);
        if (action.equals("shutdown") || action.equals("stop")) {
            // Removed: shutting the whole server down from an unverified session is a DoS
            // vector (any privileged-but-unverified admin could trigger it). The offending
            // session is deopped and kicked instead so privileges never survive.
            plugin.getLogger().severe("[Discord-Sync] unauthorized-action='" + unauthorizedAction
                    + "' da bi vo hieu hoa (rui ro DoS). Dung 'kick' hoac 'deop' trong config.");
            plugin.getAuditLog().write("DISCORD_SYNC_SHUTDOWN_BLOCKED", player.getName(),
                    player.getUniqueId().toString(), ip(player),
                    "shutdown action denied; deop+kick applied instead");
            action = "deop+kick";
        }
        switch (action) {
            case "deop+kick" -> {
                plugin.getSchedulerService().runEntity(player, () -> {
                    plugin.getOpManager().deauthorizePlayer(player, "Discord-Sync required");
                    if (player.isOnline()) {
                        player.kickPlayer(plugin.getMessage("discord_sync_kick_message"));
                    }
                });
            }
            case "deop" -> plugin.getSchedulerService().runEntity(player,
                    () -> plugin.getOpManager().deauthorizePlayer(player, "Discord-Sync required"));
            default -> plugin.getSchedulerService().runEntity(player,
                    () -> player.kickPlayer(plugin.getMessage("discord_sync_kick_message")));
        }
    }

    public long getRemainingVerificationTime(Player player) {
        Long until = verifiedUntil.get(player.getUniqueId());
        return until == null ? 0L : Math.max(0L, (until - System.currentTimeMillis()) / 1000L);
    }
    public long getVerificationTimeoutSeconds() { return verificationTimeoutMillis / 1000L; }
    public boolean isEnabled() { return enabled; }
    public Set<String> getProtectedCommands() { return Set.copyOf(protectedCommands); }

    private Request activeRequest(UUID uuid) {
        Request request = requestsByPlayer.get(uuid);
        if (request == null) return null;
        if (request.expiresAt <= System.currentTimeMillis()) {
            removeRequest(uuid);
            return null;
        }
        return request;
    }

    private void removeRequest(UUID uuid) {
        Request old = requestsByPlayer.remove(uuid);
        if (old != null) playerByRequestId.remove(old.requestId, uuid);
    }

    /**
     * Parse and validate Discord snowflake IDs. Invalid entries are reported with their
     * config path so a typo cannot silently disarm the approver whitelist.
     */
    private Set<Long> parseIds(List<String> raw, String configPath) {
        Set<Long> result = new HashSet<>();
        for (String value : raw) {
            String trimmed = value == null ? "" : value.trim();
            if (trimmed.isEmpty()) continue;
            if (!DISCORD_ID_PATTERN.matcher(trimmed).matches()) {
                plugin.getLogger().warning("[Discord-Sync] Discord ID khong hop le tai " + configPath
                        + ": '" + trimmed + "' (can 17-20 chu so, vi du 123456789012345678). Bo qua.");
                continue;
            }
            try {
                result.add(Long.parseUnsignedLong(trimmed));
            } catch (NumberFormatException ignored) {
                plugin.getLogger().warning("[Discord-Sync] Discord ID vuot gioi han so hoc tai "
                        + configPath + ": '" + trimmed + "'. Bo qua.");
            }
        }
        return result;
    }
    private static String normalizeCommand(String raw) {
        if (raw == null) return "";
        String command = raw.trim().toLowerCase(Locale.ROOT);
        while (command.startsWith("/")) command = command.substring(1);
        int space = command.indexOf(' ');
        if (space >= 0) command = command.substring(0, space);
        int colon = command.indexOf(':');
        return colon >= 0 ? command.substring(colon + 1) : command;
    }
    private static byte[] hash(String input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8)); }
        catch (Exception impossible) { throw new IllegalStateException(impossible); }
    }
    private String randomHex(int bytes) {
        byte[] value = new byte[bytes];
        random.nextBytes(value);
        return java.util.HexFormat.of().formatHex(value);
    }
    private static String ip(Player player) {
        return player.getAddress() == null ? "unknown" : player.getAddress().getAddress().getHostAddress();
    }

    private record Request(String requestId, byte[] codeHash, long expiresAt) { }
    public record VerificationResult(boolean success, String message, String playerName) {
        public static VerificationResult approved() { return new VerificationResult(true, "OK", null); }
        public static VerificationResult approved(String name) { return new VerificationResult(true, "OK", name); }
        public static VerificationResult failure(String message) { return new VerificationResult(false, message, null); }
    }
}
