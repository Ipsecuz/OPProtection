package org.ipsecuz.opprotection.security;

import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.security.PremiumAccountChecker.PremiumResult;
import org.ipsecuz.opprotection.security.PremiumAccountChecker.VerificationLevel;

import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Protects configured administrator accounts before their privileged session is unlocked.
 *
 * <p>For online-mode and secure proxy forwarding, the official Premium UUID is used as
 * cryptographic-session evidence. For a standalone offline-mode server, Bukkit receives only
 * an offline UUID and cannot prove ownership of the Mojang account. OPProtection therefore
 * accepts only the expected offline UUID after confirming the profile exists, and marks the
 * session PREMIUM_PRE (nLogin-style). The Premium 2FA bypass is controlled exclusively by
 * {@code premium-auth.op-whitelist-premium-auto-bypass-2fa}; password verification itself is
 * never skipped on cracked servers (only strongly verified online/proxy sessions may skip it).</p>
 */
public final class PreAuthService {
    private static final long MIN_SESSION_TTL_MILLIS = 30_000L;
    private static final long MAX_SESSION_TTL_MILLIS = 3_600_000L;

    private final OPProtection plugin;
    private final PremiumAccountChecker premiumChecker;
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();

    private volatile Set<String> protectedNames = Set.of();
    private volatile boolean enabled;
    private volatile boolean premiumAutoBypass2FA;
    private volatile long sessionTtlMillis = 120_000L;

    public PreAuthService(OPProtection plugin, PremiumAccountChecker premiumChecker) {
        this.plugin = plugin;
        this.premiumChecker = premiumChecker;
        reload();
    }

    public Decision preLogin(String name, UUID joinedUuid) {
        if (!isRequired(name)) return Decision.allow();
        if (joinedUuid == null) return Decision.deny("Không nhận được UUID đăng nhập");

        long now = System.currentTimeMillis();
        long ttl = sessionTtlMillis;
        // Evict stale pre-login sessions. Sessions already validated on join belong to
        // live players and must never be dropped just because the TTL elapsed.
        sessions.entrySet().removeIf(entry -> {
            Session session = entry.getValue();
            return session.joinedValidated
                    ? session.loginName.equalsIgnoreCase(name)
                    : now - session.createdAtMillis > ttl
                            || session.loginName.equalsIgnoreCase(name);
        });

        PremiumResult result = premiumChecker.check(name, joinedUuid);
        if (!result.isValid()) {
            return Decision.deny(result.getReason());
        }

        Session session = new Session(
                name,
                result.getOfficialName(),
                result.getOfficialUuid(),
                joinedUuid,
                result.getLevel(),
                now
        );
        sessions.put(joinedUuid, session);

        // PREMIUM_PRE is the designed nLogin-like state on cracked servers, not a
        // warning condition; profile-only and fail-open results still warn loudly.
        if (!result.isStronglyVerified() && !result.isPremiumPre()) {
            return Decision.allowWithWarning(result.getReason());
        }
        return Decision.allow();
    }

    public void validateOnJoin(Player player) {
        if (player == null || !isRequired(player.getName())) return;

        Session session = sessions.get(player.getUniqueId());
        if (session == null) {
            reject(player, "Không có phiên Premium PreAuth hợp lệ");
            return;
        }
        if (!session.joinedValidated
                && System.currentTimeMillis() - session.createdAtMillis > sessionTtlMillis) {
            reject(player, "Phiên Premium PreAuth đã hết hạn");
            return;
        }
        if (!session.joinedUuid.equals(player.getUniqueId())) {
            reject(player, "UUID khi join khác UUID đã kiểm tra ở pre-login");
            return;
        }
        if ((session.level == VerificationLevel.VERIFIED_PREMIUM
                || session.level == VerificationLevel.VERIFIED_PREMIUM_BYPASS)
                && session.officialUuid != null
                && !session.officialUuid.equals(player.getUniqueId())) {
            reject(player, "UUID khi join không còn khớp hồ sơ Premium đã xác minh");
            return;
        }
        if (session.level == VerificationLevel.STANDALONE_PROFILE_ONLY
                || session.level == VerificationLevel.PREMIUM_PRE
                || session.level == VerificationLevel.VERIFIED_PREMIUM_BYPASS) {
            UUID expectedOffline = PremiumAccountChecker.offlineUuid(player.getName());
            if (!expectedOffline.equals(player.getUniqueId())) {
                reject(player, "UUID standalone offline-mode không đúng định dạng dự kiến");
                return;
            }
        }

        // Bind this session to the live join; from here it stays valid until quit
        // so a slow admin typing the oppass is never blocked by the pre-login TTL.
        session.markJoinedValidated();

        if (session.level == VerificationLevel.VERIFIED_PREMIUM
                || session.level == VerificationLevel.VERIFIED_PREMIUM_BYPASS
                || session.level == VerificationLevel.PREMIUM_PRE) {
            markPremiumBypassIfEnabled(player.getUniqueId());
        } else {
            // A profile lookup or fail-open is never enough to bypass a second factor.
            plugin.clearPremium2FABypass(player.getUniqueId());
        }

        String event = switch (session.level) {
            case VERIFIED_PREMIUM -> "PREAUTH_PREMIUM_OK";
            case VERIFIED_PREMIUM_BYPASS -> "PREAUTH_PREMIUM_BYPASS_OK";
            case PREMIUM_PRE -> "PREAUTH_PREMIUM_PRE";
            case STANDALONE_PROFILE_ONLY -> "PREAUTH_STANDALONE_PROFILE_ONLY";
            case LOOKUP_BYPASS -> "PREAUTH_FAIL_OPEN";
        };
        String detail = switch (session.level) {
            case VERIFIED_PREMIUM -> "Official Premium UUID matched authenticated login UUID";
            case VERIFIED_PREMIUM_BYPASS -> "Cracked-mode premium bypass via admin registry; 2FA bypass still gated by op-whitelist-premium-auto-bypass-2fa";
            case PREMIUM_PRE ->
                    "nLogin-like PRE: premium name detected on cracked server; oppass still required, 2FA bypass gated by op-whitelist-premium-auto-bypass-2fa";
            case STANDALONE_PROFILE_ONLY ->
                    "Premium profile exists; standalone offline-mode requires password and secondary verification";
            case LOOKUP_BYPASS -> "Lookup unavailable; fail-open accepted without Premium 2FA bypass";
        };
        plugin.getAuditLog().write(
                event,
                player.getName(),
                player.getUniqueId().toString(),
                player.getAddress() == null ? "unknown" : player.getAddress().getAddress().getHostAddress(),
                detail
        );
    }

    private void reject(Player player, String reason) {
        sessions.remove(player.getUniqueId());
        plugin.getLogger().warning("[PreAuth] Từ chối " + player.getName() + ": " + reason);
        plugin.getAuditLog().write(
                "PREAUTH_REJECT",
                player.getName(),
                player.getUniqueId().toString(),
                player.getAddress() == null ? "unknown" : player.getAddress().getAddress().getHostAddress(),
                reason
        );
        plugin.getOpManager().deauthorizePlayer(player, "PreAuth thất bại");
        plugin.getSchedulerService().runEntity(player,
                () -> player.kickPlayer(plugin.getMessage("premium_auth_rejected")));
    }

    private void markPremiumBypassIfEnabled(UUID uuid) {
        if (premiumAutoBypass2FA) plugin.markPremium2FABypass(uuid);
    }

    public boolean isSatisfied(Player player) {
        if (player == null || !isRequired(player.getName())) return true;
        Session session = sessions.get(player.getUniqueId());
        if (session == null) return false;
        // Once the session survived join validation it belongs to a live player and
        // remains satisfied until quit; the TTL only guards the pre-login window.
        return session.joinedValidated
                || System.currentTimeMillis() - session.createdAtMillis <= sessionTtlMillis;
    }

    public boolean isStronglyVerified(Player player) {
        if (player == null || !isRequired(player.getName())) return true;
        Session session = sessions.get(player.getUniqueId());
        return session != null && (session.level == VerificationLevel.VERIFIED_PREMIUM
                || session.level == VerificationLevel.VERIFIED_PREMIUM_BYPASS);
    }

    public boolean isPremiumAutoBypassEnabled() {
        return premiumAutoBypass2FA;
    }

    /** The complete Premium decision is made during asynchronous pre-login. */
    public boolean isPending(Player player) {
        return false;
    }

    public void quit(UUID uuid) {
        sessions.remove(uuid);
        plugin.clearPremium2FABypass(uuid);
    }

    public void reload() {
        Set<String> names = new HashSet<>();
        for (String value : plugin.getConfig().getStringList("op-whitelist")) {
            if (value != null && !value.isBlank()) {
                names.add(value.trim().toLowerCase(Locale.ROOT));
            }
        }
        this.protectedNames = Set.copyOf(names);
        this.enabled = plugin.getConfig().getBoolean("premium-auth.enabled", false);
        this.premiumAutoBypass2FA = plugin.getConfig().getBoolean(
                "premium-auth.op-whitelist-premium-auto-bypass-2fa", false);
        this.sessionTtlMillis = Math.max(MIN_SESSION_TTL_MILLIS, Math.min(MAX_SESSION_TTL_MILLIS,
                plugin.getConfig().getLong("premium-auth.pre-session-ttl-seconds", 120L) * 1000L));

        if (!enabled) {
            sessions.clear();
        } else {
            sessions.entrySet().removeIf(entry -> !protectedNames.contains(
                    entry.getValue().loginName.toLowerCase(Locale.ROOT)));
        }
    }

    private boolean isRequired(String name) {
        return enabled && name != null && protectedNames.contains(name.toLowerCase(Locale.ROOT));
    }

    /** Mutable session state shared between async pre-login and join-time validation threads. */
    private static final class Session {
        private final String loginName;
        private final String officialName;
        private final UUID officialUuid;
        private final UUID joinedUuid;
        private final VerificationLevel level;
        private final long createdAtMillis;
        private volatile boolean joinedValidated;

        private Session(String loginName, String officialName, UUID officialUuid,
                        UUID joinedUuid, VerificationLevel level, long createdAtMillis) {
            this.loginName = loginName;
            this.officialName = officialName;
            this.officialUuid = officialUuid;
            this.joinedUuid = joinedUuid;
            this.level = level;
            this.createdAtMillis = createdAtMillis;
        }

        private void markJoinedValidated() { this.joinedValidated = true; }
    }

    public record Decision(boolean allowed, boolean warning, String reason) {
        public static Decision allow() {
            return new Decision(true, false, "OK");
        }

        public static Decision allowWithWarning(String reason) {
            return new Decision(true, true, reason);
        }

        public static Decision deny(String reason) {
            return new Decision(false, false, reason);
        }
    }
}
