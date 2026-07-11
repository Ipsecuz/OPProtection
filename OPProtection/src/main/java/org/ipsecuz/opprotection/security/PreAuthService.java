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
 * accepts only the expected offline UUID after confirming the profile exists, but continues to
 * require the normal password/console/Discord security flow and disables Premium 2FA bypass.</p>
 */
public final class PreAuthService {
    private static final long SESSION_TTL_MILLIS = 120_000L;

    private final OPProtection plugin;
    private final PremiumAccountChecker premiumChecker;
    private final Map<UUID, Session> sessions = new ConcurrentHashMap<>();

    private volatile Set<String> protectedNames = Set.of();
    private volatile boolean enabled;
    private volatile boolean premiumAutoBypass2FA;

    public PreAuthService(OPProtection plugin, PremiumAccountChecker premiumChecker) {
        this.plugin = plugin;
        this.premiumChecker = premiumChecker;
        reload();
    }

    public Decision preLogin(String name, UUID joinedUuid) {
        if (!isRequired(name)) return Decision.allow();
        if (joinedUuid == null) return Decision.deny("Không nhận được UUID đăng nhập");

        long now = System.currentTimeMillis();
        sessions.entrySet().removeIf(entry ->
                now - entry.getValue().createdAtMillis > SESSION_TTL_MILLIS
                        || entry.getValue().loginName.equalsIgnoreCase(name));

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

        if (!result.isStronglyVerified()) {
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
        if (System.currentTimeMillis() - session.createdAtMillis > SESSION_TTL_MILLIS) {
            reject(player, "Phiên Premium PreAuth đã hết hạn");
            return;
        }
        if (!session.joinedUuid.equals(player.getUniqueId())) {
            reject(player, "UUID khi join khác UUID đã kiểm tra ở pre-login");
            return;
        }
        if (session.level == VerificationLevel.VERIFIED_PREMIUM
                && session.officialUuid != null
                && !session.officialUuid.equals(player.getUniqueId())) {
            reject(player, "UUID khi join không còn khớp hồ sơ Premium đã xác minh");
            return;
        }
        if (session.level == VerificationLevel.STANDALONE_PROFILE_ONLY) {
            UUID expectedOffline = PremiumAccountChecker.offlineUuid(player.getName());
            if (!expectedOffline.equals(player.getUniqueId())) {
                reject(player, "UUID standalone offline-mode không đúng định dạng dự kiến");
                return;
            }
        }

        if (session.level == VerificationLevel.VERIFIED_PREMIUM) {
            markPremiumBypassIfEnabled(player.getUniqueId());
        } else {
            // A profile lookup or fail-open is never enough to bypass a second factor.
            plugin.clearPremium2FABypass(player.getUniqueId());
        }

        String event = switch (session.level) {
            case VERIFIED_PREMIUM -> "PREAUTH_PREMIUM_OK";
            case STANDALONE_PROFILE_ONLY -> "PREAUTH_STANDALONE_PROFILE_ONLY";
            case LOOKUP_BYPASS -> "PREAUTH_FAIL_OPEN";
        };
        String detail = switch (session.level) {
            case VERIFIED_PREMIUM -> "Official Premium UUID matched authenticated login UUID";
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
        return session != null && System.currentTimeMillis() - session.createdAtMillis <= SESSION_TTL_MILLIS;
    }

    public boolean isStronglyVerified(Player player) {
        if (player == null || !isRequired(player.getName())) return true;
        Session session = sessions.get(player.getUniqueId());
        return session != null && session.level == VerificationLevel.VERIFIED_PREMIUM;
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

    private record Session(
            String loginName,
            String officialName,
            UUID officialUuid,
            UUID joinedUuid,
            VerificationLevel level,
            long createdAtMillis
    ) { }

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
