package org.ipsecuz.opprotection.managers;

import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;

import java.util.UUID;

/**
 * Trusted-IP facade over {@link org.ipsecuz.opprotection.storage.SecurityDataStore}.
 * IP is an audit signal only and never bypasses password/2FA.
 *
 * <p>The data store is loaded eagerly by {@link org.ipsecuz.opprotection.storage.SecurityDataStore}
 * and persists asynchronously, so this class only forwards operations; it holds no state of
 * its own. {@link #onPlayerJoin(Player)} intentionally does NOT overwrite the trusted IP —
 * doing so would silence the Discord IP-change alert — the trusted IP is refreshed only
 * after a successful verification (see OpManager#unlockPlayer).</p>
 */
public final class IPManager {
    private final OPProtection plugin;
    public IPManager(OPProtection plugin) { this.plugin = plugin; }
    public void reload() { }
    /** No-op: the security data store loads its state eagerly at construction time. */
    public void loadIPs() { }
    public void saveIPs() { plugin.getSecurityDataStore().requestSave(); }
    public void addOrUpdateIP(Player player) {
        if (player != null && player.getAddress() != null) {
            plugin.getSecurityDataStore().setTrustedIp(player.getUniqueId(), player.getAddress().getAddress().getHostAddress());
        }
    }
    /**
     * Informational check only: true when the player's current IP matches the stored
     * trusted IP, or when no trusted IP is known yet. Never used to bypass verification.
     */
    public boolean isIPAllowed(Player player) {
        if (player == null) return false;
        if (player.getAddress() == null) return false;
        String trusted = plugin.getSecurityDataStore().getTrustedIp(player.getUniqueId());
        if (trusted == null || trusted.isBlank() || "unknown".equals(trusted)) return true;
        return trusted.equals(player.getAddress().getAddress().getHostAddress());
    }
    public void resetIP(String playerName) {
        UUID target = resolveUuid(playerName);
        if (target != null) plugin.getSecurityDataStore().resetTrustedIp(target);
    }
    public String getIP(String playerName) {
        UUID target = resolveUuid(playerName);
        return target == null ? "unknown" : plugin.getSecurityDataStore().getTrustedIp(target);
    }
    public String getBlockMessage() { return plugin.getMessage("geoip_block_message"); }
    /** Deliberately passive: trusted IPs are only updated after successful verification. */
    public void onPlayerJoin(Player player) { }
    public void updatePlayerIP(Player player) { addOrUpdateIP(player); }

    private UUID resolveUuid(String playerName) {
        if (playerName == null || playerName.isBlank()) return null;
        Player online = plugin.getServer().getPlayerExact(playerName);
        if (online != null) return online.getUniqueId();
        OfflinePlayer offline = Bukkit.getOfflinePlayer(playerName);
        return offline == null ? null : offline.getUniqueId();
    }
}
