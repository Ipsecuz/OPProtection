package org.ipsecuz.opprotection.managers;

import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;

/** Trusted-IP storage helper. IP is an audit signal only and never bypasses password/2FA. */
public final class IPManager {
    private final OPProtection plugin;
    public IPManager(OPProtection plugin) { this.plugin = plugin; }
    public void reload() { }
    public void loadIPs() { }
    public void saveIPs() { plugin.getSecurityDataStore().requestSave(); }
    public void addOrUpdateIP(Player player) {
        if (player != null && player.getAddress() != null) {
            plugin.getSecurityDataStore().setTrustedIp(player.getUniqueId(), player.getAddress().getAddress().getHostAddress());
        }
    }
    public boolean isIPAllowed(Player player) { return true; }
    public void resetIP(String playerName) {
        Player player = plugin.getServer().getPlayerExact(playerName);
        if (player != null) plugin.getSecurityDataStore().resetTrustedIp(player.getUniqueId());
    }
    public String getIP(String playerName) {
        Player player = plugin.getServer().getPlayerExact(playerName);
        return player == null ? "unknown" : plugin.getSecurityDataStore().getTrustedIp(player.getUniqueId());
    }
    public String getBlockMessage() { return plugin.getMessage("geoip_block_message"); }
    public void onPlayerJoin(Player player) { }
    public void updatePlayerIP(Player player) { addOrUpdateIP(player); }
}
