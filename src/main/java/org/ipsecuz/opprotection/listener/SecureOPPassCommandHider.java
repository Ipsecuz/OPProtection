package org.ipsecuz.opprotection.listener;

import java.util.Locale;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.command.CommandOPPass;

public final class SecureOPPassCommandHider implements Listener {
    private final OPProtection plugin;
    private final CommandOPPass command;

    public SecureOPPassCommandHider(OPProtection plugin, CommandOPPass command) {
        this.plugin = plugin;
        this.command = command;
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = false)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        String message = event.getMessage();
        if (!isOPPassCommand(message)) {
            return;
        }

        Player player = event.getPlayer();
        event.setMessage("/oppass [protected]");
        event.setCancelled(true);

        try {
            this.command.handlePlayerCommandLine(player, message);
        } catch (Exception ex) {
            this.plugin.getLogger().warning("[SecureOPPass] Could not process protected /oppass input for " + player.getName() + ": " + ex.getMessage());
            this.plugin.msg(player, "oppass_internal_error");
        }
    }

    private boolean isOPPassCommand(String message) {
        if (message == null || message.isBlank()) {
            return false;
        }
        String trimmed = message.trim();
        if (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        String label = trimmed.split("\\s+", 2)[0].toLowerCase(Locale.ROOT);
        int namespace = label.indexOf(':');
        if (namespace >= 0 && namespace + 1 < label.length()) {
            label = label.substring(namespace + 1);
        }
        return label.equals("oppass");
    }
}
