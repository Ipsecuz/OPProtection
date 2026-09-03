package org.ipsecuz.opprotection.listener;

import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.server.ServerCommandEvent;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.managers.OpManager;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Extra policy layer for Discord-Sync and optional console command deny-list. */
public final class CommandBlocker implements Listener {
    private final OPProtection plugin;
    private volatile boolean consoleBlockingEnabled;
    private volatile Set<String> consoleBlockedCommands = Set.of();

    public CommandBlocker(OPProtection plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        this.consoleBlockingEnabled = plugin.getConfig().getBoolean("console-blocked-cmd.enabled", false);
        Set<String> commands = new HashSet<>();
        for (String blocked : plugin.getConfig().getStringList("console-blocked-cmd.commands")) {
            if (blocked == null) continue;
            String normalized = blocked.toLowerCase(Locale.ROOT).replaceFirst("^/+", "").trim();
            if (!normalized.isEmpty()) commands.add(normalized);
        }
        this.consoleBlockedCommands = Set.copyOf(commands);
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        String command = OpManager.extractBaseCmd(event.getMessage());
        if (command.equals("oppass") || command.equals("verify") || command.equals("opverify")) return;

        if (plugin.getOpManager().isPrivileged(event.getPlayer())
                && plugin.getDiscordSyncModule().commandRequiresSync(command)
                && !plugin.getDiscordSyncModule().isPlayerVerified(event.getPlayer())) {
            event.setCancelled(true);
            plugin.getDiscordSyncModule().handleUnauthorizedCommand(event.getPlayer(), command);
        }
    }

    @EventHandler(priority = EventPriority.HIGH, ignoreCancelled = true)
    public void onServerCommand(ServerCommandEvent event) {
        if (!consoleBlockingEnabled) return;
        String command = OpManager.extractBaseCmd(event.getCommand());
        for (String normalized : consoleBlockedCommands) {
            if (command.equals(normalized) || command.endsWith(":" + normalized)) {
                event.setCancelled(true);
                event.getSender().sendMessage(plugin.getMessage("command_blocked"));
                return;
            }
        }
    }
}
