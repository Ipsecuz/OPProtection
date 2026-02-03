package org.ipsecuz.opprotection.listener;

import java.util.List;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.server.ServerCommandEvent;
import org.bukkit.plugin.Plugin;
import org.ipsecuz.opprotection.OPProtection;

public class CommandBlocker implements Listener {
    private final OPProtection plugin;
    private final boolean isFolia;

    public CommandBlocker(OPProtection plugin) {
        this.plugin = plugin;
        this.isFolia = this.initializeFolia();
    }

    private boolean initializeFolia() {
        try {
            Class.forName("io.papermc.paper.threadedregions.RegionedServer");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPlayerCommand(PlayerCommandPreprocessEvent event) {
        String msg = event.getMessage();

        String checkCmd = msg.toLowerCase();
        if (checkCmd.startsWith("/")) {
            checkCmd = checkCmd.substring(1);
        }
        if (checkCmd.startsWith("oppass")) {
            return;
        }

        if (this.isCommandBlocked(msg, "disabled-commands")) {
            event.setCancelled(true);

            if (this.isFolia) {
                event.getPlayer().getScheduler().run((Plugin) this.plugin, task ->
                        event.getPlayer().sendMessage(this.plugin.getMessage("command_blocked")), null);
            } else {
                event.getPlayer().sendMessage(this.plugin.getMessage("command_blocked"));
            }
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onServerCommand(ServerCommandEvent event) {
        if (!this.plugin.getConfig().getBoolean("console-blocked-cmd.enabled", false)) {
            return;
        }

        String command = event.getCommand();

        if (this.isCommandBlocked(command, "console-blocked-cmd.commands")) {
            event.setCancelled(true);
            event.getSender().sendMessage(this.plugin.getMessage("command_blocked"));
        }
    }


    private boolean isCommandBlocked(String command, String configPath) {
        if (command == null || command.isEmpty()) {
            return false;
        }

        String lowerCommand = command.toLowerCase();
        if (lowerCommand.startsWith("/") && lowerCommand.length() > 1) {
            lowerCommand = lowerCommand.substring(1);
        } else if (lowerCommand.equals("/")) {
            return false;
        }

        int colonIndex = lowerCommand.indexOf(58);
        if (colonIndex > 0) {
            if (colonIndex + 1 < lowerCommand.length()) {
                lowerCommand = lowerCommand.substring(colonIndex + 1);
            } else {
                return false;
            }
        }

        List<String> blockedCommands = this.plugin.getConfig().getStringList(configPath);

        for (String blocked : blockedCommands) {
            String blockedLower = blocked.toLowerCase();
            if (lowerCommand.startsWith(blockedLower)) {
                return true;
            }
        }
        return false;
    }
}