package org.ipsecuz.opprotection.command;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;

public final class CommandVerify implements CommandExecutor {
    private final OPProtection plugin;
    public CommandVerify(OPProtection plugin) { this.plugin = plugin; }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("§cLệnh này chỉ dành cho người chơi.");
            return true;
        }
        if (!plugin.getOpManager().isPrivileged(player) || !plugin.getOpManager().isConfirmed(player)) {
            player.sendMessage(plugin.getMessage("no_permission"));
            return true;
        }
        if (!plugin.isDiscordEnabled() || !plugin.getDiscordSyncModule().isEnabled()) {
            plugin.msg(player, "discord_sync_unavailable");
            return true;
        }
        if (plugin.getDiscordSyncModule().isPlayerVerified(player)) {
            long remaining = plugin.getDiscordSyncModule().getRemainingVerificationTime(player);
            player.sendMessage("§a[OPProtection] Discord-Sync còn hiệu lực §e" + Math.max(1L, remaining / 60L) + " phút§a.");
            return true;
        }
        plugin.getDiscordSyncModule().sendVerificationRequest(player);
        return true;
    }
}
