package org.ipsecuz.opprotection.command;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.managers.DiscordSyncModule;

import java.util.Map;

public final class CommandOpVerify implements CommandExecutor {
    private final OPProtection plugin;

    public CommandOpVerify(OPProtection plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!plugin.getDiscordSyncModule().isEnabled()) {
            send(sender, "§c[OPProtection] Discord-Sync chưa được bật.");
            return true;
        }
        if (args.length != 2) {
            send(sender, "§eCách dùng: §f/opverify <player> <mã-một-lần>");
            return true;
        }
        if (sender instanceof Player player) {
            if (!plugin.getOpManager().isPrivileged(player) || !plugin.getOpManager().isConfirmed(player)) {
                send(sender, plugin.getMessage("no_permission"));
                return true;
            }
            if (player.getName().equalsIgnoreCase(args[0])) {
                send(sender, "§c[OPProtection] Không thể tự phê duyệt yêu cầu Discord-Sync của chính mình.");
                return true;
            }
        } else if (!(sender instanceof ConsoleCommandSender)) {
            send(sender, plugin.getMessage("no_permission"));
            return true;
        }

        String targetName = args[0];
        String code = args[1];
        String issuer = sender instanceof Player player ? player.getName() : "CONSOLE";
        plugin.getDiscordSyncModule().verifyCodeAsync(targetName, code, issuer, result -> {
            if (!result.success()) {
                send(sender, "§c[OPProtection] Xác minh thất bại: " + result.message());
                return;
            }
            String verifiedName = result.playerName() == null ? targetName : result.playerName();
            send(sender, "§a[OPProtection] Đã xác minh Discord-Sync cho §f" + verifiedName + "§a.");
            if (plugin.isDiscordEnabled()) {
                plugin.getDiscord().sendEmbed("discord-sync-verified", Map.of(
                        "player", verifiedName,
                        "discordUser", issuer,
                        "timeout", String.valueOf(plugin.getDiscordSyncModule().getVerificationTimeoutSeconds() / 60L)), false);
            }
        });
        return true;
    }

    private void send(CommandSender sender, String message) {
        if (sender instanceof Player player) {
            plugin.getSchedulerService().runEntity(player, () -> player.sendMessage(message));
        } else {
            plugin.getSchedulerService().runGlobal(() -> sender.sendMessage(message));
        }
    }
}
