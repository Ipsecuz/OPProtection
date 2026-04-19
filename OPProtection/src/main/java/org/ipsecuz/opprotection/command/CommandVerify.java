package org.ipsecuz.opprotection.command;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;

public class CommandVerify implements CommandExecutor {
    private final OPProtection plugin;

    public CommandVerify(OPProtection plugin) {
        this.plugin = plugin;
    }

    private String generateVerificationCode(Player player) {
        return String.format("%04d", (player.getUniqueId().hashCode() & 0xFFFF) % 10000);
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player)) {
            sender.sendMessage("§cChỉ người chơi mới có thể sử dụng lệnh này!");
            return true;
        }

        Player player = (Player) sender;

        if (!plugin.isDiscordEnabled()) {
            player.sendMessage("§cHệ thống Discord chưa được bật trên server!");
            return true;
        }

        if (!player.isOp()) {
            player.sendMessage("§cBạn phải là OP để yêu cầu xác minh!");
            return true;
        }

        if (plugin.getDiscordSyncModule().isPlayerVerified(player)) {
            long remaining = plugin.getDiscordSyncModule().getRemainingVerificationTime(player);
            player.sendMessage("§aXác minh Discord của bạn hiệu lực trong " + (remaining / 60) + " phút nữa!");
            return true;
        }

        try {
            plugin.getDiscordSyncModule().sendVerificationRequest(player);

            player.sendMessage("§a✓ Yêu cầu xác minh đã được gửi tới Discord!");
            player.sendMessage("§eVui lòng check tin nhắn trong kênh Discord để xác minh...");
            plugin.getLogger().info("§a[Verify] " + player.getName() + " requested Discord verification");

            return true;

        } catch (Exception e) {
            player.sendMessage("§cLỗi gửi yêu cầu xác minh: " + e.getMessage());
            plugin.getLogger().severe("Verification request error: " + e.getMessage());
            e.printStackTrace();
            return true;
        }
    }
}
