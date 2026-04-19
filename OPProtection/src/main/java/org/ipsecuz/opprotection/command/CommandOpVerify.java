package org.ipsecuz.opprotection.command;

import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;


public class CommandOpVerify implements CommandExecutor {
    private final OPProtection plugin;

    public CommandOpVerify(OPProtection plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof Player) && !(sender instanceof org.bukkit.command.ConsoleCommandSender)) {
            sender.sendMessage("§cChỉ OP hoặc Console mới có thể sử dụng lệnh này!");
            return true;
        }

        if (!(sender instanceof Player)) {
            if (args.length < 2) {
                sender.sendMessage("§cUsage: /opverify <player-name> <code>");
                return true;
            }
            
            String playerName = args[0];
            String code = args[1];
            Player targetPlayer = Bukkit.getPlayer(playerName);
            
            if (targetPlayer == null) {
                sender.sendMessage("§cPlayer " + playerName + " not found!");
                return true;
            }
            
            if (!plugin.isDiscordEnabled()) {
                sender.sendMessage("§cDiscord system is not enabled!");
                return true;
            }
            
            verifyPlayerWithCode(targetPlayer, code, sender);
            return true;
        }

        Player player = (Player) sender;
        
        if (!player.isOp()) {
            player.sendMessage("§cBạn không có quyền OP để sử dụng lệnh này!");
            return true;
        }

        if (args.length < 1) {
            player.sendMessage("§cUsage: /opverify <verification-code>");
            player.sendMessage("§eExample: /opverify 1234");
            return true;
        }

        String code = args[0];
        
        if (!plugin.isDiscordEnabled()) {
            player.sendMessage("§cHệ thống Discord chưa được bật!");
            return true;
        }

        if (!plugin.getDiscordSyncModule().isEnabled()) {
            player.sendMessage("§cMôđun Discord-Sync chưa được bật!");
            return true;
        }

        verifyPlayerWithCode(player, code, player);
        return true;
    }

    private void verifyPlayerWithCode(Player player, String code, CommandSender issuer) {
        try {
            String expectedCode = String.format("%04d", (player.getUniqueId().hashCode() & 0xFFFF) % 10000);
            
            if (!code.equals(expectedCode)) {
                issuer.sendMessage("§c✗ Mã xác minh không chính xác!");
                issuer.sendMessage("§eExpected: " + expectedCode + ", Got: " + code);
                return;
            }

            plugin.getDiscordSyncModule().verifyPlayer(player);

            issuer.sendMessage("§a✓ Xác minh thành công cho player: " + player.getName());
            
            player.sendMessage("§a✓ Bạn đã được xác minh bởi " + (issuer instanceof Player ? ((Player)issuer).getName() : "Console"));
            player.sendMessage("§eBạn có thể sử dụng các lệnh bảo mật trong " + 
                    (plugin.getDiscordSyncModule().getVerificationTimeoutSeconds() / 60) + " phút");

            if (plugin.isDiscordEnabled()) {
                try {
                    plugin.getDiscord().sendSimpleMessage(
                        "✅ **XÁC MINH THÀNH CÔNG**\n" +
                        "Player: `" + player.getName() + "`\n" +
                        "Verified by: `" + (issuer instanceof Player ? ((Player)issuer).getName() : "Console") + "`\n" +
                        "Code: `" + code + "`"
                    );
                } catch (Exception e) {
                    plugin.getLogger().warning("Could not send Discord confirmation: " + e.getMessage());
                }
            }

            plugin.getLogger().info("§a[OpVerify] Player " + player.getName() + " verified by " + 
                    (issuer instanceof Player ? ((Player)issuer).getName() : "Console"));

        } catch (Exception e) {
            issuer.sendMessage("§cLỗi xác minh: " + e.getMessage());
            plugin.getLogger().severe("Verification error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
