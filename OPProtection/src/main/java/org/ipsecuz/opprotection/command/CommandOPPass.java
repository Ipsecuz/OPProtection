package org.ipsecuz.opprotection.command;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.bukkit.plugin.Plugin;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.managers.IPManager;
import org.ipsecuz.opprotection.managers.OpManager;

public class CommandOPPass implements CommandExecutor {
    private final OPProtection plugin;
    private final OpManager opManager;
    private final IPManager ipManager;
    private final Map<UUID, String> pendingConfirmations = new HashMap<>();
    private final boolean isFolia;

    public CommandOPPass(OPProtection plugin, OpManager opManager, IPManager ipManager) {
        this.plugin = plugin;
        this.opManager = opManager;
        this.ipManager = ipManager;
        this.isFolia = opManager.isFolia();
    }

    public void removePendingConfirmation(UUID playerUUID) {
        this.pendingConfirmations.remove(playerUUID);
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (sender instanceof Player) {
            Player p = (Player) sender;
            if (!p.isOp()) {
                p.sendMessage(this.plugin.getMessage("no_permission"));
                return true;
            }

            if (args.length == 0) {
                p.sendMessage(this.plugin.getMessage("oppass_usage"));
                return true;
            }

            if (args[0].equalsIgnoreCase("change")) {
                if (args.length != 3) {
                    p.sendMessage(this.plugin.getMessage("oppass_change_usage"));
                    return true;
                }
                String oldPass = args[1];
                String newPass = args[2];
                if (this.opManager.checkPassword(p, oldPass)) {
                    this.opManager.setPassword(p, newPass);
                    p.sendMessage(this.plugin.getMessage("password_changed"));
                } else {
                    p.sendMessage(this.plugin.getMessage("password_wrong"));
                }
                return true;
            }

            if (this.opManager.isConfirmed(p)) {
                p.sendMessage(this.plugin.getMessage("already_confirmed"));
                return true;
            }

            if (this.opManager.isTwoFAReady(p)) {
                if (this.opManager.verify2FACodeInput(p, args[0])) {
                    p.sendMessage(ChatColor.GREEN + "Xác thực 2FA thành công! Đã mở khóa.");
                } else {
                    p.sendMessage(ChatColor.RED + "Sai mã 2FA hoặc mã hết hạn!");
                }
                return true;
            }

            this.opManager.handlePasswordLogin(p, args[0]);
            return true;
        }

        if (sender instanceof ConsoleCommandSender) {
            if (args.length == 0) {
                this.sendConsoleHelp(sender);
                return true;
            }

            if (args[0].equalsIgnoreCase("confirm")) {
                if (args.length != 2) {
                    sender.sendMessage(this.plugin.getMessage("oppass_console_confirm_usage"));
                    return true;
                }
                String playerName = args[1];
                Player target = Bukkit.getPlayerExact(playerName);

                if (target == null) {
                    sender.sendMessage("§cNgười chơi không online!");
                    return true;
                }

                if (this.opManager.isAwaitingConsole(target)) {
                    this.opManager.finalizeConsoleVerification(target);
                    sender.sendMessage("§aĐã xác minh và mở khóa cho " + playerName);
                    target.sendMessage(this.plugin.getMessage("oppass_confirm_success_player"));
                } else if (this.opManager.isConfirmed(target)) {
                    sender.sendMessage("§eNgười chơi đã xác minh rồi.");
                } else {
                    sender.sendMessage("§cLỗi: Người chơi chưa nhập đúng mật khẩu! Không thể xác nhận.");
                }
                return true;
            }

            if (args[0].equalsIgnoreCase("resetip")) {
                if (args.length != 2) {
                    sender.sendMessage(this.plugin.getMessage("oppass_console_resetip_usage"));
                    return true;
                }
                String playerName = args[1];

                OfflinePlayer offlinePlayer = Bukkit.getOfflinePlayer(playerName);
                UUID targetUUID = offlinePlayer.getUniqueId();

                if (this.opManager.resetPlayerIP(targetUUID)) {
                    sender.sendMessage(this.plugin.getMessage("oppass_resetip_success"));
                    this.plugin.getLogger().info("IP của " + playerName + " đã được reset về 'unknown'.");

                    Player onlineTarget = Bukkit.getPlayer(targetUUID);
                    if (onlineTarget != null && onlineTarget.isOnline()) {
                        String kickReason = "§cIP của bạn đã bị reset bởi Admin.\n§eVui lòng đăng nhập lại để xác minh danh tính!";

                        if (this.isFolia) {
                            onlineTarget.getScheduler().run(plugin, task -> onlineTarget.kickPlayer(kickReason), null);
                        } else {
                            onlineTarget.kickPlayer(kickReason);
                        }
                        sender.sendMessage("§aĐã kick người chơi " + playerName + " để áp dụng bảo mật.");
                    }
                } else {
                    sender.sendMessage(this.plugin.getMessage("oppass_resetip_not_found"));
                }
                return true;
            }

            this.sendConsoleHelp(sender);
        }
        return true;
    }

    private void sendConsoleHelp(CommandSender sender) {
        sender.sendMessage(this.plugin.getMessage("oppass_console_usage"));
        sender.sendMessage("§c/oppass confirm <player> - Xác nhận mở khóa (khi tắt 2FA)");
        sender.sendMessage("§c/oppass resetip <player> - Reset IP");
    }

    private void sendMessage(CommandSender sender, String message) {
        if (sender instanceof Player) {
            Player p = (Player) sender;
            if (this.isFolia) {
                p.getScheduler().run((Plugin) this.plugin, task -> p.sendMessage(message), null);
                return;
            }
        }
        sender.sendMessage(message);
    }
}