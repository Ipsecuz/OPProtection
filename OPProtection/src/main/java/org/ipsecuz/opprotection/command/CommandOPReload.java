package org.ipsecuz.opprotection.command;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.ipsecuz.opprotection.OPProtection;

public final class CommandOPReload implements CommandExecutor {
    private final OPProtection plugin;

    public CommandOPReload(OPProtection plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof ConsoleCommandSender)) {
            sender.sendMessage(plugin.getMessage("reload_ingame_error"));
            return true;
        }

        if (args.length == 1 && args[0].equalsIgnoreCase("hashcheck")) {
            plugin.getIntegrityMonitor().scanAsync(true);
            sender.sendMessage("§b[OPProtection] Đã bắt đầu kiểm tra toàn bộ plugin JAR.");
            return true;
        }

        if (args.length == 1 && args[0].equalsIgnoreCase("hashaccept")) {
            sender.sendMessage("§e[OPProtection] Đang tạo baseline SHA-256 mới...");
            sender.sendMessage("§6[OPProtection] Lưu ý: lệnh này chấp nhận toàn bộ plugin JAR hiện tại,");
            sender.sendMessage("§6[OPProtection] nhưng không tự chứng minh các plugin đó an toàn hoặc không có mã độc.");
            plugin.getIntegrityMonitor().acceptCurrentBaselineAsync(success -> sender.sendMessage(success
                    ? "§a[OPProtection] Đã chấp nhận baseline plugin JAR mới."
                    : "§c[OPProtection] Không thể cập nhật baseline hoặc đang có lượt kiểm tra khác."));
            return true;
        }

        plugin.reloadPlugin();
        sender.sendMessage(plugin.getMessage("reload_success"));
        return true;
    }
}
