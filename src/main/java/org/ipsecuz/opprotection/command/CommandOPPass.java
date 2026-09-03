package org.ipsecuz.opprotection.command;

import java.util.Arrays;
import java.util.Locale;
import java.util.UUID;
import org.bukkit.Bukkit;
import org.bukkit.OfflinePlayer;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.managers.IPManager;
import org.ipsecuz.opprotection.managers.OpManager;

public class CommandOPPass implements CommandExecutor {
    private final OPProtection plugin;
    private final OpManager opManager;
    @SuppressWarnings("unused")
    private final IPManager ipManager;

    public CommandOPPass(OPProtection plugin, OpManager opManager, IPManager ipManager) {
        this.plugin = plugin;
        this.opManager = opManager;
        this.ipManager = ipManager;
    }

    public void removePendingConfirmation(UUID playerUUID) {
        this.opManager.clearAwaitingConsole(playerUUID);
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (sender instanceof Player player) {
            return handlePlayerCommandLine(player, buildCommandLine(label, args));
        }

        if (sender instanceof ConsoleCommandSender) {
            return handleConsoleCommand(sender, args);
        }

        sender.sendMessage(this.plugin.getMessage("oppass_console_only"));
        return true;
    }

    public boolean handlePlayerCommandLine(Player player, String commandLine) {
        String rawArguments = extractRawArguments(commandLine);
        String[] args = rawArguments.isEmpty() ? new String[0] : rawArguments.split("\\s+");
        return handlePlayerCommand(player, args, rawArguments);
    }

    public boolean handlePlayerCommand(Player player, String[] args, String rawArguments) {
        if (!canUsePlayerOPPass(player)) {
            player.sendMessage(this.plugin.getMessage("no_permission"));
            return true;
        }

        if (args.length == 0) {
            player.sendMessage(this.plugin.getMessage("oppass_usage"));
            return true;
        }

        String subCommand = args[0].toLowerCase(Locale.ROOT);
        if (subCommand.equals("createpass") || subCommand.equals("resetpass") || subCommand.equals("confirm") || subCommand.equals("resetip")) {
            player.sendMessage(this.plugin.getMessage("oppass_console_only"));
            return true;
        }

        if (subCommand.equals("change")) {
            handlePlayerPasswordChange(player, args);
            return true;
        }

        if (subCommand.equals("premium-register") || subCommand.equals("premium-unregister")) {
            player.sendMessage(this.plugin.getMessage("oppass_console_only"));
            return true;
        }

        if (subCommand.equals("premium-list")) {
            player.sendMessage(this.plugin.getMessage("oppass_console_only"));
            return true;
        }

        if (this.opManager.isConfirmed(player)) {
            player.sendMessage(this.plugin.getMessage("already_confirmed"));
            return true;
        }

        String input = sanitizeSensitiveInput(rawArguments == null || rawArguments.isBlank() ? args[0] : rawArguments);
        if (input.isBlank()) {
            player.sendMessage(this.plugin.getMessage("oppass_usage"));
            return true;
        }

        if (this.opManager.isTwoFAReady(player) || this.opManager.matchesPending2FACode(player, input)) {
            this.opManager.verify2FACodeInput(player, input);
            return true;
        }

        this.opManager.handlePasswordLogin(player, input);
        return true;
    }

    private boolean handleConsoleCommand(CommandSender sender, String[] args) {
        if (args.length == 0) {
            this.sendConsoleHelp(sender);
            return true;
        }

        String subCommand = args[0].toLowerCase(Locale.ROOT);
        switch (subCommand) {
            case "createpass" -> {
                handleConsoleCreatePass(sender, args);
                return true;
            }
            case "resetpass" -> {
                handleConsoleResetPass(sender, args);
                return true;
            }
            case "confirm" -> {
                handleConsoleConfirm(sender, args);
                return true;
            }
            case "resetip" -> {
                handleConsoleResetIP(sender, args);
                return true;
            }
            case "premium-register" -> {
                handleConsolePremiumRegister(sender, args);
                return true;
            }
            case "premium-unregister" -> {
                handleConsolePremiumUnregister(sender, args);
                return true;
            }
            case "premium-list" -> {
                handleConsolePremiumList(sender);
                return true;
            }
            default -> {
                this.sendConsoleHelp(sender);
                return true;
            }
        }
    }

    private void handlePlayerPasswordChange(Player player, String[] args) {
        if (args.length < 3) {
            player.sendMessage(this.plugin.getMessage("oppass_change_usage"));
            return;
        }

        String oldPass = args[1];
        String newPass = joinArgs(args, 2);
        try {
            this.opManager.changePasswordAsync(player, oldPass, newPass);
        } catch (IllegalArgumentException ex) {
            player.sendMessage(this.plugin.getMessage("oppass_password_policy").replace("%min%", String.valueOf(this.opManager.getPasswordMinLength())));
        }
    }

    private void handleConsoleCreatePass(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(this.plugin.getMessage("oppass_createpass_usage"));
            return;
        }

        try {
            this.opManager.setGlobalPassword(joinArgs(args, 1));
            sender.sendMessage(this.plugin.getMessage("oppass_createpass_success"));
            this.plugin.getLogger().info("[OPPass] Global OP password hash was created by console.");
        } catch (IllegalArgumentException ex) {
            sender.sendMessage(this.plugin.getMessage("oppass_password_policy").replace("%min%", String.valueOf(this.opManager.getPasswordMinLength())));
        }
    }

    private void handleConsoleResetPass(CommandSender sender, String[] args) {
        try {
            if (args.length >= 2) {
                this.opManager.setGlobalPassword(joinArgs(args, 1));
                sender.sendMessage(this.plugin.getMessage("oppass_resetpass_success"));
                this.plugin.getLogger().info("[OPPass] Global OP password hash was reset by console with a provided value.");
                return;
            }

            String generated = this.opManager.resetGlobalPassword();
            sender.sendMessage(this.plugin.getMessage("oppass_resetpass_success"));
            sender.sendMessage(this.plugin.getMessage("oppass_resetpass_generated").replace("%password%", generated));
            this.plugin.getLogger().info("[OPPass] Global OP password hash was reset by console. The one-time password was printed above.");
        } catch (IllegalArgumentException ex) {
            sender.sendMessage(this.plugin.getMessage("oppass_password_policy").replace("%min%", String.valueOf(this.opManager.getPasswordMinLength())));
        }
    }

    private void handleConsoleConfirm(CommandSender sender, String[] args) {
        if (args.length != 2) {
            sender.sendMessage(this.plugin.getMessage("oppass_console_confirm_usage"));
            return;
        }
        String playerName = args[1];
        Player target = Bukkit.getPlayerExact(playerName);

        if (target == null) {
            sender.sendMessage(this.plugin.getMessage("oppass_confirm_player_offline"));
            return;
        }

        this.plugin.getSchedulerService().runEntity(target, () -> {
            if (!target.isOnline()) {
                this.plugin.getSchedulerService().runGlobal(() -> sender.sendMessage(
                        this.plugin.getMessage("oppass_confirm_player_offline")));
                return;
            }
            String response;
            if (this.opManager.isAwaitingConsole(target)) {
                this.opManager.finalizeConsoleVerification(target);
                response = this.plugin.getMessage("oppass_confirm_success").replace("%player%", target.getName());
                target.sendMessage(this.plugin.getMessage("oppass_confirm_success_player"));
            } else if (this.opManager.isConfirmed(target)) {
                response = this.plugin.getMessage("oppass_confirm_not_needed");
            } else {
                response = this.plugin.getMessage("oppass_confirm_no_password");
            }
            this.plugin.getSchedulerService().runGlobal(() -> sender.sendMessage(response));
        });
    }

    private void handleConsoleResetIP(CommandSender sender, String[] args) {
        if (args.length != 2) {
            sender.sendMessage(this.plugin.getMessage("oppass_console_resetip_usage"));
            return;
        }
        String playerName = args[1];

        OfflinePlayer offlinePlayer = Bukkit.getOfflinePlayer(playerName);
        UUID targetUUID = offlinePlayer.getUniqueId();

        if (this.opManager.resetPlayerIP(targetUUID)) {
            sender.sendMessage(this.plugin.getMessage("oppass_resetip_success").replace("%player%", playerName));
            this.plugin.getLogger().info("[OPPass] Saved IP fingerprint for " + playerName + " was reset.");

            Player onlineTarget = Bukkit.getPlayer(targetUUID);
            if (onlineTarget != null && onlineTarget.isOnline()) {
                String kickReason = this.plugin.getMessage("oppass_resetip_kick");
                this.plugin.getSchedulerService().runEntity(onlineTarget, () -> onlineTarget.kickPlayer(kickReason));
                sender.sendMessage(this.plugin.getMessage("oppass_resetip_kicked").replace("%player%", playerName));
            }
        } else {
            sender.sendMessage(this.plugin.getMessage("oppass_resetip_not_found").replace("%player%", playerName));
        }
    }

    private boolean canUsePlayerOPPass(Player player) {
        return this.opManager.isWhitelisted(player.getName())
                || player.hasPermission("opprotection.oppass")
                || this.opManager.isLocked(player)
                || this.opManager.isTwoFAReady(player);
    }

    private String sanitizeSensitiveInput(String input) {
        return input == null ? "" : input.trim();
    }

    private String buildCommandLine(String label, String[] args) {
        String safeLabel = (label == null || label.isBlank()) ? "oppass" : label;
        if (args == null || args.length == 0) {
            return safeLabel;
        }
        return safeLabel + " " + String.join(" ", args);
    }

    private String extractRawArguments(String commandLine) {
        String trimmed = commandLine == null ? "" : commandLine.trim();
        if (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        int firstSpace = trimmed.indexOf(' ');
        if (firstSpace < 0 || firstSpace + 1 >= trimmed.length()) {
            return "";
        }
        return trimmed.substring(firstSpace + 1).trim();
    }

    private String joinArgs(String[] args, int startIndex) {
        if (args == null || args.length <= startIndex) {
            return "";
        }
        return String.join(" ", Arrays.copyOfRange(args, startIndex, args.length)).trim();
    }

    private void handleConsolePremiumRegister(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(this.plugin.getMessage("premium_registry_usage"));
            return;
        }
        String playerName = args[1];
        if (this.plugin.getPremiumRegistry() == null) {
            sender.sendMessage("§c[OPProtection] PremiumRegistry chưa được khởi tạo.");
            return;
        }
        this.plugin.getPremiumRegistry().register(playerName, sender.getName(), "ADMIN");
        sender.sendMessage(this.plugin.getMessage("premium_registry_registered")
                .replace("%player%", playerName));
        this.plugin.getLogger().info("[PremiumRegistry] " + sender.getName() + " đã đăng ký " + playerName + " là premium.");
    }

    private void handleConsolePremiumUnregister(CommandSender sender, String[] args) {
        if (args.length < 2) {
            sender.sendMessage(this.plugin.getMessage("premium_registry_usage"));
            return;
        }
        String playerName = args[1];
        if (this.plugin.getPremiumRegistry() == null) {
            sender.sendMessage("§c[OPProtection] PremiumRegistry chưa được khởi tạo.");
            return;
        }
        boolean removed = this.plugin.getPremiumRegistry().unregister(playerName);
        if (removed) {
            sender.sendMessage(this.plugin.getMessage("premium_registry_unregistered")
                    .replace("%player%", playerName));
        } else {
            sender.sendMessage(this.plugin.getMessage("premium_registry_not_found")
                    .replace("%player%", playerName));
        }
    }

    private void handleConsolePremiumList(CommandSender sender) {
        if (this.plugin.getPremiumRegistry() == null) {
            sender.sendMessage("§c[OPProtection] PremiumRegistry chưa được khởi tạo.");
            return;
        }
        java.util.Set<String> names = this.plugin.getPremiumRegistry().getRegisteredNames();
        if (names.isEmpty()) {
            sender.sendMessage(this.plugin.getMessage("premium_registry_list_empty"));
            return;
        }
        sender.sendMessage(this.plugin.getMessage("premium_registry_list_header"));
        for (String name : names) {
            sender.sendMessage("§7- §f" + name);
        }
    }

    private void sendConsoleHelp(CommandSender sender) {
        sender.sendMessage(this.plugin.getMessage("oppass_console_usage"));
        sender.sendMessage(this.plugin.getMessage("oppass_createpass_usage"));
        sender.sendMessage(this.plugin.getMessage("oppass_resetpass_usage"));
        sender.sendMessage(this.plugin.getMessage("oppass_console_confirm_usage"));
        sender.sendMessage(this.plugin.getMessage("oppass_console_resetip_usage"));
        sender.sendMessage(this.plugin.getMessage("premium_registry_usage"));
    }
}
