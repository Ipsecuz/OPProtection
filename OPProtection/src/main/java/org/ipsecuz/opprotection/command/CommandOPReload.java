package org.ipsecuz.opprotection.command;

import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.ConsoleCommandSender;
import org.ipsecuz.opprotection.OPProtection;

public class CommandOPReload
        implements CommandExecutor {
    private final OPProtection plugin;

    public CommandOPReload(OPProtection plugin) {
        this.plugin = plugin;
    }

    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
        if (!(sender instanceof ConsoleCommandSender)) {
            sender.sendMessage(this.plugin.getMessage("reload_ingame_error"));
            return true;
        }
        this.plugin.reloadConfig();
        this.plugin.reloadValues();
        sender.sendMessage(this.plugin.getMessage("reload_success"));
        return true;
    }
}
