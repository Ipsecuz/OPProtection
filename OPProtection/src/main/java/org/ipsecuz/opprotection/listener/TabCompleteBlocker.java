package org.ipsecuz.opprotection.listener;

import com.github.retrooper.packetevents.event.PacketListener;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientTabComplete;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandSendEvent;
import org.ipsecuz.opprotection.OPProtection;

import java.util.*;
import java.util.stream.Collectors;

public class TabCompleteBlocker implements Listener, PacketListener {
    private final OPProtection plugin;
    private final Set<String> DEFAULT_TARGET_COMMANDS = Set.of(
            "version", "ver", "about","bukkit",
            "bukkit:version", "bukkit:ver", "bukkit:about"
    );
    private Set<String> targetCommands;
    private List<String> blockedCommands;

    public TabCompleteBlocker(OPProtection plugin) {
        this.plugin = plugin;
        loadConfig();
        registerBukkitListener();
        registerPacketListener();
    }

    private void loadConfig() {
        FileConfiguration config = plugin.getConfig();

        List<String> configTargets = config.getStringList("tab-complete-block.target-commands");
        this.targetCommands = configTargets.isEmpty() ?
                DEFAULT_TARGET_COMMANDS :
                new HashSet<>(configTargets.stream()
                        .map(String::toLowerCase)
                        .collect(Collectors.toSet())
                );

        this.blockedCommands = config.getStringList("tab-complete-block.blocked-commands");
    }

    private void registerPacketListener() {
        try {

            plugin.getLogger().info("Tab complete blocker ready (Bukkit event mode)");
        } catch (Exception e) {
            plugin.getLogger().warning("Could not register packet listener: " + e.getMessage());
        }
    }

    private void registerBukkitListener() {
        plugin.getServer().getPluginManager().registerEvents(this, plugin);
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        if (!isEnabled()) return;

        try {
            if (event.getPacketType() == PacketType.Play.Client.TAB_COMPLETE) {
                try {
                    WrapperPlayClientTabComplete wrapper = new WrapperPlayClientTabComplete(event);
                    String text = wrapper.getText();

                    if (text != null && isBlockedCommand(text)) {
                        event.setCancelled(true);
                        if (isDebugMode()) {
                            logDebug("Blocked client tab complete: " + text);
                        }
                    }
                } catch (Exception ignored) {
                    
                }
            }
        } catch (Exception e) {
            plugin.getLogger().warning("Error processing client tab complete packet: " + e.getMessage());
        }
    }


    @EventHandler(priority = EventPriority.HIGHEST)
    public void onCommandSend(PlayerCommandSendEvent event) {
        if (!isEnabled()) return;

        List<String> originalCommands = new ArrayList<>(event.getCommands());
        List<String> filteredCommands = new ArrayList<>();

        for (String command : originalCommands) {
            if (isBlockedCommand(command)) {
                if (isDebugMode()) {
                    logDebug("Blocked command in tab complete: " + command);
                }
                continue;
            }
            

            if (command.contains(":")) {
                if (isDebugMode()) {
                    logDebug("Blocked namespaced command: " + command);
                }
                continue;
            }
            
            filteredCommands.add(command);
        }

        event.getCommands().clear();
        event.getCommands().addAll(filteredCommands);
        
        if (isDebugMode()) {
            logDebug("Filtered from " + originalCommands.size() + " to " + filteredCommands.size() + " commands");
        }
    }

    private boolean isEnabled() {
        return plugin.getConfig().getBoolean("tab-complete-block.enabled", true);
    }

    private boolean isDebugMode() {
        return plugin.getConfig().getBoolean("tab-complete-block.debug", false);
    }

    private void logDebug(String message) {
        plugin.getLogger().info("[TabCompleteBlocker] " + message);
    }

    private boolean shouldRemoveCommand(String command) {
        String lowerCommand = command.toLowerCase();

        if (lowerCommand.contains(":") && !targetCommands.contains(lowerCommand)) {
            return true;
        }

        return false;
    }

    private boolean isBlockedCommand(String command) {
        if (command == null || command.isEmpty()) {
            return false;
        }

        String lowerCommand = command.toLowerCase();

        if (lowerCommand.startsWith("/")) {
            lowerCommand = lowerCommand.substring(1);
        }

        if (lowerCommand.contains(":")) {
            String[] parts = lowerCommand.split(":", 2);
            if (parts.length > 1) {
                lowerCommand = parts[1];
            }
        }

        for (String blocked : blockedCommands) {
            String blockedLower = blocked.toLowerCase();

            if (matchesCommandPrefix(lowerCommand, blockedLower)) {
                return true;
            }
        }

        return false;
    }

    private static boolean matchesCommandPrefix(String buffer, String cmd) {
        if (buffer.equals(cmd)) {
            return true;
        }

        if (buffer.length() > cmd.length() && buffer.startsWith(cmd)) {
            char next = buffer.charAt(cmd.length());
            return next == ' ' || next == ':' || next == '/';
        }

        return false;
    }
}