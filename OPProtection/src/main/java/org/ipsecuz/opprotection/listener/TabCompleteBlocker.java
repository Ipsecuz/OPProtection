package org.ipsecuz.opprotection.listener;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.ProtocolManager;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.wrappers.WrappedChatComponent;
import org.bukkit.Bukkit;
import org.bukkit.command.CommandMap;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandSendEvent;
import org.bukkit.plugin.Plugin;
import org.ipsecuz.opprotection.OPProtection;

import java.lang.reflect.Field;
import java.util.*;
import java.util.stream.Collectors;

public class TabCompleteBlocker implements Listener {
    private final OPProtection plugin;
    private final ProtocolManager protocolManager;
    private final Set<String> DEFAULT_TARGET_COMMANDS = Set.of(
            "version", "ver", "about","bukkit",
            "bukkit:version", "bukkit:ver", "bukkit:about"
    );
    private Set<String> targetCommands;
    private List<String> blockedCommands;

    public TabCompleteBlocker(OPProtection plugin) {
        this.plugin = plugin;
        this.protocolManager = ProtocolLibrary.getProtocolManager();

        loadConfig();
        registerPacketListeners();
        registerBukkitListener();
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

    private void registerPacketListeners() {
        protocolManager.addPacketListener(new PacketAdapter(plugin, PacketType.Play.Server.TAB_COMPLETE) {
            @Override
            public void onPacketSending(PacketEvent event) {
                if (!isEnabled()) return;

                try {
                    PacketContainer packet = event.getPacket();

                    if (packet.getStringArrays().size() > 0) {
                        CharSequence[] suggestions = packet.getStringArrays().read(0);

                        if (suggestions != null && suggestions.length > 0) {
                            List<String> filtered = Arrays.stream(suggestions)
                                    .filter(s -> !isBlockedCommand(s.toString()))
                                    .map(CharSequence::toString)
                                    .collect(Collectors.toList());

                            packet.getStringArrays().write(0, filtered.toArray(new String[0]));

                            if (isDebugMode()) {
                                logDebug("Server Tab Complete - Original: " +
                                        String.join(", ", Arrays.asList(suggestions)) +
                                        "\nFiltered: " + String.join(", ", filtered));
                            }
                        }
                    }
                } catch (Exception e) {
                    plugin.getLogger().warning("Error processing server tab complete: " + e.getMessage());
                }
            }
        });

        protocolManager.addPacketListener(new PacketAdapter(plugin, PacketType.Play.Client.TAB_COMPLETE) {
            @Override
            public void onPacketReceiving(PacketEvent event) {
                if (!isEnabled()) return;

                try {
                    PacketContainer packet = event.getPacket();
                    String text = packet.getStrings().read(0);

                    if (text != null && isBlockedCommand(text)) {
                        event.setCancelled(true);
                        if (isDebugMode()) {
                            logDebug("Blocked client tab complete: " + text);
                        }
                    }
                } catch (Exception e) {
                    plugin.getLogger().warning("Error processing client tab complete: " + e.getMessage());
                }
            }
        });
    }

    private void registerBukkitListener() {
        plugin.getServer().getPluginManager().registerEvents(this, plugin);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onCommandSend(PlayerCommandSendEvent event) {
        if (!isEnabled()) return;

        List<String> originalCommands = new ArrayList<>(event.getCommands());
        List<String> filteredCommands = new ArrayList<>();

        for (String command : originalCommands) {
            if (!shouldRemoveCommand(command)) {
                filteredCommands.add(command);
            }
        }

        event.getCommands().clear();
        event.getCommands().addAll(filteredCommands);
    }

    private boolean isEnabled() {
        return plugin.getConfig().getBoolean("tab-complete-block.enabled", true);
    }

    private boolean isDebugMode() {
        return plugin.getConfig().getBoolean("tab-complete-block.debug", false);
    }

    private void logDebug(String message) {
        plugin.getLogger().info(message);
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
                lowerCommand = parts[1]; // Take only the command part after colon
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