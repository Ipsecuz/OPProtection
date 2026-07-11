package org.ipsecuz.opprotection.listener;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Locale;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.command.CommandOPPass;

public final class SecureOPPassPacketListener extends PacketListenerAbstract {
    private final OPProtection plugin;
    private volatile boolean enabled;

    public SecureOPPassPacketListener(OPProtection plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        this.enabled = plugin.getConfig().getBoolean("secure-command-input.hide-oppass-from-console-log", true);
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        if (!this.enabled) {
            return;
        }

        String commandLine = readCommandLine(event);
        if (commandLine == null || !isOPPassCommand(commandLine)) {
            return;
        }

        Object rawPlayer = event.getPlayer();
        if (!(rawPlayer instanceof Player player)) {
            return;
        }

        event.setCancelled(true);
        dispatchSafely(player, commandLine);
    }

    private void dispatchSafely(Player player, String commandLine) {
        Runnable action = () -> {
            if (!player.isOnline()) {
                return;
            }
            CommandOPPass command = this.plugin.getCommandOPPass();
            if (command == null) {
                this.plugin.msg(player, "oppass_internal_error");
                return;
            }
            command.handlePlayerCommandLine(player, commandLine);
        };

        this.plugin.getSchedulerService().runEntity(player, action);
    }

    private String readCommandLine(PacketReceiveEvent event) {
        String packetName = String.valueOf(event.getPacketType()).toUpperCase(Locale.ROOT);
        try {
            if (packetName.contains("CHAT_COMMAND_UNSIGNED")) {
                return readStringFromWrapper("com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatCommandUnsigned", event, "getCommand");
            }
            if (packetName.contains("CHAT_COMMAND")) {
                return readStringFromWrapper("com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatCommand", event, "getCommand");
            }
            if (packetName.contains("CHAT_MESSAGE")) {
                String message = readStringFromWrapper("com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatMessage", event, "getMessage");
                if (message != null && message.startsWith("/")) {
                    return message.substring(1);
                }
            }
        } catch (Throwable ignored) {
            
        }
        return null;
    }

    private String readStringFromWrapper(String className, PacketReceiveEvent event, String methodName) throws Exception {
        Class<?> wrapperClass = Class.forName(className);
        Constructor<?> constructor = wrapperClass.getConstructor(PacketReceiveEvent.class);
        Object wrapper = constructor.newInstance(event);
        Method method = wrapperClass.getMethod(methodName);
        Object value = method.invoke(wrapper);
        return value instanceof String string ? string : null;
    }

    private boolean isOPPassCommand(String commandLine) {
        String trimmed = commandLine == null ? "" : commandLine.trim();
        if (trimmed.startsWith("/")) {
            trimmed = trimmed.substring(1);
        }
        if (trimmed.isEmpty()) {
            return false;
        }
        String first = trimmed.split("\\s+", 2)[0].toLowerCase(Locale.ROOT);
        int namespace = first.indexOf(':');
        if (namespace >= 0 && namespace + 1 < first.length()) {
            first = first.substring(namespace + 1);
        }
        return first.equals("oppass");
    }
}
