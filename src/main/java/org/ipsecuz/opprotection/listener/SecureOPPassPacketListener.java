package org.ipsecuz.opprotection.listener;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.protocol.packettype.PacketTypeCommon;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatCommand;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatCommandUnsigned;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientChatMessage;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;
import org.ipsecuz.opprotection.command.CommandOPPass;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Packet-level guard that intercepts raw {@code /oppass} input before any command logger,
 * console appender or third-party plugin can capture the password.
 *
 * <p>Parsed with PacketEvents' own typed wrappers instead of reflection so a mapping or
 * version failure can never silently degrade into letting {@code /oppass <password>} fall
 * through to the normal dispatcher. Failures are reported without ever echoing command
 * content, and are rate-limited to avoid log flooding.</p>
 */
public final class SecureOPPassPacketListener extends PacketListenerAbstract {
    private static final long WARN_INTERVAL_MILLIS = 300_000L;

    private final OPProtection plugin;
    private final AtomicLong lastWarningMillis = new AtomicLong();
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
        PacketTypeCommon type = event.getPacketType();
        try {
            if (type == PacketType.Play.Client.CHAT_COMMAND_UNSIGNED) {
                return new WrapperPlayClientChatCommandUnsigned(event).getCommand();
            }
            if (type == PacketType.Play.Client.CHAT_COMMAND) {
                return new WrapperPlayClientChatCommand(event).getCommand();
            }
            if (type == PacketType.Play.Client.CHAT_MESSAGE) {
                String message = new WrapperPlayClientChatMessage(event).getMessage();
                if (message != null && message.startsWith("/")) {
                    return message.substring(1);
                }
            }
        } catch (Exception ex) {
            // Never log the command line: it may contain the OP password.
            // Throttle so a broken protocol mapping cannot flood the console.
            long now = System.currentTimeMillis();
            long last = lastWarningMillis.get();
            if (now - last >= WARN_INTERVAL_MILLIS && lastWarningMillis.compareAndSet(last, now)) {
                plugin.getLogger().warning("[SecureOPPass] Khong the doc packet command "
                        + type + ": " + ex.getClass().getSimpleName()
                        + ". Command /oppass co the hien trong log cua plugin khac.");
            }
        }
        return null;
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
