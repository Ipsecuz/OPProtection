package org.ipsecuz.opprotection.listener;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketReceiveEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.play.client.WrapperPlayClientTabComplete;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.player.PlayerCommandSendEvent;
import org.ipsecuz.opprotection.OPProtection;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** Hides sensitive commands from both Bukkit and packet-level command suggestions. */
public final class TabCompleteBlocker extends PacketListenerAbstract implements Listener {
    private static final Set<String> DEFAULT_TARGET_COMMANDS = Set.of(
            "version", "ver", "about", "bukkit",
            "bukkit:version", "bukkit:ver", "bukkit:about");

    private final OPProtection plugin;
    private volatile Set<String> blockedCommands = Set.of();
    private volatile boolean enabled;
    private volatile boolean debug;

    public TabCompleteBlocker(OPProtection plugin) {
        this.plugin = plugin;
        reload();
    }

    public void reload() {
        this.enabled = plugin.getConfig().getBoolean("tab-complete-block.enabled", true);
        this.debug = plugin.getConfig().getBoolean("tab-complete-block.debug", false);
        Set<String> values = new HashSet<>();
        var targets = plugin.getConfig().getStringList("tab-complete-block.target-commands");
        if (targets.isEmpty()) values.addAll(DEFAULT_TARGET_COMMANDS);
        else targets.forEach(value -> addNormalized(values, value));
        plugin.getConfig().getStringList("tab-complete-block.blocked-commands")
                .forEach(value -> addNormalized(values, value));
        blockedCommands = Set.copyOf(values);
    }

    @Override
    public void onPacketReceive(PacketReceiveEvent event) {
        if (!enabled() || event.getPacketType() != PacketType.Play.Client.TAB_COMPLETE) return;
        try {
            String text = new WrapperPlayClientTabComplete(event).getText();
            if (isBlockedInput(text)) {
                event.setCancelled(true);
                debug("Đã chặn packet tab-complete: " + sanitize(text));
            }
        } catch (RuntimeException ex) {
            if (debugEnabled()) plugin.getLogger().warning("[TabComplete] Không thể đọc packet: " + ex.getMessage());
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onCommandSend(PlayerCommandSendEvent event) {
        if (!enabled()) return;
        int before = event.getCommands().size();
        // Only hide commands that actually match the blocked list (including their
        // namespaced variants). Removing every command that contains ':' would hide
        // ALL namespaced commands and break tab-complete for the whole server.
        event.getCommands().removeIf(this::shouldHideSuggestion);
        debug("Đã lọc " + (before - event.getCommands().size()) + " command suggestion cho "
                + event.getPlayer().getName());
    }

    private boolean shouldHideSuggestion(String command) {
        if (command == null || command.isBlank()) return false;
        if (blockedCommands.contains(command)) return true;
        int colon = command.indexOf(':');
        if (colon < 0) return false;
        String namespace = command.substring(0, colon + 1);
        String plain = command.substring(colon + 1);
        return blockedCommands.contains(plain)
                || blockedCommands.contains(command)
                || blockedCommands.contains(namespace + "*");
    }

    private boolean isBlockedInput(String input) {
        if (input == null || input.isBlank()) return false;
        String value = input.trim().toLowerCase(Locale.ROOT);
        while (value.startsWith("/")) value = value.substring(1);
        int space = value.indexOf(' ');
        String command = space >= 0 ? value.substring(0, space) : value;
        if (blockedCommands.contains(command)) return true;
        int colon = command.indexOf(':');
        return colon >= 0 && blockedCommands.contains(command.substring(colon + 1));
    }

    private static void addNormalized(Set<String> values, String raw) {
        if (raw == null) return;
        String value = raw.trim().toLowerCase(Locale.ROOT);
        while (value.startsWith("/")) value = value.substring(1);
        if (!value.isBlank()) values.add(value);
    }

    private boolean enabled() { return enabled; }

    private boolean debugEnabled() { return debug; }

    private void debug(String message) {
        if (debugEnabled()) plugin.getLogger().info("[TabComplete] " + message);
    }

    private static String sanitize(String value) {
        return value == null ? "" : value.replace('\n', ' ').replace('\r', ' ');
    }
}
