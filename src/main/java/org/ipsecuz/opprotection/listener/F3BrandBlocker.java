package org.ipsecuz.opprotection.listener;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketSendEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.play.server.WrapperPlayServerPluginMessage;
import org.ipsecuz.opprotection.OPProtection;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;

public class F3BrandBlocker extends PacketListenerAbstract {
    private final OPProtection plugin;
    private volatile String fakeBrand = "Vanilla";
    private volatile boolean enabled;
    private volatile boolean debug;

    public F3BrandBlocker(OPProtection plugin) {
        this.plugin = plugin;
        loadConfig();
    }

    private void loadConfig() {
        this.enabled = plugin.getConfig().getBoolean("f3-brand-spoof.enabled", false);
        this.debug = plugin.getConfig().getBoolean("f3-brand-spoof.debug", false);
        String configured = plugin.getConfig().getString("f3-brand-spoof.fake-brand", "Vanilla");
        if (configured == null || configured.isBlank()) configured = "Vanilla";
        this.fakeBrand = configured.length() > 64 ? configured.substring(0, 64) : configured;

        if (this.enabled) {
            plugin.getLogger().info("[F3] Brand masking đã bật: " + this.fakeBrand);
        }
    }

    @Override
    public void onPacketSend(PacketSendEvent event) {
        if (!this.enabled) return;

        // Brand masking is intentionally applied on proxied backends too: the backend still
        // emits the minecraft:brand plugin message and masking it hides the server software
        // from clients regardless of ip-forwarding settings.
        if (event.getPacketType() == PacketType.Play.Server.PLUGIN_MESSAGE ||
            event.getPacketType() == PacketType.Configuration.Server.PLUGIN_MESSAGE) {

            try {
                WrapperPlayServerPluginMessage wrapper = new WrapperPlayServerPluginMessage(event);
                String channelName = wrapper.getChannelName();

                if (channelName != null &&
                    (channelName.equals("MC|Brand") || channelName.equals("minecraft:brand"))) {

                    String finalBrand = translateColor(this.fakeBrand) + "§r";

                    byte[] data = encodeMinecraftString(finalBrand);

                    wrapper.setData(data);
                    event.markForReEncode(true);

                    if (this.debug) {
                        plugin.getLogger().info("[F3] Đã thay brand thành: " + finalBrand);
                    }
                }

            } catch (Exception e) {
                plugin.getLogger().warning("Error processing F3 brand packet: " + e.getMessage());
            }
        }
    }

    public String getFakeBrand() {
        return this.fakeBrand;
    }

    public boolean isEnabled() {
        return this.enabled;
    }

    public void reload() {
        loadConfig();
    }

    private byte[] encodeMinecraftString(String text) {
        byte[] stringBytes = text.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream output = new ByteArrayOutputStream(stringBytes.length + 5);
        int value = stringBytes.length;
        while ((value & 0xFFFFFF80) != 0) {
            output.write((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        output.write(value & 0x7F);
        output.writeBytes(stringBytes);
        return output.toByteArray();
    }

    private String translateColor(String text) {
        if (text == null) return "";
        // Support &#RRGGBB hex color format
        java.util.regex.Pattern hexPattern = java.util.regex.Pattern.compile("(?i)&#([0-9a-f]{6})");
        java.util.regex.Matcher matcher = hexPattern.matcher(text);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            try {
                String hex = matcher.group(1);
                net.md_5.bungee.api.ChatColor color = net.md_5.bungee.api.ChatColor.of("#" + hex);
                matcher.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(color.toString()));
            } catch (IllegalArgumentException e) {
                // Keep original if invalid hex
                matcher.appendReplacement(sb, java.util.regex.Matcher.quoteReplacement(matcher.group()));
            }
        }
        matcher.appendTail(sb);
        // Also support legacy &-codes
        return sb.toString().replace("&", "§");
    }
}
