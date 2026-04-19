package org.ipsecuz.opprotection.listener;

import com.github.retrooper.packetevents.event.PacketListenerAbstract;
import com.github.retrooper.packetevents.event.PacketSendEvent;
import com.github.retrooper.packetevents.protocol.packettype.PacketType;
import com.github.retrooper.packetevents.wrapper.play.server.WrapperPlayServerPluginMessage;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import org.ipsecuz.opprotection.OPProtection;
import java.nio.charset.StandardCharsets;

public class F3BrandBlocker extends PacketListenerAbstract {
    private final OPProtection plugin;
    private String fakeBrand = "Vanilla";
    private boolean enabled = false;

    public F3BrandBlocker(OPProtection plugin) {
        this.plugin = plugin;
        loadConfig();
    }

    private void loadConfig() {
        this.enabled = plugin.getConfig().getBoolean("f3-brand-spoof.enabled", false);
        this.fakeBrand = plugin.getConfig().getString("f3-brand-spoof.fake-brand", "Vanilla");
        
        if (this.enabled) {
            plugin.getLogger().info("§a✓ F3 Brand Spoofer enabled - Brand: " + this.fakeBrand);
        }
    }

    @Override
    public void onPacketSend(PacketSendEvent event) {
        if (!this.enabled) return;

        if (plugin.getConfig().getBoolean("ip-forwarding", false)) return;

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

                    if (plugin.getConfig().getBoolean("f3-brand-spoof.debug", false)) {
                        plugin.getLogger().info("§e[F3] Spoofed brand to: " + finalBrand);
                    }
                }

            } catch (Exception e) {
                plugin.getLogger().warning("Error processing F3 brand packet: " + e.getMessage());
            }
        }
    }

    private void writeVarInt(ByteBuf buffer, int value) {
        while ((value & 0xFFFFFF80) != 0) {
            buffer.writeByte((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        buffer.writeByte(value & 0x7F);
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

    ByteBuf buffer = Unpooled.buffer();
    writeVarInt(buffer, stringBytes.length);
    buffer.writeBytes(stringBytes);

    byte[] result = new byte[buffer.readableBytes()];
    buffer.readBytes(result);
    return result;
}

    private String translateColor(String text) {
        return text.replace("&", "§");
    }
}
