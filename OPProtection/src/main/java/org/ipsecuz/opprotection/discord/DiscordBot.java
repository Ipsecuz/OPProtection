package org.ipsecuz.opprotection.discord;

import discord4j.common.util.Snowflake;
import discord4j.core.DiscordClientBuilder;
import discord4j.core.GatewayDiscordClient;
import discord4j.core.object.component.ActionRow;
import discord4j.core.object.component.Button;
import discord4j.core.object.entity.channel.MessageChannel;
import discord4j.core.spec.EmbedCreateSpec;
import discord4j.core.spec.MessageCreateSpec;
import discord4j.core.spec.MessageEditSpec;
import discord4j.rest.util.Color;
import org.bukkit.configuration.ConfigurationSection;
import org.ipsecuz.opprotection.OPProtection;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class DiscordBot {
    private final GatewayDiscordClient client;
    private final String channelId;
    private final OPProtection plugin;
    private final Map<String, Snowflake> active2faMessages = new ConcurrentHashMap<>();

    public DiscordBot(OPProtection plugin, String token, String channelId) {
        this.plugin = plugin;
        this.channelId = channelId;
        try {
            this.client = DiscordClientBuilder.create(token).build().login()
                    .timeout(Duration.ofSeconds(30)).block();
            if (client == null) throw new IllegalStateException("Discord client is null");
            plugin.getLogger().info("[Discord] Bot đã kết nối thành công.");
        } catch (Exception ex) {
            throw new RuntimeException("Discord login failed: " + ex.getMessage(), ex);
        }
    }

    public void shutdown() {
        if (client != null) {
            try { client.logout().timeout(Duration.ofSeconds(5)).block(); }
            catch (Exception ex) { plugin.getLogger().warning("[Discord] Logout lỗi: " + ex.getMessage()); }
        }
    }

    public void sendEmbed(String type, Map<String, String> placeholders, boolean withButton) {
        if (client == null) return;
        ConfigurationSection section = plugin.getEmbedConfig().getConfigurationSection(type);
        if (section == null) {
            plugin.getLogger().warning("[Discord] Thiếu embed section: " + type);
            return;
        }
        EmbedCreateSpec.Builder embed = EmbedCreateSpec.builder()
                .title(replace(section.getString("title", "OPProtection"), placeholders))
                .color(Color.of(section.getInt("color", 65535)))
                .timestamp(Instant.now());
        String footer = section.getString("footer", "OPProtection Security");
        if (footer != null && !footer.isBlank()) embed.footer(replace(footer, placeholders), null);

        List<Map<?, ?>> fields = section.getMapList("fields");
        for (Map<?, ?> field : fields) {
            Object rawName = field.get("name");
            Object rawValue = field.get("value");
            Object rawInline = field.get("inline");
            String name = replace(rawName == null ? "" : String.valueOf(rawName), placeholders);
            String value = replace(rawValue == null ? "" : String.valueOf(rawValue), placeholders);
            boolean inline = Boolean.parseBoolean(rawInline == null ? "false" : String.valueOf(rawInline));
            embed.addField(name, value, inline);
        }

        channel().subscribe(channel -> createOrUpdate(channel, type, placeholders, embed.build(), withButton),
                error -> plugin.getLogger().severe("[Discord] Không thể truy cập channel: " + error.getMessage()));
    }

    private void createOrUpdate(MessageChannel channel, String type, Map<String, String> placeholders,
                                EmbedCreateSpec embed, boolean withButton) {
        String player = placeholders.getOrDefault("player", "unknown");
        Snowflake existing = active2faMessages.get(player);
        if (existing != null && (type.equals("2fa-code") || type.equals("verified"))) {
            channel.getMessageById(existing)
                    .flatMap(message -> message.edit(MessageEditSpec.builder().addEmbed(embed).build()))
                    .timeout(Duration.ofSeconds(10))
                    .subscribe(message -> {
                        if (type.equals("verified")) active2faMessages.remove(player);
                    }, error -> {
                        active2faMessages.remove(player);
                        createNew(channel, type, placeholders, embed, withButton);
                    });
            return;
        }
        createNew(channel, type, placeholders, embed, withButton);
    }

    private void createNew(MessageChannel channel, String type, Map<String, String> placeholders,
                           EmbedCreateSpec embed, boolean withButton) {
        MessageCreateSpec.Builder builder = MessageCreateSpec.builder().addEmbed(embed);
        if (withButton) {
            String requestId = placeholders.get("request_id");
            if (requestId != null && !requestId.isBlank()) {
                builder.addComponent(ActionRow.of(Button.success("opprotect:verify:" + requestId, "Xác minh quản trị viên")));
            }
        }
        channel.createMessage(builder.build()).timeout(Duration.ofSeconds(10)).subscribe(message -> {
            if (type.equals("2fa-code")) active2faMessages.put(placeholders.getOrDefault("player", "unknown"), message.getId());
        }, error -> plugin.getLogger().severe("[Discord] Không thể gửi embed " + type + ": " + error.getMessage()));
    }

    public void sendSimpleMessage(String content) {
        channel().flatMap(channel -> channel.createMessage(content)).timeout(Duration.ofSeconds(10))
                .subscribe(ignored -> { }, error -> plugin.getLogger().warning("[Discord] Không thể gửi message: " + error.getMessage()));
    }

    public void sendSpoofAlertEmbed(String playerName, String socketIp, String spoofedIp, String spoofedUuid, String reason) {
        sendEmbed("spoof-alert", Map.of(
                "player", playerName,
                "ip", socketIp,
                "socketIp", socketIp,
                "socket_ip", socketIp,
                "spoofedIp", spoofedIp,
                "spoofed_ip", spoofedIp,
                "spoofedUuid", spoofedUuid,
                "spoofed_uuid", spoofedUuid,
                "reason", reason), false);
    }

    public void sendSpoofAlertEmbed(String playerName, String socketIp, String spoofedIp, String reason) {
        sendSpoofAlertEmbed(playerName, socketIp, spoofedIp, "N/A", reason);
    }

    private Mono<MessageChannel> channel() {
        return client.getChannelById(Snowflake.of(channelId)).ofType(MessageChannel.class);
    }

    private String replace(String text, Map<String, String> placeholders) {
        String output = text == null ? "" : text;
        for (Map.Entry<String, String> entry : placeholders.entrySet()) {
            output = output.replace("%" + entry.getKey() + "%", entry.getValue());
        }
        return output;
    }

    public GatewayDiscordClient getClient() { return client; }
    public boolean isConnected() { return client != null; }
}
