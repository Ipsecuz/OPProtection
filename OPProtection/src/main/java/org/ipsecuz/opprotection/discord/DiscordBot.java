package org.ipsecuz.opprotection.discord;

import discord4j.common.util.Snowflake;
import discord4j.core.DiscordClientBuilder;
import discord4j.core.GatewayDiscordClient;
import discord4j.core.object.entity.Message;
import discord4j.core.object.entity.channel.MessageChannel;
import discord4j.core.spec.EmbedCreateSpec;
import discord4j.core.spec.MessageCreateSpec;
import discord4j.core.spec.MessageEditSpec;
import discord4j.rest.util.Color;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.ipsecuz.opprotection.OPProtection;

public class DiscordBot {
    private final GatewayDiscordClient client;
    private final String channelId;
    private final OPProtection plugin;
    private final Map<String, Snowflake> active2faMessages = new HashMap<>();

    public DiscordBot(OPProtection plugin, String token, String channelId) {
        this.plugin = plugin;
        this.channelId = channelId;
        if (channelId.isEmpty()) {
            plugin.getLogger().warning("\u26a0 channelId không được cấu hình trong config.yml!");
        }
        
        System.setProperty("org.ipsecuz.opprotection.libs.reactor.netty.http.client.decompress", "false");
        System.setProperty("org.ipsecuz.opprotection.libs.reactor.netty.ioWorkerCount", "2");
        System.setProperty("org.ipsecuz.opprotection.libs.reactor.netty.tcp.ssl.handshakeTimeout", "10000");
        
        try {
            this.client = DiscordClientBuilder.create(token)
                    .build()
                    .login()
                    .retry(3) 
                    .block(java.time.Duration.ofSeconds(30));
                    
            plugin.getLogger().info("§aDiscord Bot connected successfully");
        } catch (Exception e) {
            plugin.getLogger().severe("Không thể khởi tạo Discord Bot: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Discord Bot login failed", e);
        }
    }

    public void shutdown() {
        if (this.client != null) {
            this.client.logout().block();
        }
    }

    public void sendEmbed(String type, Map<String, String> placeholders, boolean withButton) {
        if (this.client == null) return;

        Mono<MessageChannel> channelMono = this.client.getChannelById(Snowflake.of(this.channelId)).cast(MessageChannel.class);

        if (channelMono == null) return;

        Map<String, Object> section = this.plugin.getEmbedConfig().getConfigurationSection(type).getValues(false);
        if (section == null) {
            return;
        }

        String rawTitle = (String)section.getOrDefault("title", "Thông báo");
        String rawFooter = (String)section.getOrDefault("footer", "OPProtection Bot");

        EmbedCreateSpec.Builder embed = EmbedCreateSpec.builder()
                .title(this.replacePlaceholders(rawTitle, placeholders))
                .color(Color.of(((Number)section.getOrDefault("color", 65535)).intValue()))
                .footer(this.replacePlaceholders(rawFooter, placeholders), null)
                .timestamp(Instant.now());

        List<Map<String, Object>> fields = (List)section.get("fields");
        if (fields != null) {
            for (Map<String, Object> field : fields) {
                String name = (String)field.getOrDefault("name", "");
                String value = (String)field.getOrDefault("value", "");
                embed.addField(
                        this.replacePlaceholders(name, placeholders),
                        this.replacePlaceholders(value, placeholders),
                        false
                );
            }
        }

        String player = placeholders.getOrDefault("player", "unknown");

        channelMono.subscribe(
                channel -> {
                    if (this.active2faMessages.containsKey(player) && (type.equals("2fa-code") || type.equals("verified"))) {
                        Snowflake msgId = this.active2faMessages.get(player);

                        MessageEditSpec editSpec = MessageEditSpec.builder()
                                .contentOrNull(type.equals("verified") ? "✅ Đã xác minh thành công!" : "🔐 Yêu cầu xác minh 2FA cho " + player)
                                .addEmbed(embed.build())
                                .build();

                        channel.getMessageById(msgId).flatMap(m -> m.edit(editSpec))
                                .retry(2)  // Retry 2 times on failure
                                .timeout(java.time.Duration.ofSeconds(10))  // 10 second timeout
                                .subscribe(
                                        success -> {
                                            if (type.equals("verified")) {
                                                this.active2faMessages.remove(player);
                                            }
                                        },
                                        error -> {
                                            if (error.getMessage() != null && (error.getMessage().contains("404") || error.getMessage().contains("10008"))) {
                                                this.active2faMessages.remove(player);
                                                this.plugin.getLogger().warning("Tin nhắn cũ không tồn tại cho player " + player + ", sẽ gửi tin nhắn mới.");
                                                createNewMessage(channel, embed, player, type);
                                            } else {
                                                this.plugin.getLogger().warning("Lỗi khi chỉnh sửa tin nhắn Discord: " + error.getMessage());
                                            }
                                        }
                                );
                        return;
                    }
                    createNewMessage(channel, embed, player, type);
                },
                error -> {
                    this.plugin.getLogger().severe("Không thể lấy kênh Discord: " + error.getMessage());
                }
        );
    }

    private void createNewMessage(MessageChannel channel, EmbedCreateSpec.Builder embed, String player, String type) {
        MessageCreateSpec.Builder msg = MessageCreateSpec.builder().content(
                (String)(type.equals("2fa-code") ? "🔐 Yêu cầu xác minh 2FA cho " + player : "📢 Thông báo OPProtection!")
        ).addEmbed(embed.build());

        channel.createMessage(msg.build())
                .retry(3)  
                .timeout(java.time.Duration.ofSeconds(10)) 
                .subscribe(
                success -> {
                    if (type.equals("2fa-code") && success != null) {
                        this.active2faMessages.put(player, success.getId());
                    }
                },
                error -> {
                    this.plugin.getLogger().severe("Không thể gửi tin nhắn Discord: " + error.getMessage());
                }
        );
    }

    public void sendSimpleMessage(String content) {
        if (this.client == null) {
            plugin.getLogger().warning("Discord client is null, cannot send message");
            return;
        }
        
        try {
            Mono<MessageChannel> channelMono = this.client.getChannelById(Snowflake.of(this.channelId))
                    .cast(MessageChannel.class)
                    .doOnError(error -> {
                        if (error.getMessage() != null && error.getMessage().contains("404")) {
                            plugin.getLogger().severe("Discord channel not found (404). Check channelId in config.yml");
                        } else {
                            plugin.getLogger().severe("Failed to get Discord channel: " + error.getMessage());
                        }
                    });

            channelMono.subscribe(
                    channel -> channel.createMessage(content)
                            .retry(3)  
                            .timeout(java.time.Duration.ofSeconds(10))
                            .subscribe(
                                success -> {
                                    plugin.getLogger().fine("Discord message sent successfully");
                                },
                                error -> {
                                    String errorMsg = error.getMessage();
                                    if (errorMsg != null) {
                                        if (errorMsg.contains("Connection reset")) {
                                            plugin.getLogger().warning("Discord connection reset. This may be temporary. The message will be retried on next attempt.");
                                        } else if (errorMsg.contains("Timeout")) {
                                            plugin.getLogger().warning("Discord request timeout. Network may be slow.");
                                        } else if (errorMsg.contains("403") || errorMsg.contains("Forbidden")) {
                                            plugin.getLogger().severe("Discord permission denied. Check bot permissions in the channel.");
                                        } else {
                                            plugin.getLogger().severe("Failed to send Discord message: " + errorMsg);
                                        }
                                    } else {
                                        plugin.getLogger().severe("Unknown error sending Discord message: " + error.getClass().getSimpleName());
                                    }
                                }
                            ),
                    error -> {
                        if (error.getMessage() != null && error.getMessage().contains("Connection reset")) {
                            plugin.getLogger().warning("Discord connection issue. Attempting reconnection...");
                        } else {
                            plugin.getLogger().warning("Error accessing Discord channel: " + error.getMessage());
                        }
                    }
            );
        } catch (Exception e) {
            plugin.getLogger().severe("Exception in sendSimpleMessage: " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("Connection reset")) {
                plugin.getLogger().warning("Discord connection reset. This is usually temporary and will recover.");
            }
            e.printStackTrace();
        }
    }

    public void sendSpoofAlertEmbed(String playerName, String socketIp, String spoofedIp, String spoofedUuid, String reason) {
        Map<String, String> placeholders = Map.of(
                "player", playerName,
                "ip", socketIp,
                "spoofed_ip", spoofedIp,
                "spoofed_uuid", spoofedUuid,
                "reason", reason
        );
        this.sendEmbed("spoof-alert", placeholders, false);
    }

    public void sendSpoofAlertEmbed(String playerName, String socketIp, String spoofedIp, String reason) {
        this.sendSpoofAlertEmbed(playerName, socketIp, spoofedIp, "N/A", reason);
    }

    private String replacePlaceholders(String text, Map<String, String> placeholders) {
        if (text == null) {
            return "";
        }
        for (Map.Entry<String, String> e : placeholders.entrySet()) {
            text = text.replace("%" + e.getKey() + "%", e.getValue());
        }
        return text;
    }

    public GatewayDiscordClient getClient() {
        return this.client;
    }

    public boolean isConnected() {
        return this.client != null;
    }
}