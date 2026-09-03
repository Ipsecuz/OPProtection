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
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public final class DiscordBot {
    /** Discord allows roughly 5 messages per 2 seconds per channel; stay under it. */
    private static final long SEND_WINDOW_MILLIS = 2_000L;
    private static final long MAX_DEFER_MILLIS = 15_000L;

    private final GatewayDiscordClient client;
    private final String channelId;
    private final OPProtection plugin;
    private final Map<String, Snowflake> active2faMessages = new ConcurrentHashMap<>();
    private final Object sendRateLock = new Object();
    private final ArrayDeque<Long> sendTimestamps = new ArrayDeque<>();
    private volatile int maxMessagesPerWindow;

    public DiscordBot(OPProtection plugin, String token, String channelId) {
        this.plugin = plugin;
        this.channelId = channelId;
        this.maxMessagesPerWindow = Math.max(1, Math.min(50,
                plugin.getConfig().getInt("discord.rate-limit.messages-per-2-seconds", 5)));
        try {
            this.client = DiscordClientBuilder.create(token).build().login()
                    .timeout(Duration.ofSeconds(30)).block();
            if (client == null) throw new IllegalStateException("Discord client is null");
            plugin.getLogger().info("[Discord] Bot đã kết nối thành công. Rate limit: "
                    + maxMessagesPerWindow + " tin nhắn / 2 giây.");
        } catch (Exception ex) {
            throw new RuntimeException("Discord login failed: " + ex.getMessage(), ex);
        }
    }

    /**
     * Sliding-window outbound rate limiter. Sends that do not fit in the current window
n     * are deferred on the async executor instead of hammering the Discord API, which
     * would otherwise trigger 429 responses and eventually a bot ban.
     */
    private void sendRateLimited(Runnable sendAction, String what) {
        long deferMillis;
        synchronized (sendRateLock) {
            long now = System.currentTimeMillis();
            while (!sendTimestamps.isEmpty() && now - sendTimestamps.peekFirst() >= SEND_WINDOW_MILLIS) {
                sendTimestamps.pollFirst();
            }
            if (sendTimestamps.size() < maxMessagesPerWindow) {
                sendTimestamps.addLast(now);
                deferMillis = 0L;
            } else {
                deferMillis = SEND_WINDOW_MILLIS - (now - sendTimestamps.peekFirst()) + 1L;
            }
        }
        if (deferMillis <= 0L) {
            sendAction.run();
            return;
        }
        if (deferMillis > MAX_DEFER_MILLIS) {
            plugin.getLogger().warning("[Discord] Rate limit: bỏ qua gửi '" + what
                    + "' để tránh bị Discord hạn chế.");
            return;
        }
        plugin.getSchedulerService().runAsyncDelayed(() -> sendRateLimited(sendAction, what),
                deferMillis, TimeUnit.MILLISECONDS);
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

        sendRateLimited(() -> channel().subscribe(channel -> createOrUpdate(channel, type, placeholders, embed.build(), withButton),
                error -> plugin.getLogger().severe("[Discord] Không thể truy cập channel: " + error.getMessage())),
                "embed " + type);
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
        sendRateLimited(() -> channel().flatMap(channel -> channel.createMessage(content))
                .timeout(Duration.ofSeconds(10))
                .subscribe(ignored -> { }, error -> plugin.getLogger().warning("[Discord] Không thể gửi message: " + error.getMessage())),
                "message");
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

    /**
     * Send IP change alert embed, optionally mentioning a role.
     *
     * @param playerName the player name
     * @param currentIp the new IP address
     * @param trustedIp the previously stored IP
     * @param alertRoleId Discord role ID to mention (can be null/empty)
     */
    public void sendIpChangeAlert(String playerName, String currentIp, String trustedIp, String alertRoleId) {
        if (client == null) return;
        String timestamp = java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")
                .withZone(java.time.ZoneId.systemDefault()).format(java.time.Instant.now());

        Map<String, String> placeholders = new java.util.HashMap<>();
        placeholders.put("player", playerName);
        placeholders.put("current-ip", currentIp);
        placeholders.put("trusted-ip", trustedIp);
        placeholders.put("timestamp", timestamp);

        ConfigurationSection section = plugin.getEmbedConfig().getConfigurationSection("ip-change-alert");
        if (section == null) {
            plugin.getLogger().warning("[Discord] Thiếu embed section: ip-change-alert");
            return;
        }

        EmbedCreateSpec.Builder embed = EmbedCreateSpec.builder()
                .title(replace(section.getString("title", "IP Change Alert"), placeholders))
                .color(Color.of(section.getInt("color", 16766720)))
                .timestamp(java.time.Instant.now());
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

        String content = "";
        if (alertRoleId != null && !alertRoleId.isBlank()) {
            content = "<@&" + alertRoleId + ">";
        }

        String finalContent = content;
        sendRateLimited(() -> channel().subscribe(channel -> {
            MessageCreateSpec.Builder msgBuilder = MessageCreateSpec.builder().addEmbed(embed.build());
            if (!finalContent.isEmpty()) {
                msgBuilder.content(finalContent);
            }
            channel.createMessage(msgBuilder.build()).timeout(Duration.ofSeconds(10))
                    .subscribe(ignored -> { },
                            error -> plugin.getLogger().severe("[Discord] Không thể gửi IP change alert: " + error.getMessage()));
        }, error -> plugin.getLogger().severe("[Discord] Không thể truy cập channel: " + error.getMessage())),
                "ip-change-alert");
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
