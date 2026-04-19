package org.ipsecuz.opprotection.discord;

import discord4j.common.util.Snowflake;
import discord4j.core.GatewayDiscordClient;
import discord4j.core.event.domain.interaction.ButtonInteractionEvent;
import discord4j.core.object.entity.User;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.ipsecuz.opprotection.OPProtection;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class DiscordEventListener {
    private final OPProtection plugin;
    private final GatewayDiscordClient client;
    private final Map<Long, String> pendingVerifications = new HashMap<>(); // Discord User ID -> Player Name

    public DiscordEventListener(OPProtection plugin, GatewayDiscordClient client) {
        this.plugin = plugin;
        this.client = client;
        this.registerListeners();
    }

    private void registerListeners() {
        if (this.client == null) {
            plugin.getLogger().warning("Discord client is null, cannot register listeners");
            return;
        }

        try {
            this.client.on(ButtonInteractionEvent.class)
                    .subscribe(
                            event -> handleButtonInteraction(event),
                            error -> plugin.getLogger().severe("Discord button event error: " + error.getMessage())
                    );

            plugin.getLogger().info("§aDiscord event listener registered successfully");
        } catch (Exception e) {
            plugin.getLogger().severe("Failed to register Discord event listener: " + e.getMessage());
        }
    }

    private void handleButtonInteraction(ButtonInteractionEvent event) {
        try {
            String customId = event.getCustomId();
            User user = event.getInteraction().getUser();

            plugin.getLogger().info("Button clicked: " + customId + " by Discord user: " + user.getUsername());

            if (customId.startsWith("verify_")) {
                String playerName = customId.substring("verify_".length());
                plugin.getServer().getGlobalRegionScheduler().run(plugin, task -> {
                    verifyPlayer(event, playerName, user);
                });
            }
            else if (customId.startsWith("cancel_")) {
                String playerName = customId.substring("cancel_".length());
                event.reply("§cHủy xác minh cho " + playerName).withEphemeral(true).block();
            }
        } catch (Exception e) {
            plugin.getLogger().warning("Error handling button interaction: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void verifyPlayer(ButtonInteractionEvent event, String playerName, User discordUser) {
        Player player = Bukkit.getPlayerExact(playerName);

        if (player == null) {
            event.reply("❌ Người chơi " + playerName + " không online!").withEphemeral(true).block();
            plugin.getLogger().warning("Verification failed: Player " + playerName + " not found");
            return;
        }

        try {
            plugin.getDiscordSyncModule().verifyPlayer(player);
            
            long timeoutMinutes = plugin.getDiscordSyncModule().getVerificationTimeoutSeconds() / 60;

            event.reply("✅ **Xác minh thành công!**\n" +
                    "Người chơi: `" + playerName + "`\n" +
                    "Discord: " + discordUser.getMention() + "\n" +
                    "Thời hạn: " + timeoutMinutes + " phút")
                    .withEphemeral(true).block();
            
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!player.isOnline()) return;
                player.sendMessage("§a✓ Xác minh Discord thành công!");
                player.sendMessage("§eBạn có thể sử dụng các lệnh bảo mật trong " + timeoutMinutes + " phút");
            });
            
            if (plugin.isDiscordEnabled()) {
                try {
                    plugin.getDiscord().sendEmbed("discord-sync-verified", Map.of(
                        "player", playerName,
                        "discordUser", discordUser.getUsername(),
                        "timeout", String.valueOf(timeoutMinutes)
                    ), false);
                } catch (Exception e) {
                    plugin.getLogger().warning("Could not send Discord verification embed: " + e.getMessage());
                }
            }

            plugin.getLogger().info("§aPlayer " + playerName + " verified successfully by " + discordUser.getUsername());

        } catch (Exception e) {
            event.reply("❌ Lỗi xác minh: " + e.getMessage()).withEphemeral(true).block();
            plugin.getLogger().severe("Verification error for " + playerName + ": " + e.getMessage());
        }
    }

    public void shutdown() {
        if (this.client != null) {
            try {
                plugin.getLogger().info("Discord event listener shutdown");
            } catch (Exception e) {
                plugin.getLogger().warning("Error shutting down Discord listener: " + e.getMessage());
            }
        }
    }
}
