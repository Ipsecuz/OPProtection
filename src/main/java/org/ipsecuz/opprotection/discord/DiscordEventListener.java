package org.ipsecuz.opprotection.discord;

import discord4j.common.util.Snowflake;
import discord4j.core.GatewayDiscordClient;
import discord4j.core.event.domain.interaction.ButtonInteractionEvent;
import org.ipsecuz.opprotection.OPProtection;

import java.util.HashSet;
import java.util.Set;

public final class DiscordEventListener {
    private final OPProtection plugin;
    private final reactor.core.Disposable subscription;

    public DiscordEventListener(OPProtection plugin, GatewayDiscordClient client) {
        this.plugin = plugin;
        this.subscription = client.on(ButtonInteractionEvent.class).subscribe(this::handle,
                error -> plugin.getLogger().severe("[Discord] Button event error: " + error.getMessage()));
    }

    private void handle(ButtonInteractionEvent event) {
        String customId = event.getCustomId();
        if (!customId.startsWith("opprotect:verify:")) return;
        String requestId = customId.substring("opprotect:verify:".length());
        long userId = event.getInteraction().getUser().getId().asLong();
        Set<Long> roleIds = new HashSet<>();
        event.getInteraction().getMember().ifPresent(member -> {
            for (Snowflake role : member.getRoleIds()) roleIds.add(role.asLong());
        });

        plugin.getDiscordSyncModule().verifyFromDiscordAsync(requestId, userId, Set.copyOf(roleIds), result -> {
            String response = result.success()
                    ? "✅ Đã xác minh Discord-Sync cho `" + result.playerName() + "`."
                    : "❌ Không thể xác minh: " + result.message();
            event.reply(response).withEphemeral(true).subscribe(
                    ignored -> { },
                    error -> plugin.getLogger().warning("[Discord] Không thể reply button: " + error.getMessage()));
        });
    }

    public void shutdown() {
        if (subscription != null && !subscription.isDisposed()) subscription.dispose();
    }
}
