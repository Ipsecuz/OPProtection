package org.ipsecuz.opprotection.integration.luckperms;

import net.luckperms.api.LuckPerms;
import net.luckperms.api.LuckPermsProvider;
import net.luckperms.api.event.node.NodeAddEvent;
import net.luckperms.api.model.user.User;
import net.luckperms.api.node.Node;
import net.luckperms.api.node.types.PermissionNode;
import org.ipsecuz.opprotection.OPProtection;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

/**
 * LuckPerms-backed implementation. This class is loaded reflectively only when LuckPerms
 * is enabled, preventing optional API classes from leaking into OPProtection's core path.
 */
public final class LuckPermsHookImpl implements LuckPermsHook {
    private final OPProtection plugin;
    private final LuckPerms luckPerms;
    private final Predicate<UUID> consumeAuthorizedGrant;
    private final BiConsumer<UUID, String> unauthorizedGrantHandler;

    public LuckPermsHookImpl(OPProtection plugin,
                             Predicate<UUID> consumeAuthorizedGrant,
                             BiConsumer<UUID, String> unauthorizedGrantHandler) {
        this.plugin = plugin;
        this.consumeAuthorizedGrant = consumeAuthorizedGrant;
        this.unauthorizedGrantHandler = unauthorizedGrantHandler;
        this.luckPerms = LuckPermsProvider.get();
        registerListener();
    }

    @Override
    public boolean isAvailable() {
        return true;
    }

    @Override
    public boolean hasWildcard(UUID uuid) {
        if (uuid == null) return false;
        User user = luckPerms.getUserManager().getUser(uuid);
        return user != null && user.getCachedData().getPermissionData().checkPermission("*").asBoolean();
    }

    @Override
    public CompletionStage<Void> grantWildcard(UUID uuid, String playerName) {
        if (uuid == null) return CompletableFuture.completedFuture(null);
        return luckPerms.getUserManager().modifyUser(uuid, user -> {
                    user.transientData().clear(node -> node.getKey().equals("*") && !node.getValue());
                    user.data().add(PermissionNode.builder("*").value(true).build());
                })
                .thenApply(ignored -> null);
    }

    @Override
    public void revokeWildcardAndSuppress(UUID uuid) {
        if (uuid == null) return;
        PermissionNode denyWildcard = PermissionNode.builder("*").value(false).build();
        luckPerms.getUserManager().modifyUser(uuid, user -> {
            user.data().clear(node -> node.getKey().equals("*") && node.getValue());
            user.transientData().clear(node -> node.getKey().equals("*"));
            user.transientData().add(denyWildcard);
        }).exceptionally(ex -> {
            plugin.getLogger().warning("[LuckPerms] Không thể chặn * của " + uuid + ": " + ex.getMessage());
            return null;
        });
    }

    @Override
    public void clearWildcardSuppression(UUID uuid) {
        if (uuid == null) return;
        luckPerms.getUserManager().modifyUser(uuid,
                        user -> user.transientData().clear(node -> node.getKey().equals("*") && !node.getValue()))
                .exceptionally(ex -> {
                    plugin.getLogger().warning("[LuckPerms] Không thể gỡ lớp chặn * của " + uuid + ": " + ex.getMessage());
                    return null;
                });
    }

    private void registerListener() {
        luckPerms.getEventBus().subscribe(plugin, NodeAddEvent.class, event -> {
            if (!(event.getTarget() instanceof User user)) return;
            Node node = event.getNode();
            if (!(node instanceof PermissionNode permission)
                    || !permission.getPermission().equals("*")
                    || !permission.getValue()) {
                return;
            }

            UUID uuid = user.getUniqueId();
            if (consumeAuthorizedGrant.test(uuid)) return;

            String username = user.getUsername();
            luckPerms.getUserManager().modifyUser(uuid, loaded -> loaded.data().remove(node))
                    .whenComplete((ignored, ex) -> {
                        if (ex != null) {
                            plugin.getLogger().warning("[LuckPerms] Không thể thu hồi wildcard trái phép của "
                                    + uuid + ": " + ex.getMessage());
                        }
                        unauthorizedGrantHandler.accept(uuid, username);
                    });
        });
    }
}
