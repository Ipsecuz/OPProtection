package org.ipsecuz.opprotection.integration.luckperms;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

final class NoopLuckPermsHook implements LuckPermsHook {
    static final NoopLuckPermsHook INSTANCE = new NoopLuckPermsHook();

    private NoopLuckPermsHook() {
    }

    @Override
    public boolean isAvailable() {
        return false;
    }

    @Override
    public boolean hasWildcard(UUID uuid) {
        return false;
    }

    @Override
    public CompletionStage<Void> grantWildcard(UUID uuid, String playerName) {
        return CompletableFuture.completedFuture(null);
    }

    @Override
    public void revokeWildcardAndSuppress(UUID uuid) {
        // LuckPerms is not installed.
    }

    @Override
    public void clearWildcardSuppression(UUID uuid) {
        // LuckPerms is not installed.
    }
}
