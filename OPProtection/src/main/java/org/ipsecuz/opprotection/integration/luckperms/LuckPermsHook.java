package org.ipsecuz.opprotection.integration.luckperms;

import java.util.UUID;
import java.util.concurrent.CompletionStage;

/**
 * Optional LuckPerms bridge. This interface deliberately contains no LuckPerms API types,
 * so OPProtection can start normally when LuckPerms is not installed.
 */
public interface LuckPermsHook {
    boolean isAvailable();

    boolean hasWildcard(UUID uuid);

    CompletionStage<Void> grantWildcard(UUID uuid, String playerName);

    void revokeWildcardAndSuppress(UUID uuid);

    void clearWildcardSuppression(UUID uuid);

    static LuckPermsHook unavailable() {
        return NoopLuckPermsHook.INSTANCE;
    }
}
