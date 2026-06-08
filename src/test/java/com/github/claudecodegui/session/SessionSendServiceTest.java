package com.github.claudecodegui.session;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class SessionSendServiceTest {

    @Test
    public void normalizeRequestedPermissionModeRejectsBlankAndUnknownValues() {
        assertNull(SessionSendService.normalizeRequestedPermissionMode(null));
        assertNull(SessionSendService.normalizeRequestedPermissionMode(" "));
        assertNull(SessionSendService.normalizeRequestedPermissionMode("dangerouslyAllowEverything"));
    }

    @Test
    public void resolveEffectivePermissionModePrefersRequestedModeWhenValid() {
        assertEquals(
                "acceptEdits",
                SessionSendService.resolveEffectivePermissionMode("claude", "acceptEdits", "default")
        );
    }

    @Test
    public void resolveEffectivePermissionModeFallsBackToSessionModeAndDowngradesCodexPlan() {
        assertEquals(
                "default",
                SessionSendService.resolveEffectivePermissionMode("codex", null, "plan")
        );
        assertEquals(
                "default",
                SessionSendService.resolveEffectivePermissionMode("claude", null, null)
        );
    }

    @Test
    public void normalizeRequestedReasoningEffortRejectsBlankAndUnknownValues() {
        assertNull(SessionSendService.normalizeRequestedReasoningEffort(null));
        assertNull(SessionSendService.normalizeRequestedReasoningEffort(" "));
        assertNull(SessionSendService.normalizeRequestedReasoningEffort("extreme"));
        assertEquals("low", SessionSendService.normalizeRequestedReasoningEffort(" low "));
        assertEquals("xhigh", SessionSendService.normalizeRequestedReasoningEffort("xhigh"));
        assertEquals("max", SessionSendService.normalizeRequestedReasoningEffort("max"));
    }

    @Test
    public void getCodexRuntimeAccessErrorRequiresAuthorizationOrManagedProvider() {
        assertEquals(
                "Codex local configuration access is not authorized. Please authorize local ~/.codex access or enable a managed Codex provider first.",
                SessionSendService.getCodexRuntimeAccessError("inactive")
        );
        assertNull(SessionSendService.getCodexRuntimeAccessError("managed"));
        assertNull(SessionSendService.getCodexRuntimeAccessError("cli_login"));
    }

    @Test
    public void newSessionStateDoesNotInjectDefaultClaudeReasoningEffort() {
        SessionState state = new SessionState();

        assertNull(state.getReasoningEffort());
    }
}
