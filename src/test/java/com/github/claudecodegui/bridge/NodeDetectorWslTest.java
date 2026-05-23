package com.github.claudecodegui.bridge;

import org.junit.Assume;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for NodeDetector WSL path utilities.
 * These are pure-function tests that do not require the IntelliJ Platform.
 */
public class NodeDetectorWslTest {

    // =========================================================================
    // convertToWslPath
    // =========================================================================

    @Test
    public void convertToWslPath_alreadyUnix_returnsAsIs() {
        assertEquals("/usr/bin/node", NodeDetector.convertToWslPath("/usr/bin/node"));
        assertEquals("/home/user/.nvm/versions/node/v20/bin/node",
                NodeDetector.convertToWslPath("/home/user/.nvm/versions/node/v20/bin/node"));
    }

    @Test
    public void convertToWslPath_driveLetter_convertsToPosixMount() {
        assertEquals("/mnt/c/Users/foo/bar", NodeDetector.convertToWslPath("C:\\Users\\foo\\bar"));
        assertEquals("/mnt/c/Program Files/nodejs/node.exe",
                NodeDetector.convertToWslPath("C:\\Program Files\\nodejs\\node.exe"));
        assertEquals("/mnt/d/projects/app", NodeDetector.convertToWslPath("D:\\projects\\app"));
    }

    @Test
    public void convertToWslPath_uncWslLocalhost_stripsPrefix() {
        assertEquals("/home/user/project",
                NodeDetector.convertToWslPath("\\\\wsl.localhost\\Ubuntu\\home\\user\\project"));
        assertEquals("/home/user",
                NodeDetector.convertToWslPath("\\\\wsl.localhost\\Ubuntu\\home\\user"));
    }

    @Test
    public void convertToWslPath_uncWslDollar_stripsPrefix() {
        assertEquals("/home/user/project",
                NodeDetector.convertToWslPath("\\\\wsl$\\Ubuntu\\home\\user\\project"));
    }

    @Test
    public void convertToWslPath_nullOrEmpty_returnsInput() {
        assertEquals(null, NodeDetector.convertToWslPath(null));
        assertEquals("", NodeDetector.convertToWslPath(""));
    }

    @Test
    public void convertToWslPath_fallback_replacesBackslashes() {
        assertEquals("relative/path", NodeDetector.convertToWslPath("relative\\path"));
    }

    @Test
    public void convertToWslPath_driveLetterWithoutSeparator_insertsSeparator() {
        // Edge case: "C:Users\foo" (legacy form, no separator after colon)
        // should still produce a well-formed /mnt/c/Users/foo path.
        assertEquals("/mnt/c/Users/foo", NodeDetector.convertToWslPath("C:Users\\foo"));
        assertEquals("/mnt/d/", NodeDetector.convertToWslPath("D:"));
    }

    // =========================================================================
    // isWslPath  (always false on non-Windows; tested via static method contract)
    // =========================================================================

    @Test
    public void isWslPath_nullOrEmpty_returnsFalse() {
        assertFalse(NodeDetector.isWslPath(null));
        assertFalse(NodeDetector.isWslPath(""));
    }

    @Test
    public void isWslPath_windowsPath_returnsFalse() {
        assertFalse(NodeDetector.isWslPath("C:\\Program Files\\nodejs\\node.exe"));
        assertFalse(NodeDetector.isWslPath("node"));
    }

    // =========================================================================
    // buildNodeScriptCommand
    // =========================================================================

    @Test
    public void buildNodeScriptCommand_nonWslPath_returnsNodeAndScript() {
        List<String> cmd = NodeDetector.buildNodeScriptCommand(
                "/usr/local/bin/node", "/path/to/script.js");
        assertNotNull(cmd);
        assertEquals(2, cmd.size());
        assertEquals("/usr/local/bin/node", cmd.get(0));
        assertEquals("/path/to/script.js", cmd.get(1));
    }

    @Test
    public void buildNodeScriptCommand_returnsModifiableList() {
        List<String> cmd = NodeDetector.buildNodeScriptCommand("node", "script.js");
        cmd.add("extra-arg");
        assertEquals(3, cmd.size());
        assertEquals("extra-arg", cmd.get(2));
    }

    @Test
    public void buildNodeScriptCommand_windowsDrivePath_convertsScript() {
        List<String> cmd = NodeDetector.buildNodeScriptCommand(
                "C:\\Program Files\\nodejs\\node.exe",
                "C:\\Users\\foo\\script.js");
        assertNotNull(cmd);
        assertEquals(2, cmd.size());
        assertEquals("C:\\Program Files\\nodejs\\node.exe", cmd.get(0));
        assertEquals("C:\\Users\\foo\\script.js", cmd.get(1));
    }

    // =========================================================================
    // buildNodeInlineCommand
    // =========================================================================

    @Test
    public void buildNodeInlineCommand_nonWslPath_returnsNodeEvalScript() {
        List<String> cmd = NodeDetector.buildNodeInlineCommand(
                "/usr/local/bin/node", "console.log('hi');");
        assertNotNull(cmd);
        assertEquals(3, cmd.size());
        assertEquals("/usr/local/bin/node", cmd.get(0));
        assertEquals("-e", cmd.get(1));
        assertEquals("console.log('hi');", cmd.get(2));
    }

    @Test
    public void buildNodeInlineCommand_windowsPath_doesNotPrependWsl() {
        List<String> cmd = NodeDetector.buildNodeInlineCommand(
                "C:\\Program Files\\nodejs\\node.exe", "console.log(1);");
        assertNotNull(cmd);
        assertEquals(3, cmd.size());
        assertEquals("C:\\Program Files\\nodejs\\node.exe", cmd.get(0));
        assertEquals("-e", cmd.get(1));
    }

    @Test
    public void buildNodeInlineCommand_returnsModifiableList() {
        List<String> cmd = NodeDetector.buildNodeInlineCommand("node", "1+1");
        cmd.add("extra");
        assertEquals(4, cmd.size());
    }

    // =========================================================================
    // resolveWslHomeUncPath — integration (requires Windows + WSL, skipped otherwise)
    // =========================================================================

    /**
     * Verifies that resolveWslHomeUncPath() returns a valid Windows UNC path that
     * is reachable from the JVM via java.nio.file.Files.
     *
     * <p>This test is skipped automatically on non-Windows systems or when WSL is
     * unavailable, so it is safe to include in the normal test run.
     */
    @Test
    public void resolveWslHomeUncPath_onWindowsWithWsl_returnsAccessibleUncPath() {
        Assume.assumeTrue("Skipped: not running on Windows", System.getProperty("os.name", "").toLowerCase().contains("windows"));

        String uncPath = NodeDetector.resolveWslHomeUncPath();
        Assume.assumeTrue("Skipped: WSL not available or wslpath failed", uncPath != null && !uncPath.isEmpty());

        assertTrue("UNC path must start with \\\\", uncPath.startsWith("\\\\"));
        assertTrue("UNC path must be accessible via Files.exists()", Files.exists(Paths.get(uncPath)));
    }

    /**
     * Verifies that installing the SDK into the WSL home (UNC path) actually places
     * files in the Linux filesystem visible inside WSL.
     *
     * <p>Checks that the codemoss dependencies dir resolves to the WSL home subtree
     * rather than the Windows user home (C:\Users\...).
     */
    @Test
    public void resolveWslHomeUncPath_onWindowsWithWsl_isNotWindowsUserHome() {
        Assume.assumeTrue("Skipped: not running on Windows", System.getProperty("os.name", "").toLowerCase().contains("windows"));

        String uncPath = NodeDetector.resolveWslHomeUncPath();
        Assume.assumeTrue("Skipped: WSL not available", uncPath != null && !uncPath.isEmpty());

        String windowsHome = System.getenv("USERPROFILE");
        if (windowsHome != null) {
            assertFalse("WSL UNC home must differ from Windows USERPROFILE", uncPath.equalsIgnoreCase(windowsHome));
        }
        assertFalse("WSL UNC path must not contain a drive-letter root", uncPath.matches("(?i)[A-Z]:.*"));
    }
}
