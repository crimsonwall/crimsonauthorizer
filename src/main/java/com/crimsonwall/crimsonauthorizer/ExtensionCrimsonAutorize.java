/*
 * Crimson Authorizer - Automated Authorization Testing for OWASP ZAP.
 *
 * Renico Koen / crimsonwall.com / 2026.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.crimsonwall.crimsonauthorizer;

import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import com.crimsonwall.crimsonauthorizer.api.CrimsonAutorizeAPI;
import com.crimsonwall.crimsonauthorizer.config.CrimsonAutorizeOptions;
import com.crimsonwall.crimsonauthorizer.ui.CrimsonAutorizePanel;
import org.zaproxy.zap.network.HttpSenderListener;
import org.zaproxy.zap.utils.DisplayUtils;

/**
 * Main extension class for Crimson Authorizer.
 *
 * <p>Intercepts HTTP traffic from ZAP's proxy, replays each request with substituted credentials
 * (low-privilege users and unauthenticated access), and compares responses to detect authorization
 * enforcement issues.
 */
public final class ExtensionCrimsonAutorize extends ExtensionAdaptor implements HttpSenderListener {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionCrimsonAutorize.class);

    public static final String NAME = "ExtensionCrimsonAutorize";
    protected static final String PREFIX = "crimsonautorize";

    private static final int LISTENER_ORDER = 1000;
    private static final int THREAD_POOL_SIZE = 4;

    private static volatile ImageIcon cachedIcon;

    private CrimsonAutorizeOptions options;
    private AuthorizationTester tester;
    private CrimsonAutorizePanel mainPanel;
    private CrimsonAutorizeAPI api;

    private volatile boolean active = false;
    private final List<AuthorizationResult> results = new CopyOnWriteArrayList<>();
    private final AtomicInteger resultIdCounter = new AtomicInteger(0);
    private ExecutorService threadPool;

    // Full application test tracking
    private volatile boolean fullTestRunning = false;
    private final AtomicInteger fullTestProgress = new AtomicInteger(0);
    private final AtomicInteger fullTestTotal = new AtomicInteger(0);
    private final AtomicInteger fullTestCompleted = new AtomicInteger(0);
    private volatile boolean fullTestCancelled = false;
    private Runnable fullTestCompletionCallback;

    /** Maximum number of pending messages in the queue to prevent overwhelming the system. */
    private static final int MAX_PENDING_MESSAGES = 50;

    /** Maximum number of stored results to prevent unbounded memory growth. */
    private static final int MAX_RESULTS = 10000;

    public ExtensionCrimsonAutorize() {
        super(NAME);
        setI18nPrefix(PREFIX);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        options = new CrimsonAutorizeOptions();
        tester = new AuthorizationTester();
        api = new CrimsonAutorizeAPI(this);

        // Create a bounded thread pool with daemon threads to prevent blocking ZAP shutdown
        BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>(MAX_PENDING_MESSAGES);
        threadPool = new ThreadPoolExecutor(
                THREAD_POOL_SIZE,
                THREAD_POOL_SIZE,
                60L, TimeUnit.SECONDS,
                workQueue,
                r -> {
                    Thread t = new Thread(r);
                    t.setDaemon(true); // Allow ZAP to exit even if threads are running
                    t.setName("CrimsonAutorize-Worker-" + t.threadId());
                    return t;
                });
        ((ThreadPoolExecutor) threadPool).allowCoreThreadTimeOut(true);

        extensionHook.addOptionsParamSet(options);
        extensionHook.addHttpSenderListener(this);
        extensionHook.addApiImplementor(api);

        if (hasView()) {
            extensionHook.getHookView().addWorkPanel(getMainPanel());
            extensionHook.getHookView().addOptionPanel(options.getOptionsPanel());
            options.getOptionsPanel().setOnOptionsSaved(this::refreshTableColumns);
        }

        LOGGER.info("Crimson Authorizer extension hooked successfully");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private boolean isExcludedExtension(HttpMessage msg) {
        try {
            String uri = msg.getRequestHeader().getURI().toString();
            if (uri == null || uri.isEmpty()) {
                return false;
            }

            // Extract the path from the URI and check for file extension
            String path = uri.toLowerCase();

            // Handle URLs with query strings and fragments
            int queryStart = path.indexOf('?');
            if (queryStart > 0) {
                path = path.substring(0, queryStart);
            }
            int fragmentStart = path.indexOf('#');
            if (fragmentStart > 0) {
                path = path.substring(0, fragmentStart);
            }

            // Find the last dot in the path
            int lastDot = path.lastIndexOf('.');
            if (lastDot < 0 || lastDot == path.length() - 1) {
                return false; // No extension or dot at the end
            }

            // Extract extension (everything after the last dot)
            String extension = path.substring(lastDot + 1);

            // Check against excluded extensions list
            return options.getExcludeExtensions().contains(extension);
        } catch (Exception e) {
            LOGGER.debug("Error checking file extension for exclusion", e);
            return false;
        }
    }

    @Override
    public void unload() {
        super.unload();
        active = false;

        // Gracefully shut down thread pool
        if (threadPool != null) {
            threadPool.shutdown(); // Stop accepting new tasks
            try {
                // Wait up to 5 seconds for tasks to complete
                if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                    // Force shutdown if tasks don't complete
                    threadPool.shutdownNow();
                    // Wait another 2 seconds for forceful shutdown
                    threadPool.awaitTermination(2, TimeUnit.SECONDS);
                }
            } catch (InterruptedException e) {
                threadPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        LOGGER.info("Crimson Authorizer extension unloaded");
    }

    @Override
    public String getAuthor() {
        return "Renico Koen / crimsonwall.com";
    }

    @Override
    public String getDescription() {
        return getMessages().getString(PREFIX + ".desc");
    }

    @Override
    public URL getURL() {
        try {
            return URI.create("https://github.com/crimsonwall/crimsonautorize").toURL();
        } catch (Exception e) {
            return null;
        }
    }

    /** Returns the add-on's icon, cached for reuse. */
    public static ImageIcon getIcon() {
        if (cachedIcon == null) {
            cachedIcon =
                    new ImageIcon(
                            DisplayUtils.getScaledIcon(
                                            ExtensionCrimsonAutorize.class.getResource(
                                                    "resources/crimsonauthorizer-icon.png"))
                                    .getImage());
        }
        return cachedIcon;
    }

    // --- HttpSenderListener ---

    @Override
    public int getListenerOrder() {
        return LISTENER_ORDER;
    }

    @Override
    public void onHttpRequestSend(HttpMessage msg, int initiator, HttpSender sender) {
        // Not needed - we work with responses
    }

    @Override
    public void onHttpResponseReceive(HttpMessage msg, int initiator, HttpSender sender) {
        if (!active) {
            return;
        }

        // Only process proxy traffic, unless testRequester is enabled
        if (initiator == HttpSender.PROXY_INITIATOR) {
            // Always process proxied requests
        } else if (initiator == HttpSender.MANUAL_REQUEST_INITIATOR && options.isTestRequester()) {
            // Process Requester requests only if enabled
        } else {
            // Skip all other initiators
            return;
        }

        // Skip our own replayed requests
        if (msg.getUserObject() instanceof String
                && AuthorizationTester.REPLAY_MARKER.equals(msg.getUserObject())) {
            return;
        }

        // Must have a response
        if (msg.getResponseHeader() == null) {
            return;
        }

        // Check ignore 204 - skip testing if original has no content to compare
        // Note: 304 responses are now handled in EnforcementDetector - we test them
        // since a bypass would show as the unauthorized user also getting 304 (cached access)
        if (options.isIgnore304()) {
            int code = msg.getResponseHeader().getStatusCode();
            if (code == 204) {
                LOGGER.debug("Skipping 204 No Content response - no body to compare");
                return;
            }
        }

        // Check if URL has an excluded file extension
        if (isExcludedExtension(msg)) {
            return;
        }

        // Apply interception filters
        List<InterceptionFilterRule> filterRules = options.getInterceptionFilterRules();
        InterceptionFilter filter = new InterceptionFilter(filterRules);
        if (!filter.shouldTest(msg)) {
            return;
        }

        // Check if thread pool queue is full to prevent overwhelming the system
        if (threadPool instanceof ThreadPoolExecutor) {
            ThreadPoolExecutor tpe = (ThreadPoolExecutor) threadPool;
            if (tpe.getQueue().size() >= MAX_PENDING_MESSAGES) {
                LOGGER.warn("Thread pool queue full ({}), skipping message to prevent overwhelming system",
                        tpe.getQueue().size());
                return;
            }
        }

        // Submit to thread pool for async testing
        threadPool.submit(() -> processMessage(msg));
    }

    /** Process an intercepted message: snapshot config, replay with modified creds, store result. */
    private void processMessage(HttpMessage msg) {
        try {
            // Snapshot current configuration for consistency
            List<AuthCredentials> userSnapshot = new ArrayList<>(options.getUsers());
            boolean testUnauth = options.isTestUnauthenticated();
            List<EnforcementDetectorRule> unauthRules = new ArrayList<>(options.getUnauthDetectorRules());
            boolean andLogic = options.isUseAndLogic();
            List<String> authHeadersToStrip = new ArrayList<>(options.getAuthHeadersToStrip());
            List<String> authHeaderRegexToStrip = new ArrayList<>(options.getAuthHeaderRegexToStrip());
            int maxMessageSize = options.getMaxMessageSize();

            AuthorizationResult result =
                    tester.testRequest(
                            msg,
                            userSnapshot,
                            testUnauth,
                            unauthRules,
                            andLogic,
                            authHeadersToStrip,
                            authHeaderRegexToStrip,
                            maxMessageSize);

            if (result != null) {
                result.setId(resultIdCounter.incrementAndGet());
                trimResults();
                results.add(result);
                notifyResultAdded(result);
                if (result.getWorstStatus() == EnforcementStatus.BYPASSED && options.isEnableAlerts()) {
                    AlertRaiser.raiseAuthorizationBypass(msg, result, "Replay");
                }
            }
        } catch (Exception e) {
            LOGGER.error("Error processing message for authorization testing", e);
        }
    }

    /** Trims the results list to prevent unbounded memory growth. */
    private void trimResults() {
        int excess = results.size() - MAX_RESULTS;
        if (excess > 0) {
            // Batch remove from the front to avoid O(n^2) on CopyOnWriteArrayList
            results.subList(0, excess).clear();
        }
    }

    private void notifyResultAdded(AuthorizationResult result) {
        if (hasView() && mainPanel != null) {
            javax.swing.SwingUtilities.invokeLater(() -> mainPanel.addResult(result));
        }
    }

    // --- Public API ---

    public void startTesting() {
        active = true;
        LOGGER.info("Crimson Authorizer testing started");
    }

    public void stopTesting() {
        active = false;
        LOGGER.info("Crimson Authorizer testing stopped");
    }

    public boolean isActive() {
        return active;
    }

    public void clearResults() {
        results.clear();
        resultIdCounter.set(0);
        if (hasView() && mainPanel != null) {
            javax.swing.SwingUtilities.invokeLater(() -> mainPanel.clearTable());
        }
    }

    public List<AuthorizationResult> getResults() {
        return Collections.unmodifiableList(results);
    }

    public CrimsonAutorizeOptions getOptions() {
        return options;
    }

    public List<AuthCredentials> getUsers() {
        return options.getUsers();
    }

    public void addUser(AuthCredentials user) {
        options.addUser(user);
        refreshTableColumns();
    }

    public void removeUser(String userName) {
        options.removeUser(userName);
        refreshTableColumns();
    }

    /**
     * Renames a user across all stored results.
     *
     * @param oldName The current user name.
     * @param newName The new user name.
     */
    public void renameUser(String oldName, String newName) {
        for (AuthorizationResult result : results) {
            result.renameUser(oldName, newName);
        }
        // The table will refresh automatically when notified
    }

    public void refreshTableColumns() {
        if (hasView() && mainPanel != null) {
            javax.swing.SwingUtilities.invokeLater(() -> mainPanel.refreshTableColumns());
        }
    }

    public CrimsonAutorizePanel getMainPanel() {
        if (mainPanel == null) {
            mainPanel = new CrimsonAutorizePanel(this);
        }
        return mainPanel;
    }

    /**
     * Tests all URLs currently in the Site Tree that are within scope.
     * This enables one-click full application testing.
     *
     * @param inScopeOnly If true, only test in-scope URLs.
     * @return The number of URLs queued for testing.
     */
    public int testAllInScopeUrls(boolean inScopeOnly) {
        return testAllInScopeUrls(inScopeOnly, null);
    }

    /**
     * Tests all URLs currently in the Site Tree that are within scope.
     *
     * @param inScopeOnly If true, only test in-scope URLs.
     * @param completionCallback Called when the full test completes or is cancelled.
     * @return The number of URLs queued for testing.
     */
    public int testAllInScopeUrls(boolean inScopeOnly, Runnable completionCallback) {
        if (fullTestRunning) {
            LOGGER.warn("Full application test already running");
            return 0;
        }

        List<String> urls = inScopeOnly ? SiteTreeUtils.getInScopeUrls() : SiteTreeUtils.getAllUrls();

        if (urls.isEmpty()) {
            LOGGER.warn("No URLs found in Site Tree{}", inScopeOnly ? " (in scope)" : "");
            return 0;
        }

        fullTestRunning = true;
        fullTestCancelled = false;
        fullTestTotal.set(urls.size());
        fullTestCompleted.set(0);
        fullTestProgress.set(0);
        fullTestCompletionCallback = completionCallback;

        LOGGER.info("Starting full application test for {} URLs{}", urls.size(), inScopeOnly ? " (in scope)" : "");

        final java.util.concurrent.atomic.AtomicInteger submittedCount = new java.util.concurrent.atomic.AtomicInteger(0);

        for (String urlString : urls) {
            if (fullTestCancelled) {
                LOGGER.info("Full application test cancelled by user");
                break;
            }

            try {
                final String url = urlString;
                
                threadPool.submit(() -> {
                    try {
                        org.apache.commons.httpclient.URI uri = 
                            new org.apache.commons.httpclient.URI(url, true);
                        HttpMessage msg = new HttpMessage(uri);
                        msg.getRequestHeader().setMethod("GET");
                        msg.getRequestHeader().setURI(uri);

                        HttpSender sender = new HttpSender(HttpSender.MANUAL_REQUEST_INITIATOR);
                        sender.sendAndReceive(msg);

                        processMessage(msg);
                        
                    } catch (Exception e) {
                        LOGGER.error("Error testing URL: {}", url, e);
                    } finally {
                        fullTestCompleted.incrementAndGet();
                        fullTestProgress.set((int)((fullTestCompleted.get() * 100.0) / fullTestTotal.get()));
                        checkFullTestCompletion();
                    }
                });
                submittedCount.incrementAndGet();

            } catch (Exception e) {
                LOGGER.error("Failed to create message for URL: {}", urlString, e);
                fullTestCompleted.incrementAndGet();
                checkFullTestCompletion();
            }
        }

        return urls.size();
    }

    private synchronized void checkFullTestCompletion() {
        if (fullTestRunning && fullTestCompleted.get() >= fullTestTotal.get()) {
            fullTestRunning = false;
            if (fullTestCompletionCallback != null) {
                try {
                    fullTestCompletionCallback.run();
                } catch (Exception e) {
                    LOGGER.error("Error in full test completion callback", e);
                }
                fullTestCompletionCallback = null;
            }
            LOGGER.info("Full application test completed ({} URLs)", fullTestTotal.get());
        }
    }

    /**
     * Tests all URLs in the Site Tree (scope-aware).
     *
     * @return The number of URLs queued for testing.
     */
    public int testAllInScopeUrls() {
        return testAllInScopeUrls(true);
    }

    /**
     * Cancels the running full application test.
     */
    public void cancelFullTest() {
        fullTestCancelled = true;
        LOGGER.info("Full application test cancellation requested");
    }

    /**
     * Checks if a full application test is currently running.
     *
     * @return true if test is running, false otherwise.
     */
    public boolean isFullTestRunning() {
        return fullTestRunning;
    }

    /**
     * Gets the progress of the current full application test (0-100).
     *
     * @return Progress percentage.
     */
    public int getFullTestProgress() {
        return fullTestProgress.get();
    }

    /**
     * Gets the total number of URLs to test.
     *
     * @return Total URL count.
     */
    public int getFullTestTotal() {
        return fullTestTotal.get();
    }

    /**
     * Gets the number of URLs tested so far.
     *
     * @return Completed URL count.
     */
    public int getFullTestCompleted() {
        return fullTestCompleted.get();
    }

    /**
     * Checks if the full test was cancelled.
     *
     * @return true if cancelled, false otherwise.
     */
    public boolean isFullTestCancelled() {
        return fullTestCancelled;
    }

    /**
     * Resets full test tracking after completion.
     */
    public void resetFullTestTracking() {
        fullTestRunning = false;
        fullTestCancelled = false;
        fullTestProgress.set(0);
        fullTestTotal.set(0);
        fullTestCompleted.set(0);
    }

    /**
     * Checks if any contexts are configured in ZAP.
     *
     * @return true if contexts exist, false otherwise.
     */
    public boolean hasContexts() {
        return ScopeUtils.hasContexts();
    }

    /**
     * Gets a description of the current scope configuration.
     *
     * @return Scope description string.
     */
    public String getScopeDescription() {
        return ScopeUtils.getScopeDescription();
    }

    /**
     * Gets a summary of the Site Tree contents.
     *
     * @return Summary string.
     */
    public String getSiteTreeSummary() {
        return SiteTreeUtils.getSiteTreeSummary();
    }
}
