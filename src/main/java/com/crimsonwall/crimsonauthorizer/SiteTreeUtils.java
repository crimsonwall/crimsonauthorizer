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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.swing.tree.DefaultMutableTreeNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;

/**
 * Utility class for extracting URLs from ZAP's Site Tree at runtime.
 * Uses reflection to avoid compile-time dependencies.
 */
public class SiteTreeUtils {

    private static final Logger LOGGER = LogManager.getLogger(SiteTreeUtils.class);

    private SiteTreeUtils() {
        // Utility class
    }

    /**
     * Gets all unique URLs from the Site Tree using reflection.
     *
     * @return List of unique URLs, or empty list if Site Tree not accessible.
     */
    public static List<String> getAllUrls() {
        try {
            Model model = Model.getSingleton();
            if (model == null) return Collections.emptyList();
            Session session = model.getSession();
            if (session == null) return Collections.emptyList();

            Object siteMap = ReflectionUtils.invokeMethod(session, "getSiteTree");
            if (siteMap == null) return Collections.emptyList();

            Object rootNode = ReflectionUtils.invokeMethod(siteMap, "getRoot");
            if (rootNode == null) return Collections.emptyList();

            Set<String> urls = new HashSet<>();
            traverseNode(rootNode, urls);

            List<String> urlList = new ArrayList<>(urls);
            Collections.sort(urlList);

            LOGGER.info("Extracted {} unique URLs from Site Tree", urlList.size());
            return urlList;

        } catch (Exception e) {
            LOGGER.warn("Failed to access Site Tree (may not be available at compile time): {}", e.getMessage());
            LOGGER.debug("Full error:", e);
            return Collections.emptyList();
        }
    }

    /**
     * Gets URLs within scope.
     *
     * @return List of in-scope URLs.
     */
    public static List<String> getInScopeUrls() {
        List<String> allUrls = getAllUrls();
        List<String> inScope = new ArrayList<>();

        for (String url : allUrls) {
            if (ScopeUtils.isInScope(url)) {
                inScope.add(url);
            }
        }

        LOGGER.info("Found {} in-scope URLs", inScope.size());
        return inScope;
    }

    /**
     * Gets URL count.
     */
    public static int getUrlCount() {
        return getAllUrls().size();
    }

    /**
     * Checks if Site Tree has URLs.
     */
    public static boolean hasUrls() {
        return getUrlCount() > 0;
    }

    /**
     * Gets summary of Site Tree.
     */
    public static String getSiteTreeSummary() {
        List<String> allUrls = getAllUrls();
        int total = allUrls.size();
        if (total == 0) {
            return "No URLs in Site Tree (browse your application first)";
        }

        int inScope = 0;
        for (String url : allUrls) {
            if (ScopeUtils.isInScope(url)) {
                inScope++;
            }
        }

        if (inScope == total) {
            return total + " URLs (all in scope)";
        }

        return total + " URLs (" + inScope + " in scope)";
    }

    /**
     * Traverses site tree nodes via {@code DefaultMutableTreeNode} API.
     */
    private static void traverseNode(Object nodeObj, Set<String> urls) {
        if (!(nodeObj instanceof DefaultMutableTreeNode)) {
            return;
        }
        DefaultMutableTreeNode node = (DefaultMutableTreeNode) nodeObj;
        try {
            Object userObject = node.getUserObject();
            if (userObject instanceof HttpMessage) {
                HttpMessage msg = (HttpMessage) userObject;
                String url = msg.getRequestHeader().getURI().toString();
                urls.add(url);
            }

            Enumeration<?> children = node.children();
            while (children.hasMoreElements()) {
                traverseNode(children.nextElement(), urls);
            }
        } catch (Exception e) {
            LOGGER.debug("Error traversing node", e);
        }
    }
}
