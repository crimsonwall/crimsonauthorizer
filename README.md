# Crimson Authorizer

ZAP add-on that automatically detects authorization bypasses by replaying HTTP requests with substituted credentials.

## Why


Crimson Authorizer is a plugin for ZAP that continuously tests authorization as you browse. Inspired by the Autorize extension for Burp Suite (https://github.com/portswigger/autorize) which is using a very elegant approach to automated authorization testing. Crimson Authorizer intercepts your authenticated requests, replays them with different user credentials (or unauthenticated), and compares the responses to detect authorization bypasses. This makes it easier to find access control vulnerabilities during testing.

## Typical Usage

Crimson Authorizer is designed to fit naturally into your penetration testing workflow. Here's how to use it:

### Step 1: Capture Unprivileged User Credentials

1. **Configure ZAP to proxy your browser** (if not already set up)
2. **Log in as an unprivileged user** (e.g., a regular user, low-privilege account, or another user role you want to test)
3. **Capture the authentication headers** from a login request or any authenticated request:
   - In ZAP, go to the **Request** tab
   - Find the authentication headers (typically `Cookie`, `Authorization`, or custom headers)
   - Copy the header names and values (in other words, the entire header line)

### Step 2: Configure Test Users

1. **Open the Users tab** in the Crimson Authorizer panel
2. **Click "Parse Headers"** then **click "Add User"** and enter a name (e.g., "user1", "employee", "tester")
3. **Paste the captured headers** into the "Paste Raw Headers" text area
4. **Click "Parse Headers"** to automatically extract header names and values
5. **Repeat** the process (click "Parse Headers", then "Ok") for each additional user role you want to test

You can also manually add headers by clicking the "Add Header" button in the parsed headers table.

### Step 3: Log In as Administrator

1. **Log in as an administrator** or high-privilege user (keep all other user sessions alive — do not log out)
2. **Configure ZAP to proxy** this browser session if using a separate window
3. **Verify** you can access privileged endpoints that unprivileged users should not access

### Step 4: Start Authorization Testing

1. **Go to the Results tab** in the Crimson Authorizer panel
2. **Click the "Start" button** — the button will change to "Stop" and testing is now active
3. **Browse the application** as the administrator — click through pages, access sensitive endpoints, view user data, perform actions
4. **Watch for bypasses** — as you browse, Crimson Authorizer automatically:
   - Captures each request you make as the administrator
   - Replays it with each configured user's credentials
   - Replays it without authentication (if "Test unauthenticated access" is enabled)
   - Compares all responses to your admin response
   - Flags any suspicious results in real-time

### Step 5: Review Findings

Results appear in the table as they are discovered:

- **Bypassed** (red) — The unprivileged user or unauthenticated request got the same response as the admin. This is a potential authorization vulnerability.
- **Enforced** (blue) — The server returned a different response (403, 401, different content, etc.). Authorization is working correctly.
- **Not sure** (yellow) — The plugin cannot determine from the responses alone. Manual inspection required.
- **Skipped** (grey) — The the specified headers were not found in the request and the request was skipped as a result.

Click any row to view the detailed request/response comparison in the tabs below:
- **Original tab** — Your admin request/response
- **Unauthenticated tab** — The request without authentication (if enabled)
- **User tabs** — The request with each user's credentials

### Step 6: Export and Report

When testing is complete or you've found potential vulnerabilities:
1. **Click "Export"** to save results as CSV or HTML
2. **Right-click any result** to send it to ZAP's Requester tab for manual investigation
3. **Copy URLs** from the context menu for reporting or further testing

## Features

### Authorization Detection

The detection logic compares three aspects of the original (authenticated) response to the test (modified credentials) response:

1. **Status Code Comparison** — Different status codes strongly indicate enforcement:
   - Original: `200 OK`, Test: `403 Forbidden` → **ENFORCED**
   - Original: `200 OK`, Test: `200 OK` → Continue to body comparison

2. **Body Content Comparison** — When status codes match, compare response bodies:
   - Identical bodies with success status (2xx) → **BYPASSED**
   - Identical bodies with error status (4xx/5xx) → **ENFORCED**
   - Different bodies → **UNDETERMINED**

3. **Special Handling for 304/204**:
   - `204 No Content`: Skipped (no body to compare)
   - `304 Not Modified`: Both get 304 → **BYPASSED** (unauth user gets cached access)

### Test Configuration

- **Multiple test users**: Configure unlimited users with credential headers
- **Unauthenticated testing**: Test without any authentication
- **Header substitution**: Automatically substitutes user-specific headers (Cookie, Authorization, etc.)
- **Match/Replace rules**: Transform requests before replaying (regex support)
- **Smart header injection**: Only tests requests where required headers exist in original request

### Message Viewers

- **Request/Response tabs**: Color-coded One Dark theme syntax highlighting
- **Diff highlighting**: Modified/added headers highlighted in yellow/green
- **Send to Requester**: Right-click to resend any message in ZAP's Requester tab
- **Copy URL**: Quick URL copying from context menu
- **Draggable user tabs**: Reorder user result tabs (Original and Unauthenticated are fixed)

### Results Table

- **Live results**: Auto-scrolls to new bypasses (click any row to disable)
- **Status summary**: Shows total, enforced, bypassed, and undetermined counts
- **Sortable columns**: Click headers to sort
- **Per-user columns**: Each user gets status and response length columns
- **Status indicators**: Color-coded by enforcement status

### Scope and Filtering

- **Interception filters**: Configure URL patterns, methods, headers, and body content to include/exclude
- **File extension exclusions**: Skip static files (js, css, images, etc.)
- **Requester testing**: Optionally include manually sent requests

### Configuration

- **Tools → Options → Crimson Authorizer**:
  - Enable/disable unauthenticated testing
  - Configure file extension exclusions
  - Set maximum message size and result count limits

- **Users Tab**:
  - Add/remove/duplicate/rename test users
  - Edit user headers directly in the table
  - Double-click or Edit button for detailed user editing
  - Paste raw headers and auto-parse into header fields
  - Enable/disable users without deleting them

### Actions

- **Start/Stop**: Toggle authorization testing
- **Clear Results**: Remove all stored results (with confirmation)
- **Export**: Export results to CSV or HTML

## Installation

Pre-built releases are available on the [releases page](https://github.com/crimsonwall/crimsonauthorizer/releases). Download the `.zap` file and install it in ZAP via **File > Load Add-on File...**.

After installation, enable the plugin to access the Crimson Authorizer functionality.

## Building from Source

### Prerequisites

- JDK 17 or later
- Gradle (included with the project)

### Clone and build

```bash
git clone https://github.com/crimsonwall/crimsonauthorizer.git
cd crimsonauthorize
./gradlew build
```

The built `.zap` file is written to `build/zapAddOn/bin/`.

### Install in ZAP

Once built, install the add-on via **Tools > Manage Add-ons > Load Add-on from File** and select the `.zap` file, or copy it directly to the ZAP `plugin` directory.

## Requirements

- ZAP 2.17.0 or later
- The commonlib add-on (installed automatically as a dependency)

## Tips

- **Disable auto-scroll**: Click any row other than the last one to stop auto-scroll and manually inspect previous results
- **Reorder user tabs**: Drag user tabs to arrange them in your preferred order (Original and Unauthenticated stay fixed)
- **Edit users inline**: Double-click any user in the Users tab to edit their configuration
- **Paste headers**: When adding users, paste raw request headers (e.g., from browser DevTools) and click Parse Headers
- **Scope your testing**: Enable "In Scope Only" in the Results tab to focus testing on relevant URLs
- **Check the status bar**: Shows live counts of enforced, bypassed, and undetermined results
- **Use intercept filters**: Configure filters to exclude noise like health checks or static endpoints
- **Full application test**: Use the API to test all URLs in the Site Tree for comprehensive coverage
- **Keep sessions alive**: Do not terminate sessions or log out after capturing headers — all user sessions must remain active throughout testing
- **Isolate browser sessions**: Configure your browser to forget everything on close, then open the browser, log in, capture credentials, close the browser — repeat for each user account you are going to test
- **Plugin interference**: The plugin can sometimes interfere with navigation. Should this happen, simply disable the plugin, navigate through the problematic area, then enable it again

## How Authorization Detection Works

For each intercepted HTTP request (while testing is enabled):

1. The original authenticated request/response is captured
2. For each enabled test user:
   - A clone of the request is created
   - Configured headers are stripped (Cookie, Authorization, etc.)
   - Match/Replace rules are applied (if configured)
   - User-specific headers are injected
   - The request is sent to the server
   - The response is compared to the original
3. For unauthenticated testing (if enabled):
   - Headers are stripped (no user headers injected)
   - Request is sent and response compared
4. Results are displayed in real time with status indicators

### Enforcement Status Values

| Status | Meaning | Example |
|--------|---------|---------|
| **Enforced** | Authorization properly enforced | Original: `200`, Test: `403` |
| **Bypassed** | Authorization bypass detected | Original: `200`, Test: `200` (same body) |
| **Undetermined** | Cannot determine from responses | Different body content, same status |
| **Disabled** | User is disabled in configuration | User checkbox unchecked |
| **Skipped** | Required headers not present in original | Cookie not in original request |

### What Gets Flagged as Bypassed

The plugin raises a ZAP alert when the worst status across all tests is **BYPASSED**. This happens when:

- The unauthenticated test returns the same successful response as the original
- Any low-privilege user test returns the same successful response as the original
- Both original and test return `304 Not Modified` (unauthorized user gets cached access)

## Performance Limits

- Maximum 10,000 results stored (oldest auto-removed when limit reached)
- Maximum message size: 2 MB (configurable, messages larger than this are skipped)
- Maximum pending messages in queue: 50 (prevents overwhelming the system)
- Thread pool: 4 worker threads (daemon threads, won't block ZAP shutdown)

## Limitations
- This software comes with no warranty. 
- Manual inspection of all requests and responses recommended.
- Only tests HTTP(S) requests proxied through ZAP (or manually sent via Requester if enabled)
- Requires the same headers to exist in the original request for testing (prevents credential leakage)
- Session tokens must be valid for the test to work
- 204 No Content responses are skipped (no body to compare)
- State-changing operations (POST/PUT/DELETE) may cause side effects during testing

## License

Copyright 2026 crimsonwall.com. Licensed under the Apache License, Version 2.0.

## Contributing

If you encounter issues, please feel free to fix them and submit a pull request. Contributions are welcome.


