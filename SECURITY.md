# Security Policy

This site is the browser-based companion to the
[Credential Scrubber desktop app](https://github.com/Mugilan718/credential-scrubber)
- same detection engine, ported to run client-side. Security reporting
for both lives in one place, in the main app repository, rather than
being split across two policies that could drift out of sync.

**To report a vulnerability in either the site or the underlying
detection engine, see
[the main repository's SECURITY.md](https://github.com/Mugilan718/credential-scrubber/blob/main/SECURITY.md).**

That covers how to report privately (GitHub's private vulnerability
reporting, or email), what's in scope, and what to expect.

## What's specific to this site

Everything runs in your browser - nothing scanned here is ever uploaded
or sent anywhere (see the banner on every page: "Runs in your browser —
nothing uploaded"). If you find a way that claim doesn't hold - any
code path that sends scanned file content, a filename, or any other
derived data off the page - that's a vulnerability report on its own,
even if the underlying detection logic is otherwise working correctly.
