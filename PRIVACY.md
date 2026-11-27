# Privacy Policy: Phishing Email Detector

Effective: November 27, 2026

This policy covers the Phishing Email Detector Chrome extension and the open-source project it comes from (https://github.com/jd24610/ai-phishing-email-detector).

## The short version

The extension checks your emails on your own computer. It doesn't send your emails, or anything about them, to me or to anyone else. It has no servers, no accounts, no analytics, and no ads.

## What the extension reads

When you open an email in Gmail, the extension reads that email so it can check it for signs of phishing. It reads:

- the email's raw source, the same text Gmail shows under "Show original" (headers, body, links, and attachment names)
- a few parts of the Gmail page it needs to find the open email and place its warning banner

It does this only on `mail.google.com`, and only for emails you open.

## Where your data goes

Nowhere. The detector runs inside your browser, using code that ships with the extension. Your email is checked in memory and the result is shown as a banner above the message. The email text is not saved to disk and is not sent over the internet.

There is one optional exception that you have to turn on yourself. Under **Advanced**, you can switch to "local server" mode. That sends the email to a program running on your own computer at `127.0.0.1` (it never leaves your machine). Chrome asks for your permission before this mode can be used.

## What the extension stores

The extension saves two settings in Chrome's local extension storage:

- whether automatic scanning is on or off
- whether you use the built-in detector or the optional local server

It doesn't store your emails, the results of scans, or any personal information. Scan results are kept in memory only while the Gmail tab is open, so the same email isn't checked twice.

## What the extension does not do

- It does not collect, sell, or share any user data.
- It does not use your data for advertising, credit decisions, or any purpose other than showing you the phishing check.
- It does not track your browsing. It only runs on Gmail.
- It does not download or run code from the internet. Everything it runs is included in the extension package.
- It does not click links or open attachments in your emails.

## Permissions

| Permission | Why |
|---|---|
| Access to `mail.google.com` | To read the email you open and show the warning banner |
| `storage` | To remember your two settings |
| `offscreen` | To run the built-in detector in a background page, so Gmail doesn't slow down |
| Optional access to `127.0.0.1:8765` | Only if you turn on local server mode |

## Children

The extension isn't directed at children and doesn't knowingly collect data from anyone.

## Changes

If this policy changes, the new version will be posted at this same address with a new effective date. Because the extension doesn't collect data, any change would most likely be about new features.

## Contact

Questions or concerns: open an issue at https://github.com/jd24610/ai-phishing-email-detector/issues
