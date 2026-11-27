# Chrome Web Store listing

Copy and paste these into the Developer Dashboard. Check the character
counts the dashboard shows, since its limits can change.

---

## Name

Phishing Email Detector

## Summary (short description, max 132 characters)

Warns you about phishing in Gmail. Every email is checked on your own computer. Nothing is sent online.

## Category

Productivity (or Tools, if the dashboard offers a better fit)

## Language

English

---

## Description

Phishing Email Detector checks each email you open in Gmail and puts a clear banner above it: green for low risk, yellow for suspicious, red for likely phishing. It also tells you why.

It looks at the things scammers rely on:

- Sender tricks: lookalike domains like paypa1.com, fake display names, and "official" emails sent from free accounts
- Email authentication: SPF, DKIM, and DMARC results
- Links: text that shows one site but goes to another, raw IP addresses, the "@" trick, and fake subdomains
- Attachments: double extensions like invoice.pdf.exe, programs hidden in zip files, and password-protected archives
- Hidden HTML tricks: login forms built into the email and invisible text
- Wording: gift card requests, "keep this between us," fake urgency, threats, and requests for passwords

Each check reports what it found, and a scoring step combines them into one verdict. It says "likely phishing," not "confirmed," because no tool is perfect. You'll always see the reasons, so you can decide for yourself.

PRIVATE BY DESIGN
The detector runs inside your browser. Your emails are never uploaded, stored, or shared. There are no accounts, no tracking, and no ads. The extension only runs on Gmail.

OPEN SOURCE
All of the code is public on GitHub: https://github.com/jd24610/ai-phishing-email-detector

Built by Joseph Decossard as a cybersecurity project.

---

## Single purpose

Warn Gmail users about likely phishing emails by checking each email they open, on their own computer, and showing the result in a banner above the message.

## Permission justifications

**Host permission: https://mail.google.com/\***
Needed to find the email the user has opened, read its raw source (the same content as Gmail's "Show original"), and show the warning banner above it. The extension runs on no other sites.

**storage**
Saves two settings: whether automatic scanning is on, and whether the built-in detector or the optional local server is used. No email content is stored.

**offscreen**
The phishing detector is Python code compiled to WebAssembly (Pyodide), bundled with the extension. Manifest V3 service workers can't run it, so it runs in a Web Worker inside an offscreen document. This keeps the work off the Gmail page so Gmail stays fast.

**Optional host permission: http://127.0.0.1:8765/\***
Only requested if the user turns on "Use local server instead" under Advanced. It lets developers run the same detector as a program on their own computer. The address is the local machine, so data never leaves the computer.

## Are you using remote code?

No. All JavaScript, Python, and WebAssembly is included in the package. Nothing is downloaded or loaded from the internet at run time. The `wasm-unsafe-eval` content security policy is only there so Chrome can run the bundled WebAssembly.

## Data usage

The extension reads the content of emails the user opens, but it does not collect or transmit them: all processing happens locally in the browser, and nothing is sent to the developer or any third party.

Read the definitions on the dashboard's Privacy tab carefully. If you're unsure whether local-only processing of email counts as handling "Personal communications" there, it's safer to tick it and explain it's processed locally than to leave it out.

Certify all three:
- I do not sell or transfer user data to third parties, outside of the approved use cases
- I do not use or transfer user data for purposes that are unrelated to my item's single purpose
- I do not use or transfer user data to determine creditworthiness or for lending purposes

## Privacy policy URL

https://github.com/jd24610/ai-phishing-email-detector/blob/main/PRIVACY.md

## Website / support URL

https://github.com/jd24610/ai-phishing-email-detector
