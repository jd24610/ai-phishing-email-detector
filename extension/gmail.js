// Helpers for working with Gmail's page.
//
// Gmail has no official way for extensions to read an email, so we use what
// Gmail itself uses for "Show original": each open message has a hidden ID,
// and Gmail serves the raw email at a special URL built from that ID.
//
// HEADS UP: these selectors and URLs belong to Gmail, not to us. If Google
// changes its page, this file is the one to update. Everything Gmail-specific
// lives here on purpose so the rest of the extension doesn't need to change.

const PhishGmail = (() => {
  // An opened (expanded) message has this attribute, holding a hex ID.
  const MESSAGE_SELECTOR = "[data-legacy-message-id]";
  // The message body inside it. Collapsed messages in a thread don't have one.
  const BODY_SELECTOR = ".a3s";

  // "/mail/u/1/" when you're signed into several accounts. Default is account 0.
  function accountPath(pathname) {
    const match = /^\/mail\/u\/(\d{1,2})\//.exec(pathname);
    return match ? `/mail/u/${match[1]}/` : "/mail/u/0/";
  }

  // Only accept IDs that look exactly like Gmail's. Anything else is ignored,
  // so a strange value can't be slipped into the URL we build.
  function isMessageId(id) {
    return typeof id === "string" && /^[0-9a-f]{8,20}$/i.test(id);
  }

  // Gmail's hex ID "18c2f..." becomes "msg-f:1784..." in the Show original URL.
  function permId(hexId) {
    return "msg-f:" + BigInt("0x" + hexId).toString(10);
  }

  function originalUrl(pathname, hexId) {
    return originalUrls(pathname, hexId)[0].url;
  }

  // Gmail's "account key" (called ik). Real Gmail puts it in its own
  // Show original links. We look for it in the page's script text.
  // It's an account identifier, not a password, and it never leaves Gmail.
  function findIk(root = document) {
    const patterns = [
      /var GLOBALS=\[(?:[^,\]]*,){9}"([0-9a-f]{6,16})"/,   // older Gmail
      /["']ik["']\s*[:=]\s*["']([0-9a-f]{6,16})["']/,       // ik: "abc123"
      /[?&]ik=([0-9a-f]{6,16})[&"']/,                      // inside a URL
    ];
    for (const script of root.querySelectorAll("script:not([src])")) {
      const text = script.textContent;
      if (!text || text.length > 2_000_000) continue;
      for (const re of patterns) {
        const m = re.exec(text);
        if (m) return m[1];
      }
    }
    return null;
  }

  // Gmail has used a few address formats for Show original over the years.
  // We try them in order and keep the first one that returns a real email.
  function originalUrls(pathname, hexId, ik = null) {
    if (!isMessageId(hexId)) throw new Error("Not a Gmail message ID.");
    if (ik && !/^[0-9a-f]{6,16}$/.test(ik)) ik = null;
    const base = accountPath(pathname);
    const pid = encodeURIComponent(permId(hexId));
    const urls = [];
    if (ik) {
      urls.push({ name: "permmsgid+ik", url: `${base}?ik=${ik}&view=om&permmsgid=${pid}` });
      urls.push({ name: "th+ik", url: `${base}?ui=2&ik=${ik}&view=om&th=${hexId}` });
      urls.push({ name: "download+ik", url: `${base}?ui=2&ik=${ik}&view=att&th=${hexId}&attid=0&disp=comp&safe=1&zw` });
    }
    urls.push({ name: "permmsgid", url: `${base}?view=om&permmsgid=${pid}` });
    urls.push({ name: "th", url: `${base}?view=om&th=${hexId}` });
    return urls;
  }

  // Does this text start like a raw email (header lines like "From: ...")?
  function looksLikeEmail(text) {
    if (!text) return false;
    const head = text.slice(0, 5000);
    return /^(Delivered-To|Received|Return-Path|ARC-[\w-]+|DKIM-Signature|MIME-Version|From|Date|Subject|X-[\w-]+):/im.test(head)
      && /^From:/im.test(head);
  }

  // Pull the raw email out of a Show original response.
  // - Plain text download: the whole response is the email.
  // - HTML page: the email sits inside a <pre>. We try Gmail's usual
  //   id first, then any <pre> that looks like an email.
  // DOMParser builds a detached document: nothing in it runs or loads.
  function extractRaw(body, contentType = "text/html") {
    if (!contentType.includes("html")) {
      return looksLikeEmail(body) ? body : null;
    }
    const doc = new DOMParser().parseFromString(body, "text/html");
    const known = doc.querySelector("#raw_message_text, pre.raw_message_text");
    if (known && looksLikeEmail(known.textContent)) return known.textContent;
    for (const pre of doc.querySelectorAll("pre")) {
      if (looksLikeEmail(pre.textContent)) return pre.textContent;
    }
    return null;
  }

  // Every message that's open on screen right now, with its ID.
  function openMessages(root = document) {
    return [...root.querySelectorAll(MESSAGE_SELECTOR)]
      .map((el) => ({ el, id: el.getAttribute("data-legacy-message-id") }))
      .filter(({ el, id }) => isMessageId(id) && el.querySelector(BODY_SELECTOR));
  }

  // Where to put our banner: just above the message body.
  function bannerAnchor(messageEl) {
    const body = messageEl.querySelector(BODY_SELECTOR);
    return body ? body.parentElement : messageEl;
  }

  return { accountPath, isMessageId, permId, originalUrl, originalUrls, findIk,
           looksLikeEmail, extractRaw, openMessages, bannerAnchor };
})();
