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
    if (!isMessageId(hexId)) throw new Error("Not a Gmail message ID.");
    return `${accountPath(pathname)}?view=om&permmsgid=${encodeURIComponent(permId(hexId))}`;
  }

  // The Show original page puts the raw email inside <pre id="raw_message_text">.
  // DOMParser builds a detached document: nothing in it runs or loads.
  function extractRaw(html) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const pre = doc.querySelector("#raw_message_text, pre.raw_message_text");
    return pre ? pre.textContent : null;
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

  return { accountPath, isMessageId, permId, originalUrl, extractRaw, openMessages, bannerAnchor };
})();
