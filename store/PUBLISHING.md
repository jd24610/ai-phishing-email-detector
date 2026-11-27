# Publishing to the Chrome Web Store

Everything for the store is already in this folder. The only things left
are the ones that need you: paying the fee and clicking submit.

## What's ready

| What | Where |
|---|---|
| Upload zip | `python3 dev/package_extension.py` builds `dist/phishing-email-detector-<version>.zip` |
| Listing text, permission reasons, data answers | `store/listing.md` |
| Privacy policy | `PRIVACY.md` (link: https://github.com/jd24610/ai-phishing-email-detector/blob/main/PRIVACY.md) |
| Screenshots, 1280x800 | `store/images/screenshot-1` to `-4` |
| Small promo tile, 440x280 | `store/images/promo-small-440x280.png` |
| Marquee promo tile, 1400x560 (optional) | `store/images/promo-marquee-1400x560.png` |
| Store icon, 128x128 | `store/images/icon-128.png` |

To redo the images after changing the extension: `python3 store/make_images.py`.

## Steps

### 1. Register as a developer (one time)
1. Go to the Chrome Web Store Developer Dashboard and sign in.
   Google suggests using a separate Google account just for publishing.
2. Pay the one-time registration fee and accept the agreement.
3. Fill in your publisher name and verify your contact email.

### 2. Build the upload zip
```
python3 dev/build_extension.py      # make sure the extension has the latest detector
python3 -m unittest discover tests  # everything should pass
python3 dev/package_extension.py    # builds dist/phishing-email-detector-<version>.zip
```
The script removes the `key` line from the manifest, because the store
rejects uploads that contain it.

### 3. Create the item
1. Dashboard: **Add new item**, upload the zip.
2. **Store listing** tab: paste from `store/listing.md`, upload the icon,
   screenshots, and promo tile.
3. **Privacy** tab: paste the single purpose, each permission reason, the
   "no remote code" answer, the data usage answers, and the privacy policy link.
4. **Distribution**: Public (or Unlisted if you only want people with the link).
5. **Submit for review.**

Extensions that read Gmail get a closer review, so expect it to take
longer than usual. If the reviewer asks a question, the answers are in
`store/listing.md`, and the code is public on GitHub.

### 4. After it's approved: match the IDs

The store gives the extension its own ID. Two small updates keep
everything in sync:

1. Dashboard, **Package** tab: **View public key**. Copy the text between
   the BEGIN and END lines and remove the line breaks.
2. Paste it as the `"key"` value in `extension/manifest.json`. Now your
   unpacked copy has the same ID as the store version.
3. Load the extension unpacked, copy its ID from `chrome://extensions`, and
   put it in `OUR_EXTENSION_ID` in `server.py` (only matters for local
   server mode). Update the ID mentioned in the README too.
4. Run the tests and commit.

### 5. Shipping updates
1. Bump `"version"` in `extension/manifest.json` (every upload needs a higher number).
2. Run step 2 again and upload the new zip under **Package**.
