# Screenshots for the guides

The console screenshots the guides link to. A guide that still needs one has a placeholder: a
blockquote beginning **📷 Screenshot** and naming the file it wants, so
`grep -rn '📷 Screenshot' docs/` lists everything still outstanding.

Conventions, so the set looks like one set:

- **Crop to the content area.** No browser chrome, no OS window frame, no bookmarks bar. The
  exception is a screenshot whose point is the browser itself, such as the sign-in page
  showing the console's name with no certificate warning.
- **Use a deployment you do not mind publishing.** Everything in a screenshot is published:
  host names, addresses and user names. Prefer demo data (`pki.example.org`, `admin`,
  `host.example.org`).
- **Never show a secret**, even from a throwaway deployment: enrolment secrets, session
  cookies, EAB keys, passwords a browser filled in. Take the screenshot with the value hidden;
  a value scribbled over can still be read at its edges.
- **1440 pixels wide, PNG, reduced to a 256-colour palette.** A full-resolution screenshot is
  about 400 KB, and every image also ships in the release's source archive, which the website
  mirrors with a 25 MiB limit per file. Reduced, one is about 60 KB and looks the same:

  ```bash
  sips --resampleWidth 1440 shot.png --out shot.png                       # macOS
  docker run --rm -v "$PWD":/w alpine sh -c \
      'apk add -q pngquant && pngquant --quality=80-95 --speed 1 --strip --force --ext .png /w/*.png'
  ```

- Name the file after the placeholder: `console-login.png`, `inventory-request-key-in-browser.png`.

A placeholder becomes a normal image link once the file exists:

```markdown
![Inventory — the three request buttons](images/inventory-buttons.png)
```
