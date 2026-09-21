# Screenshots for the guides

Drop console screenshots here and replace the matching placeholder in the guide. Every
placeholder is a blockquote beginning **📷 Screenshot** and naming the file it wants, so
`grep -rn '📷 Screenshot' docs/` lists everything still outstanding.

Conventions, so the set looks like one set:

- **Crop to the content area.** No browser chrome, no OS window frame, no bookmarks bar.
- **Use the demo data**, never a real deployment: `pki.example.org`, `admin`,
  `host.example.org`. A screenshot is the easiest way to publish an internal hostname by
  accident, and it is the hardest to notice afterwards.
- **Redact anything secret** even from a throwaway deployment — enrolment secrets, session
  cookies, EAB keys. Blur or overwrite; do not rely on the value being fake.
- PNG, 2x pixel density if you can, and roughly 1200px wide before scaling.
- Name the file after the placeholder: `console-login.png`, `inventory-request-key-in-browser.png`.

A placeholder becomes a normal image link once the file exists:

```markdown
![Inventory — the three request buttons](images/inventory-buttons.png)
```
