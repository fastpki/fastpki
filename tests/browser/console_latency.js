// The console driven by a real browser over a slow link.
//
// Every request to /api/ is held for DELAY_MS before it goes out, the way a console reached
// over a phone hotspot on another continent answers (about a second per request, measured).
// At localhost speed none of these flows can fail; at this speed each one did, in a release:
//   - Client Configs' Edit stuck at "Loading…";
//   - a user's window not opening, or opening with another person's details;
//   - a page left while it loaded drawn over the page that replaced it.
// Run by tests/browser/run.sh against one FastPKI image. Prints [PASS]/[FAIL] lines and a
// summary, and exits non-zero on any failure.
'use strict';
const pw = require('playwright');
// BROWSER=webkit runs Safari's engine; chromium is the default.
const ENGINE = process.env.BROWSER || 'chromium';

const BASE  = process.env.BASE || 'http://127.0.0.1:8090';
const DELAY = Number(process.env.DELAY_MS || 1000);
const USER  = process.env.ADMIN_USER || 'admin';
const PASS  = process.env.ADMIN_PASS || 'Passw0rd!';

let pass = 0, fail = 0;
let onFail = () => {};   // set once the page exists: prints what the page and network looked like
function chk(name, ok, detail) {
  if (ok) { console.log('  [PASS] ' + name); pass++; }
  else    { console.log('  [FAIL] ' + name + (detail ? ' (' + detail + ')' : '')); fail++; return Promise.resolve().then(onFail).catch(() => {}); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function within(ms, fn) {
  const end = Date.now() + ms;
  for (;;) {
    try { if (await fn()) return true; } catch (e) { /* not there yet */ }
    if (Date.now() > end) return false;
    await sleep(200);
  }
}

(async () => {
  const browser = await pw[ENGINE].launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e) + (process.env.DEBUG ? ' @ ' + String(e.stack || '').replace(/\s+/g, ' ').slice(0, 400) : '')));
  // Every console request that failed in transit, or was answered with an error. A window
  // whose requests fail draws its fallbacks ("Not set", "None") as if they were facts, so a
  // failure here is a wrong screen even when every check below passes.
  // DEBUG=1: a timeline of every console request, for diagnosing a failure.
  const t0 = Date.now();
  if (process.env.DEBUG) {
    const t = () => ((Date.now() - t0) / 1000).toFixed(2) + 's';
    page.on('request', r => { if (r.url().includes('/api/')) console.log('      ' + t() + ' > ' + r.method() + ' ' + new URL(r.url()).pathname); });
    page.on('response', r => { if (r.url().includes('/api/')) console.log('      ' + t() + ' < ' + r.status() + ' ' + new URL(r.url()).pathname); });
    page.on('requestfinished', r => { if (r.url().includes('/api/')) console.log('      ' + t() + ' = done ' + new URL(r.url()).pathname); });
    page.on('console', m => console.log('      ' + t() + ' page: ' + m.text()));
  }
  const netErrors = [];
  let recording = false;   // from sign-in on: the sign-in page's own 401 and reload are expected
  page.on('requestfailed', r => { if (recording && r.url().includes('/api/')) netErrors.push(r.method() + ' ' + new URL(r.url()).pathname + ': ' + ((r.failure() || {}).errorText || 'failed')); });
  page.on('response', r => { if (recording && r.url().includes('/api/') && r.status() >= 400 && !r.url().includes('/api/me')) netErrors.push(r.request().method() + ' ' + new URL(r.url()).pathname + ': HTTP ' + r.status()); });
  // The delay VARIES per request, 0.3 to 1.7 times DELAY_MS, as it does on a real link: with a
  // fixed delay every answer comes back in the order it was asked for, and the races this test
  // exists for need a later request to overtake an earlier one.
  // offline = true makes every console request fail in transit, as when a link drops.
  let offline = false;
  await page.route('**/api/**', async route => {
    await sleep(Math.round(DELAY * (0.3 + 1.4 * Math.random())));
    if (offline) return route.abort('internetdisconnected');
    await route.continue();
  });

  console.log('=== sign in (every /api/ request delayed ' + DELAY + ' ms) ===');
  await page.goto(BASE + '/');
  await page.waitForSelector('#pwsignin input[name=username]', { timeout: 30000 });
  await page.fill('#pwsignin input[name=username]', USER);
  await page.fill('#pwsignin input[name=password]', PASS);
  await page.click('#pwsignin button');
  chk('signed in', await within(30000, async () =>
    (await page.textContent('#who') || '').includes(USER)));
  recording = true;
  onFail = async () => {
    const open = await page.evaluate(() => [...document.querySelectorAll('.modal')]
      .filter(m => getComputedStyle(m).display !== 'none')
      .map(m => m.id + ': ' + (m.innerText || '').replace(/\s+/g, ' ').slice(0, 160)));
    console.log('      open windows: ' + (open.join(' || ') || 'none'));
    console.log('      failed requests so far: ' + (netErrors.join(' | ') || 'none'));
  };

  const modalOpen = async id => page.evaluate(i => {
    const m = document.getElementById(i);
    return !!m && getComputedStyle(m).display !== 'none';
  }, id);
  const tab = async t => page.click('nav button[data-tab="' + t + '"]');

  console.log('=== Client Configs: Edit opens and loads ===');
  await tab('clientcfg');
  await page.waitForSelector('button.ccfgedit', { timeout: 30000 });
  await page.click('button.ccfgedit');
  chk('the edit window shows the config, not "Loading…"', await within(20000, async () =>
    await page.isVisible('#cfgfilemodal #cctext')));
  if (await modalOpen('cfgfilemodal')) await page.click('#cfgfilemodal #ccx');

  console.log('=== Users: a user\'s window opens with that user\'s details ===');
  await tab('users');
  const gear = name => page.locator('tr', { hasText: name }).locator('button.gearbtn[title="Edit"]').first();
  await gear('alice').waitFor({ timeout: 30000 });
  await gear('alice').click();
  chk('alice\'s window opens', await within(25000, async () => await modalOpen('usermodal')));
  chk('  titled for alice', ((await page.textContent('#usermodal h3')) || '').includes('alice'));
  chk('  with its PIN section filled', await within(5000, async () =>
    (await page.locator('#usermodal #umsignin .umsec').count()) > 0));
  if (await modalOpen('usermodal')) await page.click('#usermodal #umclose');
  await within(10000, async () => !(await modalOpen('usermodal')));

  console.log('=== Users: opening one user, then another before it appears ===');
  await gear('alice').click();
  await sleep(300);
  await gear('bob').click();
  chk('a window opens', await within(25000, async () => await modalOpen('usermodal')));
  await sleep(DELAY * 4);   // let every late answer for alice arrive
  const title = (await page.textContent('#usermodal h3')) || '';
  chk('  and it is bob\'s', title.includes('bob') && !title.includes('alice'), title);
  if (await modalOpen('usermodal')) await page.click('#usermodal #umclose');
  await within(10000, async () => !(await modalOpen('usermodal')));

  console.log('=== Users: save one user, then open another at once ===');
  await gear('alice').click();
  await within(25000, async () => await modalOpen('usermodal'));
  await page.click('#usermodal #umsave');
  await within(15000, async () => !(await modalOpen('usermodal')));
  await gear('bob').click();
  chk('bob\'s window opens after a save reloaded the page', await within(25000, async () =>
    await modalOpen('usermodal') && ((await page.textContent('#usermodal h3')) || '').includes('bob')));
  if (await modalOpen('usermodal')) await page.click('#usermodal #umclose');
  await within(10000, async () => !(await modalOpen('usermodal')));

  console.log('=== Users: a window opened after the page sat idle for 7 s ===');
  // A connection idle past the server's keep-alive timeout is closed by the server; a browser
  // that sends on it at that moment loses the request in transit.
  // Idle times around the server's 5 s keep-alive timeout, where its close is still on the wire
  // (run.sh adds RTT_MS of real network delay on the server's side) when the browser sends.
  for (const idle of (process.env.IDLE_MS || '4800,5000,5100,5200,5400,7000').split(',').map(Number)) {
    const before = netErrors.length;
    await sleep(idle);
    await gear('alice').click();
    const opened = await within(25000, async () => await modalOpen('usermodal'));
    const bad = netErrors.slice(before);
    chk('after ' + idle + ' ms idle, alice\'s window opens with every request answered',
        opened && bad.length === 0, (opened ? '' : 'window did not open; ') + bad.join(' | '));
    if (await modalOpen('usermodal')) await page.click('#usermodal #umclose');
    await within(10000, async () => !(await modalOpen('usermodal')));
  }

  console.log('=== Users: the link drops as a user\'s window opens ===');
  // A request that never arrives must read as "could not be loaded", never as the user having
  // no PIN, no passkeys and no roles, which is what a dropped hotspot link once showed.
  recording = false;
  offline = true;
  await gear('alice').click();
  const shown = await within(25000, async () => await modalOpen('usermodal'));
  chk('the window still opens', shown);
  if (shown) {
    const txt = (await page.innerText('#usermodal')) || '';
    chk('  each section says it could not be loaded',
        (await page.locator('#usermodal .sectionfailed').count()) >= 3,
        (await page.locator('#usermodal .sectionfailed').count()) + ' sections');
    chk('  and none claims the user has nothing',
        !/Not set\.|None\. A passkey|holds no role that permits|No role assignments/.test(txt),
        txt.replace(/\s+/g, ' ').slice(0, 200));
  }
  chk('  and the page says the console could not be reached', await within(5000, async () =>
    ((await page.innerText('body')) || '').includes('could not be reached')));
  offline = false;
  if (await modalOpen('usermodal')) await page.click('#usermodal #umclose');
  await within(10000, async () => !(await modalOpen('usermodal')));
  recording = true;

  console.log('=== switching page while one is still loading ===');
  await tab('certs');
  await sleep(200);
  await tab('users');
  await sleep(200);
  await tab('cas');
  await sleep(DELAY * 5);   // every late answer has arrived by now
  chk('the page is the one chosen last', ((await page.textContent('#pagetitle')) || '').includes('CAs'));
  chk('  and the Users page did not draw over it', await page.evaluate(() => {
    const p = document.getElementById('userpanel');
    return !p || p.hidden || getComputedStyle(p).display === 'none';
  }));

  chk('no script errors on the page', errors.length === 0, errors.join(' | '));
  chk('no console request failed or was refused', netErrors.length === 0, netErrors.join(' | '));
  await browser.close();
  console.log('=== BROWSER CONSOLE LATENCY: PASS=' + pass + ' FAIL=' + fail + ' ===');
  process.exit(fail ? 1 : 0);
})().catch(e => { console.log('  [FAIL] the test itself failed: ' + e); console.log('RESULT: FAIL'); process.exit(2); });
