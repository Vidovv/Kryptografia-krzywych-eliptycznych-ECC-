'use strict';
const $ = id => document.getElementById(id);
const MAX_SIZE = 15 * 1024 * 1024;

function switchTab(name) {
  document.querySelectorAll('[data-tab]').forEach(button => {
    const active = button.dataset.tab === name;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  });
  for (const key of ['about', 'keys', 'encrypt', 'decrypt']) $('panel-' + key).classList.toggle('hidden', key !== name);
}
document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => switchTab(button.dataset.tab)));

function switchAboutTab(name) {
  for (const item of ['overview', 'theory']) {
    const active = item === name;
    $('about-view-' + item).classList.toggle('hidden', !active);
    const button = $('about-tab-' + item);
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.tabIndex = active ? 0 : -1;
  }
}
document.querySelectorAll('[data-about-tab]').forEach(button => {
  button.addEventListener('click', () => switchAboutTab(button.dataset.aboutTab));
  button.addEventListener('keydown', event => {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return;
    event.preventDefault();
    const next = button.dataset.aboutTab === 'overview' ? 'theory' : 'overview';
    switchAboutTab(next);
    $('about-tab-' + next).focus();
  });
});


function setStatus(id, message, type = '') {
  const element = $(id); element.textContent = message; element.className = 'feedback ' + type;
}
function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return btoa(binary);
}
function fromBase64(value) {
  const binary = atob(value), bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
async function post(path, payload) {
  let response;
  try { response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)}); }
  catch { throw new Error('Brak połączenia z serwerem. Uruchom FastAPI.'); }
  const data = await response.json().catch(() => { throw new Error('Serwer zwrócił nieprawidłową odpowiedź.'); });
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : `Błąd HTTP ${response.status}`);
  return data;
}
function download(data, filename, mime = 'application/octet-stream') {
  const url = URL.createObjectURL(new Blob([data], {type: mime}));
  const link = document.createElement('a'); link.href = url; link.download = filename; document.body.appendChild(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function safeFilename(name) {
  return String(name || 'odszyfrowany_plik').split(/[\\/]/).pop().replace(/[\x00-\x1f]/g, '_') || 'odszyfrowany_plik';
}
async function bindKeyFile(fileInput, textArea) {
  $(fileInput).addEventListener('change', async () => {
    const file = $(fileInput).files[0];
    if (!file) return;
    if (file.size > 64 * 1024) { setStatus(fileInput.startsWith('enc') ? 'encryptStatus' : 'decryptStatus', 'Plik PEM jest zbyt duży.', 'error'); return; }
    $(textArea).value = await file.text();
  });
}
bindKeyFile('encKeyFile', 'encKey');
bindKeyFile('decKeyFile', 'decKey');

$('encryptForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('encryptBtn'); button.disabled = true;
  setStatus('encryptStatus', 'Szyfrowanie w toku...');
  try {
    const file = $('encFile').files[0];
    if (!file) throw new Error('Wybierz plik.');
    if (file.size > MAX_SIZE) throw new Error('Maksymalny rozmiar pliku to 15 MB.');
    const key = $('encKey').value.trim();
    if (!key) throw new Error('Podaj klucz publiczny.');
    const encrypted = await post('/api/files/encrypt', {public_key_pem: key, filename: file.name, file_base64: toBase64(new Uint8Array(await file.arrayBuffer()))});
    download(JSON.stringify(encrypted, null, 2), safeFilename(file.name) + '.ecc', 'application/json');
    setStatus('encryptStatus', 'Plik został zaszyfrowany i pobrany.', 'success');
  } catch (error) { setStatus('encryptStatus', error.message, 'error'); }
  finally { button.disabled = false; }
});
$('decryptForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('decryptBtn'); button.disabled = true;
  setStatus('decryptStatus', 'Odszyfrowywanie w toku...');
  try {
    const file = $('decFile').files[0];
    if (!file) throw new Error('Wybierz plik .ecc.');
    if (file.size > MAX_SIZE * 1.5) throw new Error('Zaszyfrowany plik jest zbyt duży.');
    let encrypted;
    try { encrypted = JSON.parse(await file.text()); }
    catch { throw new Error('Nieprawidłowy plik .ecc (wymagany format JSON).'); }
    const privateKey = $('decKey').value.trim(), password = $('decPassword').value;
    if (!privateKey || !password) throw new Error('Podaj klucz prywatny oraz jego hasło.');
    const result = await post('/api/files/decrypt', {private_key_pem: privateKey, password, encrypted});
    download(fromBase64(result.file_base64), safeFilename(result.filename));
    setStatus('decryptStatus', 'Plik został odszyfrowany i pobrany.', 'success');
  } catch (error) { setStatus('decryptStatus', error.message, 'error'); }
  finally { button.disabled = false; }
});

// Generator używa istniejącego endpointu API. Klucze pozostają tylko w bieżącej karcie.
$('keyForm').addEventListener('submit', async event => {
  event.preventDefault();
  const button = $('generateBtn');
  const password = $('keyPassword').value;
  const confirmation = $('keyPasswordConfirm').value;
  if (!password) { setStatus('keyStatus', 'Podaj hasło.', 'error'); return; }
  if (password !== confirmation) { setStatus('keyStatus', 'Hasła muszą być takie same.', 'error'); return; }
  button.disabled = true;
  $('keyResults').classList.add('hidden');
  $('generatedPublic').value = '';
  $('generatedPrivate').value = '';
  setStatus('keyStatus', 'Generowanie kluczy...');
  try {
    const result = await post('/keys/generate', {password});
    if (typeof result.public_key_pem !== 'string' || typeof result.private_key_pem !== 'string') throw new Error('Serwer nie zwrócił poprawnych kluczy.');
    $('generatedPublic').value = result.public_key_pem;
    $('generatedPrivate').value = result.private_key_pem;
    $('keyResults').classList.remove('hidden');
    setStatus('keyStatus', 'Para kluczy została wygenerowana.', 'success');
  } catch (error) { setStatus('keyStatus', error.message, 'error'); }
  finally { button.disabled = false; }
});

function downloadPem(id, name) {
  const value = $(id).value;
  if (value) download(value, name, 'application/x-pem-file');
}
async function copyPem(id) {
  const value = $(id).value;
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    setStatus('keyStatus', 'Klucz skopiowany do schowka.', 'success');
  } catch {
    $(id).focus(); $(id).select();
    setStatus('keyStatus', 'Nie można skopiować automatycznie. Zaznaczony tekst skopiuj Ctrl+C.', 'error');
  }
}
$('copyPublic').addEventListener('click', () => copyPem('generatedPublic'));
$('copyPrivate').addEventListener('click', () => copyPem('generatedPrivate'));
$('downloadPublic').addEventListener('click', () => downloadPem('generatedPublic', 'public_key.pem'));
$('downloadPrivate').addEventListener('click', () => downloadPem('generatedPrivate', 'private_key.pem'));
$('usePublic').addEventListener('click', () => {
  const value = $('generatedPublic').value;
  if (!value) { setStatus('encryptStatus', 'Najpierw wygeneruj klucze w zakładce Generator kluczy.', 'error'); return; }
  $('encKey').value = value;
  setStatus('encryptStatus', 'Wstawiono wygenerowany klucz publiczny.', 'success');
});
$('usePrivate').addEventListener('click', () => {
  const value = $('generatedPrivate').value;
  if (!value) { setStatus('decryptStatus', 'Najpierw wygeneruj klucze w zakładce Generator kluczy.', 'error'); return; }
  $('decKey').value = value;
  $('decPassword').value = $('keyPassword').value;
  setStatus('decryptStatus', 'Wstawiono klucz prywatny i hasło z generatora.', 'success');
});

// Motyw jest zapamiętywany lokalnie. Nie zmienia żadnej operacji API.
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $('themeToggle').textContent = theme === 'dark' ? '☀ Motyw jasny' : '☾ Motyw ciemny';
  $('themeToggle').setAttribute('aria-pressed', String(theme === 'dark'));
}
let savedTheme = 'light';
try { savedTheme = localStorage.getItem('ecc-theme') === 'dark' ? 'dark' : 'light'; } catch (_) {}
applyTheme(savedTheme);
$('themeToggle').addEventListener('click', () => {
  const theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(theme);
  try { localStorage.setItem('ecc-theme', theme); } catch (_) {}
});

// Demonstracja używa rzeczywistych parametrów secp256k1 i arytmetyki BigInt.
// Wykres natomiast wizualizuje równanie w R, a nie rozmieszczenie punktów w Fp.
const EC_P = (1n << 256n) - (1n << 32n) - 977n;
const EC_G = [
  55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  32670510020758816978083085130507043184471273380659243275938904335757337482424n
];
const ecMod = x => (x % EC_P + EC_P) % EC_P;
function ecPow(base, exp) {
  let value = 1n;
  for (base = ecMod(base); exp > 0n; exp >>= 1n) {
    if (exp & 1n) value = ecMod(value * base);
    base = ecMod(base * base);
  }
  return value;
}
function ecAdd(P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  if (P[0] === Q[0] && ecMod(P[1] + Q[1]) === 0n) return null;
  const doubling = P[0] === Q[0] && P[1] === Q[1];
  const numerator = doubling ? 3n * P[0] * P[0] : Q[1] - P[1];
  const denominator = doubling ? 2n * P[1] : Q[0] - P[0];
  const slope = ecMod(numerator * ecPow(denominator, EC_P - 2n));
  const x = ecMod(slope * slope - P[0] - Q[0]);
  return [x, ecMod(slope * (P[0] - x) - P[1])];
}
function ecMultiply(scalar) {
  let result = null, current = EC_G;
  for (let n = BigInt(scalar); n > 0n; n >>= 1n) {
    if (n & 1n) result = ecAdd(result, current);
    current = ecAdd(current, current);
  }
  return result;
}
function renderDemo(d) {
  d = Math.max(1, Math.min(16, Math.round(Number(d))));
  $('curveScalar').value = String(d);
  $('curveDLabel').textContent = `d = ${d}`;
  $('demoPrivate').textContent = `d = ${d}`;
  const [x, y] = ecMultiply(d);
  $('demoOperation').textContent = `${d} · G = Q  |  ${d.toString(2)}₂ → podwajanie i dodawanie punktów`;
  $('demoCoordinates').textContent = `Q.x = ${x.toString()}
Q.y = ${y.toString()}`;
  const markerX = 38 + (d - 1) * 575 / 15;
  $('curveCursor').setAttribute('x1', markerX);
  $('curveCursor').setAttribute('x2', markerX);
}
function drawCurve() {
  const svgNS = 'http://www.w3.org/2000/svg';
  const grid = $('curveGrid'), lines = $('curveLines');
  const xMin = -2.0, xMax = 3.8, yMin = -9, yMax = 9;
  const cx = x => 38 + (x - xMin) / (xMax - xMin) * 575;
  const cy = y => 277 - (y - yMin) / (yMax - yMin) * 265;
  function elem(tag, attrs, parent) {
    const el = document.createElementNS(svgNS, tag);
    for (const [name, val] of Object.entries(attrs)) el.setAttribute(name, val);
    parent.appendChild(el);
    return el;
  }
  for (let x = -2; x <= 3; x++) elem('line', {x1:cx(x),y1:12,x2:cx(x),y2:277,class:'grid-line'},grid);
  for (let y = -8; y <= 8; y += 2) elem('line', {x1:38,y1:cy(y),x2:613,y2:cy(y),class:'grid-line'},grid);
  elem('line', {x1:38,y1:cy(0),x2:613,y2:cy(0),class:'axis-line'},grid);
  elem('line', {x1:cx(0),y1:12,x2:cx(0),y2:277,class:'axis-line'},grid);
  const roots = -Math.cbrt(7);
  for (const sign of [-1, 1]) {
    const coords = [];
    for (let i = 0; i <= 500; i++) {
      const x = roots + (xMax - roots) * i / 500;
      const y = sign * Math.sqrt(Math.max(0, x*x*x + 7));
      if (y >= yMin && y <= yMax) coords.push(`${coords.length?'L':'M'} ${cx(x).toFixed(2)} ${cy(y).toFixed(2)}`);
    }
    elem('path', {d:coords.join(' '),class:'elliptic-line'},lines);
  }
}
drawCurve();
renderDemo(5);
$('curveScalar').addEventListener('input', event => renderDemo(event.target.value));
$('curveHit').addEventListener('pointermove', event => {
  // Ruch kursora po obszarze wykresu jedynie wybiera demonstracyjną liczbę d.
  if (event.pointerType === 'touch' && event.buttons === 0) return;
  const rect = $('curvePlot').getBoundingClientRect();
  const x = (event.clientX - rect.left) / rect.width * 640;
  renderDemo(1 + (Math.max(38, Math.min(613, x)) - 38) / 575 * 15);
});
$('curveHit').addEventListener('keydown', event => {
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
  event.preventDefault();
  renderDemo(+$('curveScalar').value + (event.key === 'ArrowRight' ? 1 : -1));
});
