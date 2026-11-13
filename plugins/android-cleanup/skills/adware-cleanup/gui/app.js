'use strict';
history.replaceState(null, '', '/');
const $ = id => document.getElementById(id);
let token = '', stamp = '', phonesStamp = '', reveal = false, current = null, nextCapture = 0;
function phonePanels(state) {
  $('capture').disabled = !$('phone').value || Date.now() < nextCapture;
  const key = JSON.stringify([state.phones, state.phone_error, state.serial, reveal]);
  if (key === phonesStamp) return; // Keep an open phone selector stable during polling.
  phonesStamp = key;
  $('phones').replaceChildren();
  const selected = $('phone').value;
  $('phone').replaceChildren(new Option('Select a phone…', ''));
  state.phones.forEach((phone, index) => {
    const serial = reveal ? phone.serial : `Phone ${index + 1} (serial hidden)`;
    const row = document.createElement('p');
    row.textContent = `${serial} · ${phone.model || 'Unknown model'} · ${phone.state}. ${phone.advice}`;
    $('phones').append(row);
    if (phone.state === 'device') $('phone').add(new Option(`${phone.model || 'Phone'} · ${serial}`, phone.serial));
  });
  if (state.phones.some(p => p.serial === selected && p.state === 'device')) $('phone').value = selected;
  if (!state.phones.length) $('phones').textContent = state.phone_error || 'No phones found. Check USB debugging and use a data cable.';
  $('identity').hidden = !reveal || !state.serial;
  $('serial').textContent = reveal ? state.serial : '';
  $('capture').disabled = !$('phone').value || Date.now() < nextCapture;
}
async function poll() {
  try {
    const response = await fetch('/api/state');
    if (!response.ok) throw Error(`Viewer request failed (${response.status}); reopen the terminal URL.`);
    current = await response.json();
    const next = JSON.stringify(current.mtimes);
    if (next !== stamp) {
      $('records').innerHTML = current.html;
      stamp = next;
      $('reports').replaceChildren();
      current.reports.forEach(name => {
        const p = document.createElement('p'), link = document.createElement('a');
        link.href = '/files/' + encodeURIComponent(name); link.textContent = name;
        link.target = '_blank'; link.rel = 'noopener'; p.append(link); $('reports').append(p);
      });
      if (!current.reports.length) $('reports').textContent = 'No PDF reports yet.';
    }
    phonePanels(current);
    $('status').textContent = 'Watching job files · Updated ' + new Date().toLocaleTimeString();
  } catch (error) { $('status').textContent = error.message; }
  setTimeout(poll, 2000);
}
$('reveal').onclick = () => { reveal = !reveal; $('reveal').textContent = reveal ? 'Hide serials' : 'Reveal serials'; if (current) phonePanels(current); };
$('phone').onchange = () => { $('capture').disabled = !$('phone').value || Date.now() < nextCapture; $('screen').hidden = true; };
$('capture').onclick = async () => {
  const serial = $('phone').value;
  if (!serial) return;
  nextCapture = Date.now() + 10000;
  $('capture').disabled = true; $('capture-status').textContent = 'Capturing…';
  try {
    const response = await fetch('/api/screenshot', {method:'POST', headers:{'Content-Type':'application/json','X-Access-Token':token}, body:JSON.stringify({serial})});
    const data = await response.json();
    if (!response.ok) throw Error(data.error || 'Capture failed');
    if ($('phone').value === serial) { $('screen').src = data.url; $('screen').hidden = false; }
    $('capture-status').textContent = 'Screenshot saved. Wait 10 seconds before refreshing.';
  } catch(error) { $('capture-status').textContent = error.message; }
};
fetch('/api/session').then(r => { if (!r.ok) throw Error('Reopen the terminal access URL.'); return r.json(); }).then(data => {token=data.token; poll();}).catch(error => {$('status').textContent=error.message;});
