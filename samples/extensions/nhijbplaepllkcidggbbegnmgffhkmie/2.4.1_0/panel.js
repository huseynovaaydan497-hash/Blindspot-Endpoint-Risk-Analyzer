const note = document.getElementById('note');
chrome.storage.local.get('note').then(v => { note.value = v.note || ''; });
note.addEventListener('change', () => chrome.storage.local.set({ note: note.value }));
