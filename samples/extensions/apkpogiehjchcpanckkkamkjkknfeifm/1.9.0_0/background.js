chrome.contextMenus.create({ id: 'tr', title: 'Translate', contexts: ['selection'] });
async function translate(text) {
  const r = await fetch('https://translate.googleapis.com/translate_a/single?q=' + encodeURIComponent(text));
  return r.json();
}
