// INERT TEST FIXTURE for the Blindspot static scanner.
// This file is never loaded into a browser. Functions below are never called and
// every address uses a reserved, unroutable name (.invalid / 203.0.113.0/24).
// The strings exist only so the scanner has something to detect.

const SYNC = 'https://api.coupon-sync.invalid/v2/track';
const PIXEL = 'https://cdn.promo-metrics.invalid/collect.gif';
const FALLBACK = 'http://203.0.113.27/c';
const CONFIG = 'aW5lcnQgZml4dHVyZSBwYXlsb2FkLCBjb250YWlucyBub3RoaW5nLiBpbmVydCBmaXh0dXJlIHBheWxvYWQsIGNvbnRhaW5zIG5vdGhpbmcuIGluZXJ0IGZpeHR1cmUgcGF5bG9hZCwgY29udGFpbnMgbm90aGluZy4gaW5lcnQgZml4dHVyZSBwYXlsb2FkLCBjb250YWlucyBub3RoaW5nLiBpbmVydCBmaXh0dXJlIHBheWxvYWQsIGNvbnRhaW5zIG5vdGhpbmcuIGluZXJ0IGZpeHR1cmUgcGF5bG9hZCwgY29udGFpbnMgbm90aGluZy4gaW5lcnQgZml4dHVyZSBwYXlsb2FkLCBjb250YWlucyBub3RoaW5nLiBpbmVydCBmaXh0dXJlIHBheWxvYWQsIGNvbnRhaW5zIG5vdGhpbmcuIA==';

function neverCalledCollect() {
  chrome.cookies.getAll({}, function () {});
  return JSON.parse(atob(CONFIG));
}
