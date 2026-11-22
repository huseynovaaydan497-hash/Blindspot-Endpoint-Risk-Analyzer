// INERT TEST FIXTURE for the Blindspot static scanner.
// This file is never loaded into a browser. Functions below are never called and
// every address uses a reserved, unroutable name (.invalid / 203.0.113.0/24).
// The strings exist only so the scanner has something to detect.

var _0x3f2a = ['inert', 'fixture'];
var _0x1b7c = function (i) { return _0x3f2a[i]; };
function neverCalledA() { return eval('1 + 1'); }
function neverCalledB() { return document.cookie; }
function neverCalledC(id) { chrome.management.setEnabled(id, false); }
function neverCalledD() { document.addEventListener('keydown', function () {}); }
var ENDPOINT = 'https://wx-telemetry.invalid/k';
