const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '..', 'static', 'app.js'), 'utf8');
const start = source.indexOf('function getSafetyCardLanguage');
const end = source.indexOf('function reportItems', start);
assert.ok(start >= 0 && end > start, 'safety-card helper block exists');
const escapeHtml = value => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const safetyCard = new Function('escapeHtml', `${source.slice(start, end)}\nreturn { getSafetyCardLanguage, getSafetyCardModel, renderFamilySafetyCard };`)(escapeHtml);

const report = {
  risk_level: 'high',
  findings: [
    { rule_id: 'TEXT-URGENCY', category: 'Urgency or threat' },
    { rule_id: 'TEXT-CREDENTIAL', category: 'Credential or OTP request' }
  ]
};
const originalMessage = 'Unique-private-text 992811 OTP at https://private.example/login';
let copiedText = '';
let downloaded = false;
const env = {
  currentReport: report,
  currentTool: 'text',
  $: () => ({ value: originalMessage }),
  navigator: { clipboard: { writeText: async text => { copiedText = text; } } },
  showToast: () => {},
  Blob,
  URL: { createObjectURL: () => 'blob:test', revokeObjectURL: () => {} },
  document: {
    body: { appendChild: () => {} },
    createElement: () => ({ click: () => { downloaded = true; }, remove: () => {} })
  },
  setTimeout: () => {}
};
const statefulHelpers = new Function(
  'escapeHtml', '$', 'currentReport', 'currentTool', 'navigator', 'showToast', 'Blob', 'URL', 'document', 'setTimeout',
  `${source.slice(start, end)}\nreturn { getFamilySafetyCardText, copyFamilySafetyCard, downloadFamilySafetyCard };`
)(escapeHtml, env.$, env.currentReport, env.currentTool, env.navigator, env.showToast, env.Blob, env.URL, env.document, env.setTimeout);

test('detects the three supported scripts and localizes cues', () => {
  for (const [message, language, cue] of [
    ['Act now, send OTP', 'en', 'Request for an OTP or secret'],
    ['अभी OTP भेजें', 'hi', 'OTP या गुप्त जानकारी माँगना'],
    ['તાત્કાલિક OTP મોકલો', 'gu', 'OTP અથવા ગુપ્ત માહિતીની વિનંતી']
  ]) {
    assert.equal(safetyCard.getSafetyCardLanguage(message), language);
    assert.ok(safetyCard.getSafetyCardModel(report, message).cues.includes(cue));
  }
});

test('share card summarizes signals without including the source message', () => {
  const privateMessage = 'Unique-private-text 992811 OTP at https://private.example/login';
  const html = safetyCard.renderFamilySafetyCard(report, privateMessage);
  assert.ok(html.includes('someone you trust'));
  assert.ok(html.includes('data-safety-card-action="copy"'));
  assert.ok(html.includes('data-safety-card-action="download"'));
  assert.ok(html.includes('Original message') || html.includes('original message'));
  assert.ok(!html.includes('Unique-private-text'));
  assert.ok(!html.includes('992811'));
  assert.ok(!html.includes('private.example'));
});

test('link-only triage includes link caution and trusted-person guidance', () => {
  const triageReport = { findings: [], url_analyses: [{ url: 'https://private.example/login' }] };
  const model = safetyCard.getSafetyCardModel(triageReport, 'Please check this link');
  assert.ok(model.cues.includes('A link is included'));
  assert.ok(model.actions.some(action => action.includes('do not open it')));
  assert.ok(model.actions.some(action => action.includes('someone you trust')));
});

test('copy and download actions export the privacy-safe summary', async () => {
  await statefulHelpers.copyFamilySafetyCard();
  assert.ok(copiedText.includes('Family Help Card'));
  assert.ok(copiedText.includes('Request for an OTP or secret'));
  assert.ok(!copiedText.includes('Unique-private-text'));
  assert.ok(!copiedText.includes('992811'));
  assert.ok(!copiedText.includes('private.example'));
  statefulHelpers.downloadFamilySafetyCard();
  assert.equal(downloaded, true);
});
