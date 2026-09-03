import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const server = await createServer({server: {middlewareMode: true}, appType: 'custom'});
let DecisionAssessment, rawModelSignal;
try {
  ({ DecisionAssessment, rawModelSignal } = await server.ssrLoadModule('/src/components/DecisionAssessment.tsx'));
} finally {
  await server.close();
}
const base = {classification_status: 'AUTO_CLASSIFIED', confidence: 0.849, validation: {status: 'PASS'}};
const render = (value, compact = false) => renderToStaticMarkup(React.createElement(DecisionAssessment, {classification: value, compact}));

test('raw score remains unrounded and in collapsed technical details, without percentage or band', () => {
  const html = render(base);
  assert.match(html, /<details class="model-signal-details">/);
  assert.match(html, /Raw model signal: 0.849/);
  assert.doesNotMatch(html, /85%|MEDIUM|HIGH|<details[^>]*open/);
});
test('failed placeholder zero is unavailable, real successful zero is preserved', () => {
  assert.equal(rawModelSignal({...base, classification_status: 'FAILED', confidence: 0}), 'Unavailable');
  assert.equal(rawModelSignal({...base, confidence: 0}), '0');
  assert.equal(rawModelSignal({...base, confidence: null}), 'Unavailable');
});
test('null historical values do not imply abstention or a passed validator', () => {
  const html = render({...base, validation: null, detected_entity: null});
  assert.match(html, /Historical field decision metadata is unavailable/);
  assert.doesNotMatch(html, /Abstained|<dd>Passed<\/dd>/);
});
test('explicit abstention, not-applicable and assigned decisions retain their meaning', () => {
  const html = render({...base, field_decisions: {
    category: {status:'ASSIGNED', value:'Network Abuse'},
    detected_entity: {status:'ABSTAINED', value:null, reason:'No entity evidence'},
    entity_type: {status:'NOT_APPLICABLE', value:null},
  }});
  assert.match(html, /1 of 9 fields assigned/);
  assert.match(html, /Abstained/);
  assert.match(html, /Not applicable/);
  assert.match(html, /No entity evidence/);
});
test('validator pass does not hide separate semantic review in table or detail', () => {
  const c = {...base, validation: {status:'PASS', semantic_verifier:{status:'REVIEW'}}};
  for (const compact of [false, true]) {
    const html = render(c, compact);
    assert.match(html, /Passed/);
    assert.match(html, /Review flagged/);
  }
  assert.doesNotMatch(render(c, true), /0.849|%/);
});
test('unclassified rules show no confidence or assignment claim', () => {
  assert.match(render(null), /Not classified/);
  assert.doesNotMatch(render(null), /Passed|assigned|%/);
});
