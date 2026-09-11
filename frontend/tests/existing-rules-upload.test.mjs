import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';

const server = await createServer({server:{middlewareMode:true,hmr:false},appType:'custom'});
let ExistingRules;
try {
  ({ExistingRules} = await server.ssrLoadModule('/src/pages/ExistingRules.tsx'));
} finally { await server.close(); }

test('existing rules upload explains the accepted schema and restricts file selection', () => {
  const html = renderToStaticMarkup(React.createElement(MemoryRouter, {}, React.createElement(ExistingRules)));
  assert.ok(html.includes('Accepted ruleset format'));
  assert.ok(html.includes('.rules · UTF-8'));
  assert.ok(html.includes('SID · REV'));
  assert.ok(html.includes('alert tcp $HOME_NET any -&gt; $EXTERNAL_NET 443'));
  assert.ok(html.includes('accept=".rules"'));
  assert.ok(!html.includes('accept=".rules,.txt'));
  assert.ok(html.includes('Validated before any database write'));
});
