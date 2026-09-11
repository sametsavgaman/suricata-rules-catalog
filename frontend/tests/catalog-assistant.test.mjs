import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'vite';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';

const server = await createServer({server:{middlewareMode:true, hmr:false}, appType:'custom'});
let AssistantResults, CatalogAssistant, DetectionFamilies;
try {
  ({AssistantResults, CatalogAssistant} = await server.ssrLoadModule('/src/components/CatalogAssistant.tsx'));
  ({DetectionFamilies} = await server.ssrLoadModule('/src/pages/DetectionFamilies.tsx'));
} finally { await server.close(); }
const render = (component, props) => renderToStaticMarkup(React.createElement(MemoryRouter, {}, React.createElement(component, props)));
const familyPageSource = readFileSync(new URL('../src/pages/DetectionFamilies.tsx', import.meta.url), 'utf8');
const result = {status:'RESULTS', answer:'1 kayıt bulundu', filters:{category:'Malware'}, total:1, items:[{
  sid:123, rev:2, classification_id:42, message:'<img src=x onerror=alert(1)>', category:'Malware', subcategory:null,
  entity:null, mitre_id:null, mitre_tactic:null, provider:'gemini', model:'model-test', product_status:'NOT_EVALUATED',
}], planner_model:'planner',source:'LOCAL_CATALOG'};
test('stored rule text is escaped and links use trusted numeric references', () => {
  const html = render(AssistantResults,{result});
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('/rules/123?classification_id=42'));
  assert.ok(html.includes('REV 2'));
  assert.ok(html.includes('MITRE atanmamış'));
});
test('clarification does not invent counts or results', () => {
  const html = render(AssistantResults,{result:{...result,status:'CLARIFY',total:null,items:[],answer:'Ölçüt belirtin'}});
  assert.ok(!html.includes('<table'));
  assert.ok(html.includes('Ölçüt belirtin'));
});
test('question form has accessible labels, bounded input and data disclosure', () => {
  const html = render(CatalogAssistant,{});
  assert.ok(html.includes('for="catalog-question"'));
  assert.ok(html.includes('maxLength="1000"'));
  assert.ok(html.includes('Seçili yardımcı modele yalnızca sorunuz gönderilir'));
  assert.ok(html.includes('aria-live="polite"'));
});
test('family results are structured, linked and never rendered as model prose', () => {
  const html = render(AssistantResults,{result:{...result,resource:'FAMILIES',items:[],families:[{
    id:7,slug:'anydesk',name:'AnyDesk',family_type:'TOOL',rule_count:10,mitre_count:1,
    protocols:['tcp','tls'],categories:['Command and Control'],mitre_ids:['T1219'],entity_types:['Remote Access Tool'],product_status:{},
  }]}});
  assert.ok(html.includes('/catalog/families/anydesk'));
  assert.ok(html.includes('AnyDesk'));
  assert.ok(html.includes('10'));
  assert.ok(html.includes('Command and Control'));
});
test('Detection Families page exposes useful filters and conservative coverage language', () => {
  const html = render(DetectionFamilies,{});
  assert.ok(html.includes('Detection Families'));
  assert.ok(html.includes('Search detection families'));
  assert.ok(html.includes('MITRE tactic'));
  assert.ok(html.includes('MITRE technique'));
  assert.ok(!html.includes('Product status: any'));
  assert.ok(html.includes('conservative coverage'));
});
test('Detection Families filters submit canonical values instead of translated labels', () => {
  assert.match(familyPageSource, /key=\{x\.value\} value=\{x\.value\}/);
  assert.doesNotMatch(familyPageSource, /url\.get\("product_status"\)|set\("product_status"|Family product status|Product status: any/);
});
