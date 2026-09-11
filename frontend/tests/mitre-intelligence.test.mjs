import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MemoryRouter } from 'react-router-dom';

const server = await createServer({server:{middlewareMode:true, hmr:false}, appType:'custom'});
let TechniqueRows, RelatedFamilyLinks, FamilyMitrePanel;
try {
  ({TechniqueRows} = await server.ssrLoadModule('/src/pages/MitreCatalog.tsx'));
  ({RelatedFamilyLinks} = await server.ssrLoadModule('/src/pages/MitreTechniqueDetail.tsx'));
  ({FamilyMitrePanel} = await server.ssrLoadModule('/src/pages/FamilyDetail.tsx'));
} finally { await server.close(); }
const render = component => renderToStaticMarkup(React.createElement(MemoryRouter, {}, component));
const technique = {technique_id:'T1071.001',name:'Web Protocols',tactics:['Command And Control'],parent_id:'T1071',is_subtechnique:true,rule_count:4,family_count:1,parent:{technique_id:'T1071',name:'Application Layer Protocol'}};

test('technique hierarchy links to canonical technique detail', () => {
  const html = render(React.createElement(TechniqueRows,{items:[technique]}));
  assert.ok(html.includes('/catalog/mitre/T1071.001'));
  assert.ok(html.includes('Web Protocols'));
  assert.ok(html.includes('T1071 · Application Layer Protocol'));
});

test('family and MITRE surfaces expose bidirectional navigation', () => {
  const family = {id:7,slug:'anydesk',name:'AnyDesk',family_type:'TOOL',rule_count:18};
  const related = render(React.createElement(RelatedFamilyLinks,{families:[family]}));
  assert.ok(related.includes('/catalog/families/anydesk'));
  const panel = render(React.createElement(FamilyMitrePanel,{profile:{mapped_rule_count:18,unmapped_rule_count:2,techniques:[{...technique,technique_id:'T1219',name:'Remote Access Tools',parent_id:null,is_subtechnique:false,tactics:['Command And Control'],rule_count:18,family_count:1}]}}));
  assert.ok(panel.includes('/catalog/mitre/T1219'));
  assert.ok(panel.includes('/catalog/mitre'));
});
