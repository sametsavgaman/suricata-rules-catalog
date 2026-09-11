import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'vite';

const server = await createServer({server:{middlewareMode:true,hmr:false},appType:'custom'});
let buildRuleDecisionContext;
try {
  ({buildRuleDecisionContext} = await server.ssrLoadModule('/src/pages/RuleDetail.tsx'));
} finally { await server.close(); }

const rule = {
  action:'alert', protocol:'tcp', source:'$HOME_NET', source_port:'any', direction:'->',
  destination:'$EXTERNAL_NET', destination_port:'443', flow:['established','to_server'],
  flowbits:['set,example'], contents:['powershell','encodedcommand'], pcre:['/cmd/i'],
  app_layer:[{name:'tls.sni',value:null},{name:'tls.sni',value:null}], classtype:'trojan-activity',
};

test('system decision context exposes deterministic Suricata traffic scope', () => {
  const items = buildRuleDecisionContext(rule, 'tr');
  assert.equal(items.find(item => item.key === 'source').value, '$HOME_NET : any');
  assert.equal(items.find(item => item.key === 'direction').value, '->');
  assert.equal(items.find(item => item.key === 'destination').value, '$EXTERNAL_NET : 443');
  assert.match(items.find(item => item.key === 'inspection').value, /ALERT · TCP/);
  assert.match(items.find(item => item.key === 'inspection').detail, /tls\.sni/);
  assert.match(items.find(item => item.key === 'flow').value, /established · to_server/);
  assert.match(items.find(item => item.key === 'signals').value, /2 içerik kalıbı · 1 düzenli ifade/);
});

test('missing optional selectors are described without inventing evidence', () => {
  const items = buildRuleDecisionContext({...rule,flow:[],flowbits:[],contents:[],pcre:[],app_layer:[],classtype:null}, 'en');
  assert.equal(items.find(item => item.key === 'flow').value, 'No explicit flow condition');
  assert.match(items.find(item => item.key === 'inspection').detail, /No explicit application-layer keyword/);
  assert.match(items.find(item => item.key === 'signals').detail, /No classtype/);
});
