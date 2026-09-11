import { useEffect, useState } from "react";
import { addRuleToPack, createRulePack, getActiveRulePackId, loadRulePacks, setActiveRulePack, type StoredRulePack } from "../services/rulePack";
import { useI18n } from "../i18n";
export function AddToRulePack({sid,compact=false}:{sid:number;compact?:boolean}){
 const { t } = useI18n();
 const [open,setOpen]=useState(false),[packs,setPacks]=useState<StoredRulePack[]>([]),[selected,setSelected]=useState(""),[name,setName]=useState(""),[message,setMessage]=useState("");
 const refresh=()=>{const values=loadRulePacks();setPacks(values);setSelected(current=>current||getActiveRulePackId()||values[0]?.id||"")};
 useEffect(()=>{refresh();window.addEventListener("rule-pack-change",refresh);return()=>window.removeEventListener("rule-pack-change",refresh)},[]);
 const add=()=>{if(!selected)return;addRuleToPack(selected,sid);setActiveRulePack(selected);setMessage(t("Rule added."));setTimeout(()=>setOpen(false),450)};
 const create=()=>{if(!name.trim())return;const pack=createRulePack(name,[sid]);setSelected(pack.id);setName("");setMessage(t("Pack created and rule added."));setTimeout(()=>setOpen(false),550)};
 return <div className={`pack-picker ${compact?"compact":""}`} onClick={e=>e.stopPropagation()}><button className="pack-picker-trigger" onClick={()=>{setOpen(v=>!v);setMessage("")}}>{t("Add to Rule Pack")}</button>{open&&<div className="pack-picker-menu" role="dialog"><b>{t("Choose a rule pack")}</b>{packs.length?<><select value={selected} onChange={e=>setSelected(e.target.value)}>{packs.map(p=><option value={p.id} key={p.id}>{p.name} ({p.sids.length})</option>)}</select><button className="primary" onClick={add}>{t("Add to selected pack")}</button></>:<small>{t("No rule packs yet. Create the first one below.")}</small>}<div className="pack-picker-create"><input value={name} onChange={e=>setName(e.target.value)} placeholder={t("New pack name")}/><button onClick={create} disabled={!name.trim()}>{t("Create + add")}</button></div>{message&&<em>{message}</em>}<button className="pack-picker-close" onClick={()=>setOpen(false)}>{t("Cancel")}</button></div>}</div>
}
