/* radare2 Copyleft 2013-2022 pancake & frenchyeti */

import * as r2pipe from "r2pipe-promise";
import MemoryMap, {MemoryPart} from "./MemoryMap";

export interface R2Setting {
    name:string;
    defVal:string|boolean|number;
    apply: any;
}

export interface R2Configuration {
    [settingName:string] :R2Setting
}

export interface Chunk {
    data: any;
    prev?: Chunk;
    next?: Chunk;
}
/**
 *
 * Not exported, internal use only
 *
 * @function
 */
function isFirefoxOS():boolean {
    // @ts-ignore
    if (typeof locationbar !== 'undefined' && !locationbar.visible) {
        // @ts-ignore
        if (navigator.userAgent.indexOf('Firefox') > -1 && navigator.userAgent.indexOf('Mobile') > -1) {
            // @ts-ignore
            return ('mozApps' in navigator);
        }
    }
    return false;
}

/**
 * Utility, not exported function
 *
 * @param str
 */
function toBoolean(str) {
    if (str === 'true') return true;
    else if (str === 'false') return false;
    else return undefined;
}

/**
 * Utility, not exported function
 *
 * @param str
 */
function address_canonicalize(pAddrStr:string):string {
    pAddrStr = pAddrStr.substr(2);
    while (pAddrStr.substr(0, 1) == '0') pAddrStr = pAddrStr.substr(1);
    pAddrStr = '0x' + pAddrStr;
    pAddrStr = pAddrStr.toLowerCase();
    return pAddrStr;
}


enum R2SyncMode {
    SYNC= 'sync',
    ASYNC= 'async',
    SASYNC= 'sasync',
    FAKE= 'fake',
}

export enum PluginType {
    ANAL= 'anal',
    CORE= 'core',
    DEBUG= 'debug',
    DEC_SUPPORTED= 'dec',
    ESIL= 'esil',
    EGG= 'egg',
    HASH= 'hash',
    BIN= 'bin',
    COLOR= 'color',
    LANG= 'language',
    FS= 'fd',
    IO= 'io',
    PARSER= 'parser'
}

export enum INTERNAL_DATA_FORMAT {
    JSON,
    TEXT
}

export interface Plugin {
    name:string;
    licence?:string;
    descr?:string;
    addrSizes?:string;
    author?:string;
    perm?:string;
    selected?:boolean;
}

interface PluginCache {
    [type:string] :Plugin[]
}

export class PluginManager {

    static types: any = {
        [PluginType.ANAL]: { cmd:'La', fmt:INTERNAL_DATA_FORMAT.TEXT, sep:/\s\s+/, cols:["?"/* TODO */,"addrSizes","name","licence","descr"] },
        [PluginType.CORE]: { cmd:'Lcj', fmt:INTERNAL_DATA_FORMAT.JSON },
        [PluginType.DEBUG]: { cmd:'Ldj', fmt:INTERNAL_DATA_FORMAT.JSON },
        [PluginType.DEC_SUPPORTED]: { cmd:'LD', fmt:INTERNAL_DATA_FORMAT.TEXT, cols:["descr"] },
        [PluginType.ESIL]: { cmd:'Le', fmt:INTERNAL_DATA_FORMAT.TEXT, cols:["descr"] }, // TODO
        [PluginType.EGG]: { cmd:'Lg', fmt:INTERNAL_DATA_FORMAT.TEXT, sep:/\s\s+/, cols:["name","descr"] },
        [PluginType.HASH]: { cmd:'Lh', fmt:INTERNAL_DATA_FORMAT.TEXT, cols:["name"] },
        [PluginType.BIN]: { cmd:'Li', fmt:INTERNAL_DATA_FORMAT.TEXT, sep:/\s\s+/, cols:["?"/* TODO */,"name","descr","licence","author"] },
        [PluginType.COLOR]: { cmd:'Lt', fmt:INTERNAL_DATA_FORMAT.TEXT, sep:/\s\s+/, cols:["selected","name"] },
        [PluginType.LANG]: { cmd:'Ll', fmt:INTERNAL_DATA_FORMAT.TEXT, sep:/\s\s+/, cols:["name","licence","descr"] },
        [PluginType.FS]: { cmd:'Lm', fmt:INTERNAL_DATA_FORMAT.TEXT, sep:/\s\s+/, cols:["name","descr"] },
        [PluginType.IO]: { cmd:'Lo', fmt:INTERNAL_DATA_FORMAT.TEXT, sep:/\s\s+/, cols:["perm","name","licence","descr"] },
        [PluginType.PARSER]: { cmd:'Lp', fmt:INTERNAL_DATA_FORMAT.TEXT, cols:["name"] }
    }

    public plugins:PluginCache = {};
    private _r2api:R2API = null;

    constructor(pAPI:R2API) {
        this._r2api = pAPI;
    }

    async list(pPluginType:PluginType, pCallback:any):void {
        if(PluginManager.types[pPluginType]==null){
            throw new Error(`Plugin type "${pPluginType}" not exists.`)
        }

        const type:any = PluginManager.types[pPluginType];

        this._r2api.cmd(type.cmd, (vRes:string)=>{
            let plist:Plugin[] = [];

            if(type.fmt === INTERNAL_DATA_FORMAT.JSON ){
                plist = JSON.parse(vRes);
            }else{
                // TODO : detect EOL
                const lines:string[] = vRes.trim().split("\n");
                if(type.sep != null){
                    lines.map( (l:string )=> {
                        const plugin:any = {};
                        l.split(type.sep).map((n:string,idx:number)=> {
                            plugin[type.cols[idx]] = n;
                        });
                        plist.push(plugin);
                    });
                }else{
                    lines.map( (l:string )=> {
                        const plugin:any = {};
                        plugin[type.cols[0]] = l;
                        plist.push(plugin);
                    });
                }
            }

            this.plugins[pPluginType] = plist;

            if(typeof (pCallback) === 'function'){
                pCallback.call(plist);
            }
        })

    }
}

export enum R2PipeMode {
    PIPE,
    AJAX
}

export class R2API {

    mmap:MemoryMap = null;

    static backward:boolean = false;
    static next_curoff:number = 0;
    static next_lastoff:number = 0;
    static prev_curoff:number = 0;
    static prev_lastoff:number = 0;
    static hascmd:any = false;
    static asyncMode:R2SyncMode = R2SyncMode.SYNC;

    static varMap = [];
    static argMap = [];
    static ajax_in_process:boolean = false;
    /**
     * callback to be executed when connection fails
     * @field
     */
    static err:any = null;

    // @ts-ignore
    static r2_root:string = self.location.pathname.split('/').slice(0, -2).join('/');

    static root:string =  isFirefoxOS()? 'http://cloud.radare.org' : R2API.r2_root;

    static project_name:string = '';
    static asm_config:any = {};
    static sections:any = {};
    static settings:any = {};
    static flags:any = {};

    static inColor:any = null;

    private _pm:PluginManager;
    private r2pipe:any = null;
    private path:string = null;
    private _mode:R2PipeMode;

    /**
     *
     * @param pBinPath
     * @param pMode
     */
    constructor( pBinPath:string = null, pMode:R2PipeMode = R2PipeMode.PIPE ) {
        this.path = pBinPath;
        this._mode = pMode;
        this._pm = new PluginManager(this);
    }

    /**
     *
     * @param pBinaryPath
     */
    async connect( pBinaryPath:string):Promise<void> {
        if(this._mode!==R2PipeMode.PIPE){
            throw new Error("[ERROR] R2API.connect() : Only R2PipeMode.PIPE mode is supported.")
        }

        this.r2pipe = await r2pipe.open(pBinaryPath);
    }


    getPluginManager():PluginManager{
        return this._pm;
    }

    plugin():void {
        try {
            // @ts-ignore
            if (typeof r2plugin !== 'undefined') {
                // @ts-ignore
                R2API.plugin = r2plugin;
            }else{
                throw new Error();
            }
        } catch (e) {
            console.error('r2.plugin is not available in this environment');
        }
    };



    analAll():void {
        this.cmd('aa', function() {});
    };

    analOp(pAddress:string, pCallback:any):void {
        this.cmd('aoj 1 @ ' + pAddress, function(pStr:string) {
            try {
                pCallback(JSON.parse(pStr)[0]);
            } catch (e) {
                console.error(e);
                pCallback(pStr);
            }
        });
    };


    assemble(pOffset:any, pOpcode:string, pCallback:any):void {
        const off = pOffset ? '@' + pOffset : '';
        this.cmd('"pa ' + pOpcode + '"' + off, pCallback);
    };

    disassemble(pOffset:any, pBytes:any, pCallback:any):void {
        const off = pOffset ? '@' + pOffset : '';
        const str = 'pi @b:' + pBytes + off;
        this.cmd(str, pCallback);
    };

    get_hexdump(pOffset:any, pLength:number, pCallback:any):void {
        this.cmd('px ' + pLength + '@' + pOffset, pCallback);
    };

    get_disasm(pOffset:any, pLength:number, pCallback:any):void {
        // TODO: honor offset and length
        this.cmd('pD ' + pLength + '@' + pOffset, pCallback);
    };

    get_disasm_before(pOffset:any, pStart:number, pCallback:any) {
        let before:string[] = [];
        this.cmd('pdj -' + pStart + '@' + pOffset + '|', function(x) {
            before = JSON.parse(x);
        });
        // TODO (frenchyeti) : callback outside cmd(), error ?
        pCallback(before);
    };

    get_disasm_after(pOffset:any, pEnd:number, pCallback:any) {
        let after:any = [];
        this.cmd('pdj ' + pEnd + '@' + pOffset + '|', function(x) {
            after = JSON.parse(x);
        });
        // TODO (frenchyeti) : callback outside cmd(), error ?
        pCallback(after);
    };

    get_disasm_before_after(pOffset:any, pStart:number, pEnd:number, pCallback:any) {
        let before:any = [];
        let after:any = [];
        this.cmd('pdj ' + pStart + ' @' + pOffset + '|', function(x) {
            before = JSON.parse(x);
        });
        this.cmd('pdj ' + pEnd + '@' + pOffset + '|', function(x) {
            after = JSON.parse(x);
        });
        const opcodes = before.concat(after);
        // TODO (frenchyeti) : callback outside cmd(), error ?
        pCallback(opcodes);
    };

    Config(pKey:string, pValue:any, pCallback:any) {
        if (typeof pValue == 'function' || !pValue) { // get
            this.cmd('e ' + pKey + '|', pCallback || pValue);
        } else { // set
            this.cmd('e ' + pKey + '=' + pValue, pCallback);
        }
        return R2API;
    };


    loadMemoryMap():void {
        this.cmdj('iSj|', function(x) {
            if (x !== undefined && x !== null) {
                R2API.sections = x;
            }
        });
    };

    get_address_type(pAddress:string):string {
        const offset = parseInt(pAddress, 16);
        for (const i in R2API.sections) {
            if (offset >= R2API.sections[i].addr && offset < R2API.sections[i].addr + R2API.sections[i].size) {
                if (R2API.sections[i].flags.indexOf('x') > -1) {
                    return 'instruction';
                } else {
                    return 'memory';
                }
            }
        }
        return '';
    };


    load_settings() {
        this.cmd('e asm.arch', function(x) {R2API.settings['asm.arch'] = x.trim();});
        this.cmd('e asm.bits', function(x) {R2API.settings['asm.bits'] = x.trim();});
        this.cmd('e asm.bytes', function(x) {R2API.settings['asm.bytes'] = toBoolean(x.trim());});
        this.cmd('e asm.flags', function(x) {R2API.settings['asm.flags'] = toBoolean(x.trim());});
        this.cmd('e asm.offset', function(x) {R2API.settings['asm.offset'] = toBoolean(x.trim());});
        this.cmd('e asm.lines', function(x) {R2API.settings['asm.lines'] = toBoolean(x.trim());});
        this.cmd('e asm.xrefs', function(x) {R2API.settings['asm.xrefs'] = toBoolean(x.trim());});
        this.cmd('e asm.cmtright', function(x) {R2API.settings['asm.cmtright'] = toBoolean(x.trim());});
        this.cmd('e asm.pseudo', function(x) {R2API.settings['asm.pseudo'] = toBoolean(x.trim());});
        // console.log("Loading settings from r2");
        // console.log(r2.settings);
    };


    update_flags():void {
        this.cmd('fs *;fj|', function(x) {

            const fs = JSON.parse(x);
            if (fs !== undefined && fs !== null) {
                R2API.flags = {};
                for (const f in fs) {
                    let addr:string = '0x' + fs[f].offset.toString(16);
                    addr = address_canonicalize(addr);
                    if (addr in R2API.flags) {
                        const fl = R2API.flags[addr];
                        fl[fl.length] = { name: fs[f].name, size: fs[f].size};
                        R2API.flags[addr] = fl;
                    } else {
                        R2API.flags[addr] = [{ name: fs[f].name, size: fs[f].size}];
                    }
                }
            }
        });
    };

    get_flag_address(pName:string):any {
        for (const f in R2API.flags) {
            for (const v in R2API.flags[f]) {
                if (pName == R2API.flags[f][v].name) return f;
            }
        }
        return null;
    };

    get_flag_names(pOffset:number):string[] {
        const names:string[] = [];
        for (const i in R2API.flags[pOffset]) {
            names[names.length] = R2API.flags[pOffset][i].name;
        }
        return names;
    };

    set_flag_space(pNamespace:string, pSuccessCallback:any):void {
        this.cmd('fs ' + pNamespace, pSuccessCallback);
    };

    get_flags(pSuccessCallback:any):void {
        this.cmd('fj|', function(x) {
            pSuccessCallback(x ? JSON.parse(x) : []);
        });
    };

    get_opcodes(pOffset:string, n:string, pSuccessCallback:any):void {
        this.cmd('pdj @' + pOffset + '!' + n + '|', function(json) {
            pSuccessCallback(JSON.parse(json));
        });
    };

    get_bytes(pOffset:string, n:string, pSuccessCallback:any):void {
        this.cmd('pcj @' + pOffset + '!' + n +'|', function(json) {
            pSuccessCallback(JSON.parse(json));
        });
    };


    store_asm_config():void {
        const config = {};
        this.cmd('e', function(x) {
            const confStr = x.split('\n');
            for (const prop in confStr) {
                const fields = confStr[prop].split(' ');
                if (fields.length == 3) {
                    // TODO: Dont know why byt e~asm. is not working so filtering here
                    if (fields[0].trim().indexOf('asm.') == 0) config[fields[0].trim()] = fields[2].trim();
                }
            }
            R2API.asm_config = config;
        });
    };

    restore_asm_config():void {
        let cmd:string = '';
        for (const prop in R2API.asm_config) {
            cmd += 'e ' + prop + '=' + R2API.asm_config[prop] + ';';
        }
        this.cmd(cmd, function() {});
    };

    get_info(pSuccessCallback:any):void {
        this.cmd('ij|', function(json) {
            pSuccessCallback(JSON.parse(json));
        });
    };

    bin_relocs(pSuccessCallback:any):void {
        this.cmd('irj|', function(json) {
            pSuccessCallback(JSON.parse(json));
        });
    };

    bin_imports(pSuccessCallback:any):void {
        this.cmd('iij|', function(json) {
            pSuccessCallback(JSON.parse(json));
        });
    };

    bin_symbols(pSuccessCallback:any):void {
        this.cmd('isj|', function(json) {
            pSuccessCallback(JSON.parse(json));
        });
    };

    bin_sections(pSuccessCallback:any):void {
        this.cmd('iSj|', function(json) {
            pSuccessCallback(JSON.parse(json));
        });
    };

    cmds(pCommand:string[], pSuccessCallback:any):void {
        if (pCommand.length == 0) return;
        let cmd:string = pCommand[0];
        pCommand = pCommand.splice(1);
        function lala() {
            if (cmd === undefined || pCommand.length == 0) {
                return;
            }
            cmd = pCommand[0];
            pCommand = pCommand.splice(1);
            this.cmd(cmd, lala);
            if (pSuccessCallback) {
                pSuccessCallback();
            }
            return;
        }
        this.cmd(cmd, lala);
    };

    _internal_cmd(pCommand:string, pSuccessCallback:any, pErrCallback:any):any {
        this.r2pipe.cmd
        // TODO (frenchyeti) : move it outside, make it common
        // @ts-ignore
        if (typeof (r2cmd) != 'undefined') {
            // @ts-ignore
            R2API.hascmd = r2cmd;
        }
        if (R2API.hascmd) {
            // TODO (pancake): use setTimeout for async?
            // TODO (frenchyeti) : move it outside, make it common
            // @ts-ignore
            if (typeof (r2plugin) != 'undefined') {
                // duktape
                // @ts-ignore
                return pSuccessCallback(r2cmd(pCommand));
            } else {
                // node
                return R2API.hascmd(pCommand, pSuccessCallback);
            }
        } else {
            this.ajax('GET', R2API.root + '/cmd/' + encodeURI(pCommand), '', function(x) {
                if (pSuccessCallback) {
                    pSuccessCallback(x);
                }
            }, pErrCallback);
        }
    }

    cmd(pCommand:string, pSuccessCallback:any = ()=>{}, pErrCallback:any = null):void {
        if (Array.isArray(pCommand)) {
            let res:any = [];
            let idx:number = 0;
            asyncLoop(pCommand.length, function(vLoop) {
                this._internal_cmd(pCommand[idx], function(vResult) {
                    idx = vLoop.iteration();
                    res[idx] = vResult.replace(/\n$/, '');
                    idx++;
                    vLoop.next();
                }, pErrCallback);
            }, function() {
                // all iterations done
                pSuccessCallback(res);
            });
        } else {
            this._internal_cmd(pCommand, pSuccessCallback, pErrCallback);
        }
    };

    cmdj(pCommand:string, pSuccessCallback:any):void {
        this.cmd(pCommand, function(x) {
            try {
                pSuccessCallback(JSON.parse(x));
            } catch (e) {
                pSuccessCallback(null);
            }
        });
    };

    // TODO (frenchyeti) : purpose ?
    alive(pSuccessCallback:any) {
        this.cmd('b', function(o) {
            let ret:boolean = false;
            if (o && o.length() > 0) {
                ret = true;
            }
            if (pSuccessCallback) {
                pSuccessCallback(o);
            }
        });
    };

    getTextLogger(pObject:any) {
        if (typeof (pObject) != 'object') {
            pObject = {};
        }
        pObject.last = 0;
        pObject.events = {};
        pObject.interval = null;
        this.cmd('Tl', function(x) {
            pObject.last = +x;
        });
        pObject.load = function(cb) {
            this.cmd('"Tj ' + (pObject.last + 1) + '"', function(ret) {
                if (cb) {
                    cb(JSON.parse(ret));
                }
            });
        };
        pObject.clear = function(cb) {
            // XXX: fix l-N
            this.cmd('T-', cb); //+obj.last, cb);
        };
        pObject.send = function(msg, cb) {
            this.cmd('"T ' + msg + '"', cb);
        };
        pObject.refresh = function(cb) {
            pObject.load(function(ret) {
                //obj.last = 0;
                for (let i = 0; i < ret.length; i++) {
                    const message = ret[i];
                    pObject.events['message']({
                        'id': message[0],
                        'text': message[1]
                    });
                    if (message[0] > pObject.last) {
                        pObject.last = message[0];
                    }
                }
                if (cb) {
                    cb();
                }
            });
        };
        pObject.autorefresh = function(n) {
            if (!n) {
                if (pObject.interval) {
                    pObject.interval.stop();
                }
                return;
            }
            function to() {
                pObject.refresh(function() {
                    //obj.clear ();
                });
                // @ts-ignore
                if (r2ui.selected_panel === 'Logs') {
                    setTimeout(to, n * 1000);
                } else {
                    console.log('Not in logs :(');
                }
                return true;
            }
            pObject.interval = setTimeout(to, n * 1000);
        };
        pObject.on = function(ev, cb) {
            pObject.events[ev] = cb;
            return pObject;
        };
        return pObject;
    };


    haveDisasm(x):boolean {
        if (x[0] == 'p' && x[1] == 'd') return true;
        if (x.indexOf(';pd') != -1) return true;
        return false;
    }

    filter_asm( pStr:string, display:string):string {
        let curoff:number = R2API.backward ? R2API.prev_curoff : R2API.next_curoff;
        let lastoff:number = R2API.backward ? R2API.prev_lastoff : R2API.next_lastoff;
        let lines:string[] = pStr.split(/\n/g);

        this.cmd('s', function(x) {
            curoff = x;
        });

        for (let i:number = lines.length - 1; i > 0; i--) {
            const a:RegExpMatchArray = lines[i].match(/0x([a-fA-F0-9]+)/);
            if (a && a.length > 0) {
                //lastoff = a[0].replace(/:/g, '');
                lastoff = parseInt(a[0].replace(/:/g, ''),16);
                break;
            }
        }
        if (display == 'afl') {
            //hasmore (false);
            let z:string = '';
            for (let i = 0; i < lines.length; i++) {
                const row:string[] = lines[i].replace(/\ +/g, ' ').split(/ /g);
                z += row[0] + '  ' + row[3] + '\n';
            }
            pStr = z;
        } else if (display[0] == 'f') {
            //hasmore (false);
            if (display[1] == 's') {
                let z:string = '';
                for (let i:number = 0; i < lines.length; i++) {
                    const row = lines[i].replace(/\ +/g, ' ').split(/ /g);
                    const mark = row[1] == '*' ? '*' : ' ';
                    const space = row[2] ? row[2] : row[1];
                    if (!space) continue;
                    z += row[0] + ' ' + mark + ' <a href="javascript:runcmd(\'fs ' +
                        space + '\')">' + space + '</a>\n';
                }
                pStr = z;
            } else {
            }
        } else if (display[0] == 'i') {
            //hasmore (false);
            if (display[1]) {
                let z:string = '';
                for (let i:number = 0; i < lines.length; i++) {
                    const elems:string[] = lines[i].split(/ /g);
                    let name:string = '';
                    let addr:string = '';
                    for (let j:number = 0; j < elems.length; j++) {
                        const kv:string[] = elems[j].split(/=/);
                        if (kv[0] == 'addr') {
                            addr = kv[1];
                        }
                        if (kv[0] == 'name') {
                            name = kv[1];
                        }
                        if (kv[0] == 'string') {
                            name = kv[1];
                        }
                    }
                    z += addr + '  ' + name + '\n';
                }
                pStr = z;
            }
        } //else hasmore (true);

        if (R2API.haveDisasm(display)) {
            //	x = x.replace(/function:/g, '<span style=color:green>function:</span>');
            /*
                    x = x.replace(/;(\s+)/g, ';');
                    x = x.replace(/;(.*)/g, '// <span style=\'color:#209020\'>$1</span>');
                    x = x.replace(/(bl|goto|call)/g, '<b style=\'color:green\'>call</b>');
                    x = x.replace(/(jmp|bne|beq|js|jnz|jae|jge|jbe|jg|je|jl|jz|jb|ja|jne)/g, '<b style=\'color:green\'>$1</b>');
                    x = x.replace(/(dword|qword|word|byte|movzx|movsxd|cmovz|mov\ |lea\ )/g, '<b style=\'color:#1070d0\'>$1</b>');
                    x = x.replace(/(hlt|leave|iretd|retn|ret)/g, '<b style=\'color:red\'>$1</b>');
                    x = x.replace(/(add|sbb|sub|mul|div|shl|shr|and|not|xor|inc|dec|sar|sal)/g, '<b style=\'color:#d06010\'>$1</b>');
                    x = x.replace(/(push|pop)/g, '<b style=\'color:#40a010\'>$1</b>');
                    x = x.replace(/(test|cmp)/g, '<b style=\'color:#c04080\'>$1</b>');
                    x = x.replace(/(outsd|out|string|invalid|int |int3|trap|main|in)/g, '<b style=\'color:red\'>$1</b>');
                    x = x.replace(/nop/g, '<b style=\'color:blue\'>nop</b>');
            */
            pStr = pStr.replace(/(reloc|class|method|var|sym|fcn|str|imp|loc)\.([^:<(\\\/ \|\])\->]+)/g, '<a href=\'javascript:r2ui.seek("$1.$2")\'>$1.$2</a>');
        }
        pStr = pStr.replace(/0x([a-zA-Z0-9]+)/g, '<a href=\'javascript:r2ui.seek("0x$1")\'>0x$1</a>');
        // registers
        if (R2API.backward) {
            R2API.prev_curoff = curoff;
            R2API.prev_lastoff = lastoff;
        } else {
            R2API.next_curoff = curoff;
            R2API.next_lastoff = lastoff;
            if (!R2API.prev_curoff) {
                R2API.prev_curoff = R2API.next_curoff;
            }
        }
        return pStr;
    };


    disableUtf8(){
        this.cmd('e scr.utf8=false');
    }

};


// async helper
function asyncLoop(iterations:number, func:any, callback:any) {
    let index:number = 0;
    let done:boolean = false;
    const loop:any = {
        next: function() {
            if (done) {
                return;
            }

            if (index < iterations) {
                index++;
                func(loop);

            } else {
                done = true;
                callback();
            }
        },

        iteration: function() {
            return index - 1;
        },

        break: function() {
            done = true;
            callback();
        }
    };
    loop.next();
    return loop;
}

if (typeof (module) !== 'undefined') {
    module.exports = function(r) {
        if (typeof (r) == 'function') {
            R2API.hascmd = r;
        } else {
            R2API.hascmd = r.cmd;
        }
        return R2API;
    };
}

