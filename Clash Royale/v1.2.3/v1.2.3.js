{
const Host = '127.0.0.1';
const Port = '9339';

Interceptor.attach(Process.getModuleByName("libc.so").findExportByName('getaddrinfo'), {
    onEnter(args) {
        const arg0 = args[0];
        const arg1 = args[1];
        const AskForHost = arg0.readUtf8String();
        const AskForPort = arg1.readUtf8String();

        console.log(`${AskForHost}:${AskForPort} > ${Host}:${Port}!`);      

        arg0.writeUtf8String(Host);
        arg1.writeUtf8String(Port);
    }
});
}

{
/*
This script facilitates reverse engineering by logging the bytestream functions so you can see packet structure easily and if your values are going in correctly.

It also hooks onto the Debugger:: functions so you can see crash errors or warns such as "LogicClientHome::getSpellAt index out of bounds"
*/
const libg = {
    init() {
        libg.module = Process.findModuleByName("libg.so")
        libg.base = libg.module.base

        libg.add = function(x) {return libg.base.add(x)}
    }
}
const libc = {
    init() {
        libc.module = Process.findModuleByName("libc.so")
        libc.base = libc.module.base

        libc.getExport = function(x) {return libc.module.getExportByName(x)}
    }    
}
libg.init()
libc.init()

const Offsets = { // Offsets are currently for Clash Royale v1.2.3
    Debugger: {
        warning: 0x1707C0+1,
        error:  0x1709C4+1,
    },
    Bytestream: {
        readVInt:            0x1704AC+1,
        readInt:             0x16FF64+1,
        readBoolean:         0x16FE64+1,
        readString:          0x16FAE8+1,
        readBytes:           0x1701D4+1,
        readShort:           0x16FFB0+1,
        readByte:            0x16FFA0+1,
        readStringReference: 0x16FCD8+1,
    }
}

const Utils = {
    arrayBufferToArray: function(buffer) {
        return Array.from(new Uint8Array(buffer))
    },
    isBoolean: function(x) {return x ? true : false},
    decodeString: function(src) {
        let len = src.add(4).readInt();
        if (len >= 8) {
            return src.add(8).readPointer().readUtf8String(len);
        }
        return src.add(8).readUtf8String(len)
    },
    decodeBytes: function(src, len) { 
        return src.add(8).readByteArray(len)
    },
    decodeBoolean: function(src) { 
        return src.add(8).toInt32()
    },
    handleRetval: function(name, retval, bytesize) {
        try {
            if (retval.isNull()) return null;
            if (name === ("readStringReference")) {
                return retval.readUtf8String();
            } else if (name === ("readString")) {
                return Utils.decodeString(retval)
            } else if (name === ("readBytes")) {
                const bytes = Utils.decodeBytes(retval, bytesize.toInt32())
                return Utils.arrayBufferToArray(bytes)
            } else if (name.includes("Long")) {
                return [retval.toInt64(), retval.add(Process.pointerSize).toInt64()]
            } else if (name === "readBoolean") {
                return Utils.decodeBoolean(retval)
            } else {
                return retval.toInt32();
            }
        } catch (e) {
            console.error(`There was an error decoding [Bytestream::${name}]. Error message: ${e.message}`)
        }
    }
};

const Logger = {
    print(x) {console.log(x)},
    warning(x) {console.warn(x)},
    error(x) {console.error(x)}
}

const SetupDebugger = {
    init() {
        for (const logoffset in Offsets.Debugger) {
            Interceptor.attach(libg.add(Offsets.Debugger[logoffset]), {
                onEnter(args) {
                    let msg = args[0].readUtf8String()
                    Logger[logoffset](`[Debugger::${logoffset}]>> ${msg}`)
                }
            })
        }
    }
}

const SetupReadFunctions = {
    init() {
        for (const [funcName, offset] of Object.entries(Offsets.Bytestream)) {

            Interceptor.attach(libg.add(Offsets.Bytestream[funcName]), {
                onEnter(args) {
                    if (funcName === "readBytes") {
                        this.len = args[1];
                    }
                },
                onLeave(retval) {
                    const needsSize = funcName === "readBytes"

                    const val = needsSize
                        ? Utils.handleRetval(funcName, retval, this.len)
                        : Utils.handleRetval(funcName, retval);

                    const bytestreamLog = function(name, msg) {
                        console.log(`[Bytestream::${name}]>> ${msg}`)
                    }

                    if (funcName === "readBoolean") {
                        bytestreamLog(funcName, Utils.isBoolean(val));
                        return;
                    }

                    bytestreamLog(funcName, val)
                }
            });
        }
    }
}

libg.init()
libc.init()

SetupDebugger.init()
SetupReadFunctions.init()
        
console.log("Script initialized. Happy Reverse Engineering!")
}
