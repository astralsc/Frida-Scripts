const Host = '10.0.2.2';
const Port = '9339';

var base = Process.getModuleByName("libg.so").base;
const libc = Process.getModuleByName("libc.so");
const getaddrinfo = libc.findExportByName('getaddrinfo');
const loadoffset = 0xA0C3BC;
const addr = base.add(loadoffset);
const original = addr.readByteArray(4);

const PepperKiller = {
    init() {
        try {
            Interceptor.replace(base.add(0xA03158), new NativeCallback(function() { // PepperCrypto::secretbox_open
                console.warn("[+][PepperCrypto::secretbox_open] Skipped decryption");
                return 1;
            }, 'int', []));
        }
        catch (e) {
            console.warn("[+] PepperCrypto::secretbox_open is already skipped! ", e)
        }
        Interceptor.attach(base.add(0xA03E90), { // Messaging::sendPepperAuthentication
            onEnter(args) {
                this.messaging = args[0];
                const ptr = this.messaging.add(24);
                console.warn("[+][PepperState::State][1] Pepper State Is", ptr.readU32(this.messaging.add(24)));
                ptr.writeU32(5);
                //args[1] = args[2]; // CRASH
                console.warn("[+][PepperState::State][2] Pepper State Is", ptr.readU32(this.messaging.add(24)));

            },
            onLeave(retval) {
                const ptr = this.messaging.add(24);
                ptr.writeU32(5);
                console.warn("[+][PepperState::State][3] Pepper State Is", ptr.readU32(this.messaging.add(24)));
            }
        });
        Interceptor.attach(base.add(0xA03FB4), function() { // Messaging::encryptAndWrite
            this.context.w0 = 0x2774; // not tested
            console.warn("[+][PepperCrypto::secretbox_open] Skipped encryption");
        });
    }
}

Interceptor.attach(getaddrinfo, {
    onEnter(args) {
        this.host = Memory.allocUtf8String(Host);
        args[0] = this.host;
        this.port = Memory.allocUtf8String(Port);
        args[1] = this.port;

        // Initialization
        {
            PepperKiller.init()
        }
        
        Memory.protect(addr, 0x1000, 'rwx');
        addr.writeByteArray(original);

        setTimeout(() => {
            addr.writeU8(0xA8);
            addr.add(1).writeU8(0x00);
            addr.add(2).writeU8(0x80);
            addr.add(3).writeU8(0x52);
        }, 1000);
    }
});

// LogicTime::isClientOffSync (Battle patch)
{
    Interceptor.replace(base.add(0x9D8E68), new NativeCallback(function (a1) {
        console.log('LogicTime::isClientOffSync killed!');
        return 0;
    }, 'int', ['pointer']));
}
