const Host = '127.0.0.1'; // CR 6.256 doesn't like Local IPS, so use Public IP
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
            Interceptor.replace(base.add(0xA03158), new NativeCallback(function() {
                console.warn("[+][PepperCrypto::secretbox_open] Skipped decryption");
                return 1;
            }, 'int', []));
        }
        catch (e) {
            console.warn("[+] PepperCrypto::secretbox_open is already skipped! ", e)
        }
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
