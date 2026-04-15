const Host = '10.0.2.2';
const Port = '9339';

var base = Process.getModuleByName("libg.so").base;
const libc = Process.getModuleByName("libc.so");
const getaddrinfo = libc.findExportByName('getaddrinfo');
const loadoffset = 0x1111E58;
const addr = base.add(loadoffset);
const original = addr.readByteArray(4);

const fMessaging_Send = new NativeFunction(base.add(0x1108514), "void", ["pointer", "pointer"]);

const PepperKiller = {
    init() {
        try {
            Interceptor.replace(base.add(0x1109180), new NativeCallback(function() {
                console.warn("[+][PepperCrypto::secretbox_open] Skipped decryption");
                return 1;
            }, 'int', []));
        }
        catch (e) {
            console.warn("[+] PepperCrypto::secretbox_open is already skipped!", e);
        }

        try {
            Interceptor.replace(base.add(0x94c810), new NativeCallback(function() {
                console.warn("[+][sub_94C810] Skipped");
            }, "void", []));
        }
        catch (e) {
            console.warn("[+] sub_94C810 is already skipped!", e);
        }

        try {
            Interceptor.replace(base.add(0x1109630), new NativeCallback(function(a1, a2) {
                console.warn("[+][Messaging::sendPepperAuthentication] Replaced â€” forcing pepper state to 5");
                a1.add(24).writeU8(5);
                fMessaging_Send(a1, a2);
            }, "pointer", ["pointer", "pointer"]));
        }
        catch (e) {
            console.warn("[+] sendPepperAuthentication is already replaced!", e);
        }
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
            PepperKiller.init();
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
