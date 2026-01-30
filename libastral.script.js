const Host = '127.0.0.1';
const Port = '9339';

const libc = Process.getModuleByName("libc.so");
const getaddrinfo = libc.findExportByName('getaddrinfo');

console.log("[*] Script executed!");

Interceptor.attach(getaddrinfo, {
    onEnter(args) {
        if (args[0].isNull()) return;
        if (args[1].isNull()) return;

        const arg0 = args[0];
        const arg1 = args[1];
        const AskForHost = arg0.readUtf8String();
        const AskForPort = arg1.readUtf8String();

        console.log(`Redirected ${AskForHost}:${AskForPort} to ${Host}:${Port}!`);      

        arg0.writeUtf8String(Host);
        arg1.writeUtf8String(Port);
    }
});
