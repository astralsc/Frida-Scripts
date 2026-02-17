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
