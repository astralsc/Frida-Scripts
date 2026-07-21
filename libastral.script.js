Interceptor.attach(Process.getModuleByName("libc.so").findExportByName('getaddrinfo'), {
    onEnter(args) {
        args[0].writeUtf8String('127.0.0.1') // Host
        args[1].writeUtf8String('9339') // Port
    }
})