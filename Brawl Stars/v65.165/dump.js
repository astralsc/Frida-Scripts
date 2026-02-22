const module = Process.findModuleByName("libg.so");
const base = module.base;

class LogicMath 
{
    static max(valueA, valueB) {
        if (valueA >= valueB) {
            return valueA;
        }
        return valueB;
    }
}

class PiranhaMessage {
    static encode(Message) { 
        return (new NativeFunction(Message.readPointer().add(16).readPointer(), "int", ["pointer"]))(Message); 
    }

    static decode(Message) { 
        return (new NativeFunction(Message.readPointer().add(24).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getServiceNodeType(Message) { 
        return (new NativeFunction(Message.readPointer().add(32).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getMessageType(Message) { 
        return (new NativeFunction(Message.readPointer().add(40).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getMessageTypeName(Message) { 
        return (new NativeFunction(Message.readPointer().add(48).readPointer(), "pointer", ["pointer"]))(Message); 
    }

    static getEncodingLength(Message) {
        return PiranhaMessage.getByteStream(Message).add(24).readInt();
    }

    static isClientToServerMessage(Message) {
        return (PiranhaMessage.getMessageType(Message) >= 10000 && PiranhaMessage.getMessageType(Message) < 20000) || PiranhaMessage.getMessageType(Message) === 30000;
    }

    static destruct(Message) { 
        return (new NativeFunction(Message.readPointer().add(56).readPointer(), "int", ["pointer"]))(Message); 
    }

    static getByteStream(Message) { 
        return Message.add(8);
    }
}

Interceptor.attach(base.add(0x76329C), { // MessageManager::receiveMessage
    onEnter(args) {
        this.message = args[1];
        this.type = PiranhaMessage.getMessageType(this.message);
        this.length = PiranhaMessage.getEncodingLength(this.message);
        let PayloadPtr = PiranhaMessage.getByteStream(this.message).add(56).readPointer();
        let payload = PayloadPtr.readByteArray(this.length);

        // here change this if statement to the message type you want to dump
        // 20103 = LoginFailedMessage, 20108 = KeepAliveMessage, 24109 = SectorHearbeatMessage
        if (![20103, 20108, 24109].includes(this.type)) {
            console.log("[MessageManager::receiveMessage] Received message with type:", this.type);
            console.log("Stream dump:", payload);
            console.log("Stream size:", this.length);
        }
    }
});
