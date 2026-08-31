var base = Process.getModuleByName("libcocos2dcpp.so").base;

// This script basically replaces the world level screen with the normal GD level screen
let levelScreenToNormal = 1 // 0 = World level screen, 1 = Normal GD level screen 
if (levelScreenToNormal === 1) {
    const WorldSelectLayer_create = base.add(0x71BCB0);
    const LevelSelectLayer_create = new NativeFunction(
        base.add(0x5CE884),
        'pointer',
        ['pointer']
    );

    Interceptor.replace(WorldSelectLayer_create, new NativeCallback(function (self) {
        return LevelSelectLayer_create(self);
    }, 'pointer', ['pointer']));
}

// This script add some placeholder pages for Versus and The Map to prevent crashes from happening
const MultiplayerLayer__create = base.add(0x76AD04);
const MapSelectLayer__scene = base.add(0x739608);
const FixMenu  = new NativeFunction(
    base.add(0x5ED418),
    'pointer',
    ['pointer']
);

Interceptor.replace(MultiplayerLayer__create, new NativeCallback(function (self) {
    return FixMenu(self);
}, 'pointer', ['pointer']));
const MoreVideoOptionsLayer__onClose = base.add(0x5E58DC);
const LeaderboardsLayer__onBack = new NativeFunction(
    base.add(0x624C88),
    'pointer',
    ['pointer']
);
Interceptor.replace(MoreVideoOptionsLayer__onClose, new NativeCallback(function (self) {
    return LeaderboardsLayer__onBack(self);
}, 'pointer', ['pointer']));

// The Map
Interceptor.replace(MapSelectLayer__scene, new NativeCallback(function (self) {
    return new NativeFunction(
    base.add(0x76ADB8),
    'pointer',
    ['pointer']
)(self);
}, 'pointer', ['pointer']));
const getUGV = base.add(0x4817BC);
Interceptor.attach(getUGV, {
    onLeave(retval) {
        retval.replace(1);
    }
});
const onAdventureMap = base.add(0x52F3F0);
Interceptor.attach(onAdventureMap, {
    onEnter(args) {},
    onLeave(retval) {}
});
