#!/usr/bin/env node

(function(root) {
    "use strict";

    /*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
    /*global document, window, escape, unescape, module, require, Uint32Array */

    const MAC = require('./MAC_encrypt.js');

    test(
        'MAC_encrypt: buildFrame ReSync (0x id)',
        () =>
        {
            var type = '0x6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var timestamp = '1030.377292';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var msb = "";
            var lsb = "";            
            var payload = Buffer.from('000074086d40000000013884000075083a44e20c00003208', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';

            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tmac, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.buildFrame().toString('hex')).toBe('06e0740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b0000');
        }
    );

    test(
        'MAC_encrypt: buildFrame Sync (0x id)',
        () =>
        {
            var type = '0x697';
            var name = 'FVSyncFrame_BCM_FD';
            var timestamp = '1000.000000';
            var ecuName = 'PWT';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100c896c2', 'hex');
            var msb = "740100c8";
            var lsb = "96c2";
            var payload = "";
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';
            
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tmac, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.buildFrame().toString('hex')).toBe('0697740100c896c20000');
        }
    );

    test(
        'MAC_encrypt: buildFrame SC_FD (0x type)',
        () =>
        {
            var type = '0x453';
            var name = 'USM_A101SC_FD';
            var timestamp = '1000.000000';
            var ecuName = 'USM';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('000005d', 'hex');
            var lsb = Buffer.from('be4e', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            var tMAC = '';
            
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.buildFrame().toString('hex')).toBe('045300045308f1171567a02af6000005be4e');
        }
    );

    test(
        'MAC_encrypt: buildFrame ReSync (no 0x type)',
        () =>
        {
            var type = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var timestamp = '1000.000000';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var msb = '';
            var lsb = '';
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';
            
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.buildFrame().toString('hex')).toBe('06e0740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b0000');
        }
    );

    test(
        'MAC_encrypt: buildFrame Sync (no 0x type)',
        () =>
        {
            var type = '697';
            var name = 'FVSyncFrame_BCM_FD';
            var timestamp = '1000.000000';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100c896c2', 'hex');
            var msb = '';
            var lsb = '';
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';
            
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.buildFrame().toString('hex')).toBe('0697740100c896c20000');
        }
    );

    test(
        'MAC_encrypt: buildFrame SC_FD (no 0x type)',
        () =>
        {
            var type = '453';
            var name = 'USM_A101SC_FD';
            var timestamp = '1000.000000';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('000005d', 'hex');
            var lsb = Buffer.from('be4e', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            var tMAC = '';
            
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.buildFrame().toString('hex')).toBe('045300045308f1171567a02af6000005be4e');
        }
    );

    test(
        'MAC_encrypt: cipher ReSync frame (0x id)',
        () =>
        {
            var type = '0x6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var timestamp = '1000.000000';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var msb = Buffer.from('000005d', 'hex');
            var lsb = Buffer.from('be4e', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('2f93d02c5c218cf565dfe7a2ab0f87f4');
        }
    );

    test(
        'MAC_encrypt: cipher ReSync frame (no 0x type)',
        () =>
        {
            var type = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var timestamp = '1000.000000';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100b9e2c7000000674575000005d4bdc6000009482ea7000000000040000011998d8b', 'hex');
            var msb = '';
            var lsb = '';
            var payload = '';
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('2f93d02c5c218cf565dfe7a2ab0f87f4');
        }
    );

    test(
        'MAC_encrypt: cipher Sync frame (0x type)',
        () =>
        {
            var type = '0x697';
            var name = 'FVSyncFrame_BCM_FD';
            var timestamp = '1000.000000';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100c896c2', 'hex');
            var msb = Buffer.from('740100c8', 'hex');
            var lsb = Buffer.from('96c2', 'hex');
            var payload = '';
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('d1f55dadfb95d26e5304b5f1549479b9');
        }
    );

    test(
        'MAC_encrypt: cipher Sync frame (no 0x type)',
        () =>
        {
            var type = '697';
            var name = 'FVSyncFrame_BCM_FD';
            var timestamp = '1000.000000';
            var ecuName = 'BCM';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100c896c2', 'hex');
            var msb = Buffer.from('740100c8', 'hex');
            var lsb = Buffer.from('96c2', 'hex');
            var payload = '';
            var pad = Buffer.from('0000', 'hex');
            var tMAC = '';
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);            
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('d1f55dadfb95d26e5304b5f1549479b9');
        }
    );

    test(
        'MAC_encrypt: cipher SC_FD frame (0x type)',
        () =>
        {
            var type = '0x453';
            var name = 'USM_A101SC_FD';
            var timestamp = '1000.000000';
            var ecuName = 'USM';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('000005d4', 'hex');
            var lsb = Buffer.from('be4e', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            var tMAC = '';

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('0b2c4e4388cd84b64ac3f49afa17ff4f');
        }
    );

    test(
        'MAC_encrypt: cipher SC_FD frame (no 0x type)',
        () =>
        {
            var type = '453';
            var name = 'USM_A101SC_FD';
            var timestamp = '1000.000000';
            var ecuName = 'USM';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('000005d4be4e', 'hex');
            var msb = Buffer.from('000005d4', 'hex');
            var lsb = Buffer.from('be4e', 'hex');
            var payload = Buffer.from('00045308f1171567a02af6', 'hex');
            var pad = Buffer.from('000000', 'hex');
            var tMAC = '';

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            //MAC_encrypt(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad)
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('0b2c4e4388cd84b64ac3f49afa17ff4f');
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered SC_FD frame',
        () =>
        {
            //  This is the Sync Frame of the Domain master ECU preceding the frame for which the MAC is computed
            //    0.035032 CANFD   3 Rx        697  FVSyncFrame_BCM_FD               1 0 a 16 00 00 05 d2 c4 86 00 00 34 e9 95 71 29 6b ee c1
            //    <------> <--->   ^ ^         <->  <---------------->                     D  <---------> <---> <---> <--------------------->
            //   TimeStamp  Net   /  \         Fr     Frame Name                           L      MSB      LSB   Pad            tMAC Sync
            //               NetId   CommWay   Id                                          C  <--- Ful FV ---->
            //
            // And the frame to rebuild for computing MAC
            //    0.035573 CANFD   3 Rx        5e7  BCM_A116SC_FD                    1 0 c 24 00 05 e7 07 72 40 f8 f9 00 01 3c 00 00 00 c4 86 e2 ad cc eb 81 92 e8 f4
            //    <------> <--->   ^ ^         <->  <----------->                          D  <------------------------------> <------> <---> <--------------------->  
            //   TimeStamp  Net   /  \         Fr    Frame Name                            L              Payload                 PAD    LSB             tMAC  
            //              Net ID   CommWay   ID                                          C                                                                          
            var timestamp = '0.035573';
            var type = '5e7';
            var name = 'BCM_A116SC_FD';
            var ecuName = 'BCM';
            var dlc = "24";
            var fv = Buffer.from('c486', 'hex');
            var msb = Buffer.from('000005d2' ,'hex');
            var lsb = Buffer.from('c486' ,'hex');
            var payload = Buffer.from('0005e7077240f8f900013c', 'hex');
            var pad = Buffer.from('000000', 'hex');
            var tMAC = Buffer.from('e2adcceb8192e8f4','hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('e2adcceb8192e8f44220f3b961b64a6e');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (CDM)',
        () =>
        {
            //   0.115460 CANFD   3 Rx        69d  FVSyncFrame_CDM_FD               1 0 a 16 00 00 09 43 06 4b 00 00 12 4f 49 e3 a4 23 4f 96
            //   <------> <--->   ^ ^         <->  <---------------->                     <> <---------> <---> <---> <--------------------->
            //  TimeStamp  Net   /   \       FrId     Frame Name                          D      MSB      LSB   Pad            tMAC
            //            Name NetId  Comm Way                                            L  <--------------->
            //                                                                            C       Full FV
            var timestamp = '0.115460';
            var type = '69d';
            var name = 'FVSyncFrame_CDM_FD';
            var ecuName = 'FVSyncFrame_CDM_FD';
            var dlc = "16";
            var fv = Buffer.from('00000943064b', 'hex');
            var msb = Buffer.from('00000943', 'hex');
            var lsb = Buffer.from('064b', 'hex');
            var payload = '';
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('124f49e3a4234f96', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('124f49e3a4234f96b30c9412ed5df3a6');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));            
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered ReSync frame (CDM)',
        () =>
        {
            // 1629.949878 CANFD   3 Rx        6e0  FVReSyncFrame_ATCU_FD            1 0 e 48 74 01 00 ca 84 b4 00 00 05 d8 8c 22 00 00 09 56 99 dc 00 00 02 09 69 af 00 00 00 00 00 00 00 00 11 b3 f1 d6 00 00 00 00 2f 30 8d f6 27 2a f5 db
            // <---------> <--->   ^  ^        <->  <------------------->                  <> <---------------------------------------------------------------------------------------------------------> <---------> <--------------------->
            //  TimeStamp   Net   /   \      Frame          name                           D  <---------------> <---------------> <---------------> <---------------> <---------------> <--------------->    
            //                   /     \      ID                                           L        FV1               FV2                 FV3               FV4               FV5               FV6           PAD                tMAC
            //                NetID     Comm way                                           C
            var timestamp = '1629.949878';
            var ecuName = "ATCU";
            var dlc = "48";
            var type = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var fv = Buffer.from('740100ca84b4000005d88c220000095699dc0000020969af000000000000000011b3f1d6', 'hex');
            var pad = Buffer.from('00000000', 'hex');
            var tMAC = Buffer.from('2f308df6272af5db', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, undefined, undefined, undefined, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('2f308df6272af5db7a1a62257c86392a');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));            
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered SC_FD frame',
        () =>
        {
            //  This is the Sync Frame of the Domain master ECU preceding the frame for which the MAC is computed
            //    0.035032 CANFD   3 Rx        697  FVSyncFrame_BCM_FD               1 0 a 16 00 00 05 d2 c4 86 00 00 34 e9 95 71 29 6b ee c1
            //    <------> <--->   ^ ^         <->  <---------------->                     D  <---------> <---> <---> <--------------------->
            //   TimeStamp  Net   /  \         Fr     Frame Name                           L      MSB      LSB   Pad            tMAC Sync
            //               NetId   CommWay   Id                                          C  <--- Ful FV ---->
            //
            // And the frame to rebuild for computing MAC
            //    0.035573 CANFD   3 Rx        5e7  BCM_A116SC_FD                    1 0 c 24 00 05 e7 07 72 40 f8 f9 00 01 3c 00 00 00 c4 86 e2 ad cc eb 81 92 e8 f4
            //    <------> <--->   ^ ^         <->  <----------->                          D  <------------------------------> <------> <---> <--------------------->  
            //   TimeStamp  Net   /  \         Fr    Frame Name                            L              Payload                 PAD    LSB             tMAC  
            //              Net ID   CommWay   ID                                          C                                                                          
            var timestamp = '0.035573';
            var type = '5e7';
            var name = 'BCM_A116SC_FD';
            var ecuName = "BCM";
            var dlc = '24';
            var fv = Buffer.from('000005d2c486', 'hex');
            var msb = Buffer.from('000005d2' ,'hex');
            var lsb = Buffer.from('c486' ,'hex');
            var payload = Buffer.from('0005e7077240f8f900013c', 'hex');
            var pad = Buffer.from('000000', 'hex');
            var tMAC = Buffer.from('e2adcceb8192e8f4','hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
	    var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('e2adcceb8192e8f44220f3b961b64a6e');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (CDM)',
        () =>
        {
            //   0.115460 CANFD   3 Rx        69d  FVSyncFrame_CDM_FD               1 0 a 16 00 00 09 43 06 4b 00 00 12 4f 49 e3 a4 23 4f 96
            //   <------> <--->   ^ ^         <->  <---------------->                     <> <---------> <---> <---> <--------------------->
            //  TimeStamp  Net   /   \       FrId     Frame Name                          D      MSB      LSB   Pad            tMAC
            //            Name NetId  Comm Way                                            L  <--------------->
            //                                                                            C       Full FV
            var type = '69d';
            var name = 'FVSyncFrame_CDM_FD';
            var timestamp = '0.115460';
            var ecuName = 'CDM';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('00000943064b', 'hex');
            var msb = Buffer.from('00000943', 'hex');
            var lsb = Buffer.from('064b', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var payload = '';            
            var tMAC = Buffer.from('124f49e3a4234f96', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(cipheredFrame.toString('hex')).toBe('124f49e3a4234f96b30c9412ed5df3a6');
            expect(cipheredFrame.subarray(0,8).toString('hex')).toBe(tMAC.toString('hex'));            
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered ReSync frame (CDM)',
        () =>
        {
            // 1629.949878 CANFD   3 Rx        6e0  FVReSyncFrame_ATCU_FD            1 0 e 48 74 01 00 ca 84 b4 00 00 05 d8 8c 22 00 00 09 56 99 dc 00 00 02 09 69 af 00 00 00 00 00 00 00 00 11 b3 f1 d6 00 00 00 00 2f 30 8d f6 27 2a f5 db
            // <---------> <--->   ^  ^        <->  <------------------->                  <> <---------------------------------------------------------------------------------------------------------> <---------> <--------------------->
            //  TimeStamp   Net   /   \      Frame          name                           D  <---------------> <---------------> <---------------> <---------------> <---------------> <--------------->    
            //                   /     \      ID                                           L        FV1               FV2                 FV3               FV4               FV5               FV6           PAD                tMAC
            //                NetID     Comm way                                           C
            var type = '6e0';
            var name = 'FVReSyncFrame_ATCU_FD';
            var timestamp = '1629.949878';
            var ecuName = 'ATCU';
            var dlc = Buffer.from('48', 'hex');
            var fv = Buffer.from('740100ca84b4000005d88c220000095699dc0000020969af000000000000000011b3f1d6', 'hex');
            var msb = '';
            var lsb = '';
            var payload = '';
            var pad = Buffer.from('00000000', 'hex');
            var tMAC = Buffer.from('2f308df6272af5db', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
            expect(mac.buildFrame().toString('hex')).toBe('06e0740100ca84b4000005d88c220000095699dc0000020969af000000000000000011b3f1d600000000');
            expect(cipheredFrame.toString('hex')).toBe('2f308df6272af5db7a1a62257c86392a');
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered ReSync frame (CDM)',
        () =>
        {
            
            // 939.465237 CANFD   3 Rx        6e4  FVReSyncFrame_ADAS_FD            48 740100ca48130000006873fe000005d6d85b0000094e554b000000000040000011a4b401 00000000 7b85a2c6a8264b8e
            var type = '6e4';
            var name = 'FVReSyncFrame_ADAS_FD';
            var timestamp = '939.465237';
            var ecuName = 'ADAS';
            var dlc = Buffer.from('48', 'hex');
            var fv = Buffer.from('740100ca48130000006873fe000005d6d85b0000094e554b000000000040000011a4b401', 'hex');
            var msb = '';
            var lsb = '';
            var payload = '';            
            var pad = Buffer.from('00000000', 'hex');
            var tMAC = Buffer.from('7b85a2c6a8264b8e', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (CDM)',
        () =>
        {
            // 939.468032 CANFD   3 Rx        698  FVSyncFrame_PWT_FD               16 740100c94816 0000 6c777c2d9e11935f

            var type = '698';
            var name = 'FVSyncFrame_PWT_FD';
            var timestamp = '939.468032';
            var ecuName = 'PWT';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100c94816', 'hex');
            var msb = '';
            var lsb = '';
            var payload = '';
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('6c777c2d9e11935f', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered ReSync frame (ADAS)',
        () =>
        {
            
            // 939.465237  6e4  FVReSyncFrame_ADAS_FD            48 740100ca48130000006873fe000005d6d85b0000094e554b000000000040000011a4b401 00000000 7b85a2c6a8264b8e
            var type = '6e4';
            var name = 'FVReSyncFrame_ADAS_FD';
            var timestamp = '939.468032';
            var ecuName = 'ADAS';
            var dlc = Buffer.from('48', 'hex');
            var fv = Buffer.from('740100ca48130000006873fe000005d6d85b0000094e554b000000000040000011a4b401', 'hex');
            var msb = '';
            var lsb = ''
            var payload = ''
            var pad = Buffer.from('00000000', 'hex');
            var tMAC = Buffer.from('7b85a2c6a8264b8e', 'hex');

            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
            expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (CDM)',
        () =>
        {
            // 939.468032 CANFD   3 Rx        698  FVSyncFrame_PWT_FD               16 740100c94816 0000 6c777c2d9e11935f
            var type = '698';
            var name = 'FVSyncFrame_PWT_FD';
            var timestamp = '939.468032';
            var ecuName = 'PWT';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('740100c94816', 'hex');
            var msb = Buffer.from('740100c9' ,'hex');
            var lsb = Buffer.from('4816' ,'hex');
            var payload = '';
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('6c777c2d9e11935f', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );


    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (CDM)',
        () =>
        {
            // 747.241737 CANFD  698  FVSyncFrame_PWT_FD   16 740100c93904 0000 cb82b84d6a543ce1
            // 747.339620        8c  ECM_A07SC_FD          48 000074086680000000013880000075084584e20c00003208 0000000000000000000000000000 390f 486cc5870a620948
            var type = '0x8c';
            var name = 'ECM_A07SC_FD';
            var timestamp = '747.339620';
            var ecuName = 'ECM';
            var dlc = Buffer.from('48', 'hex');
            var fv = Buffer.from('740100c9390f', 'hex');
            var msb = Buffer.from('740100c9' ,'hex');
            var lsb = Buffer.from('390f' ,'hex');
            var payload = Buffer.from('000074086680000000013880000075084584e20c00003208', 'hex');
            var pad = Buffer.from('0000000000000000000000000000', 'hex');
            var tMAC = Buffer.from('486cc5870a620948', 'hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, ecuName, dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );

    
    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (ECM) (type 0x)',
        () =>
        {
            // FVSyncFrame_PWT_FD__PT_FD        1 0 a 16 b3430eeea15f 0000  f0c9755c6e869129
            var type = '0x698';
            var name = 'FVSyncFrame_PWT_FD__PT_FD';
            var timestamp = '1030.377292';
            var dlc = Buffer.from('48', 'hex');
            var fv = Buffer.from('b3430eeea15f', 'hex');
            var msb = Buffer.from('b3430eee' ,'hex');
            var lsb = Buffer.from('a15f' ,'hex');
            var payload = Buffer.from('b3430eeea15f', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('f0c9755c6e869129','hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, 'ECM', dlc, tMAC, fv, payload, msb, lsb, pad);
            var builtFrame = mac.buildFrame();
            var cipheredFrame = mac.encrypt_Frame(mac.buildFrame(), bufferKey);
	    expect(builtFrame.toString('hex')).toBe('0698b3430eeea15f0000');
	    expect(cipheredFrame.toString('hex')).toBe('f0c9755c6e86912982fb4a5359d35812');
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );
    test(
        'MAC_encrypt: verify MAC for ciphered ECM (type 0x)',
        () =>
        {
            // FVSyncFrame_PWT_FD__PT_FD        1 0 a 16 b3430eeea15f 0000  f0c9755c6e869129
            // 8c  ECM_A07SC_FD__PT_FD              1 0 e 48 00007408b8c00000000138800000750859c4e20000003208 0000000000000000000000000000 a161 3d26c69b00c07740
            var type = '8c';
            var name = 'ECM_A07SC_FD';
            var timestamp = '1030.377292';
            var dlc = Buffer.from('48', 'hex');
            var fv = Buffer.from('b3430eeea161', 'hex');
            var msb = Buffer.from('b3430eee' ,'hex');
            var lsb = Buffer.from('a161' ,'hex');
            var payload = Buffer.from('00007408b8c00000000138800000750859c4e20000003208', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('3d26c69b00c07740','hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, 'ECM', dlc, tMAC, fv, payload, msb, lsb, pad);
            var builtFrame = mac.buildFrame();
            var cipheredFrame = mac.encrypt_Frame(builtFrame, bufferKey);
	    expect(builtFrame.toString('hex')).toBe('008c00007408b8c00000000138800000750859c4e20000003208b3430eeea161');
	    expect(cipheredFrame.toString('hex')).toBe('3d26c69b00c077403506906eeb2ac854');
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );
    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (ECM) (type 0x)',
        () =>
        {
            // 1030.368743 698  FVSyncFrame_PWT_FD               16 740100c972b2 0000 f6312824a30518d6
            // 1030.377292  8c  ECM_A07SC_FD                     48 000074086d40000000013884000075083a44e20c00003208 0000000000000000000000000000 72b3 7a0a25690b86fda0

            var type = '0x8c';
            var name = 'ECM_A07SC_FD';
            var timestamp = '1030.377292';
            var dlc = Buffer.from('48', 'hex');
            var fv = Buffer.from('740100c972b3', 'hex');
            var msb = Buffer.from('740100c9' ,'hex');
            var lsb = Buffer.from('72b3' ,'hex');
            var payload = Buffer.from('000074086d40000000013884000075083a44e20c00003208', 'hex');
            var pad = Buffer.from('0000000000000000000000000000', 'hex');
            var tMAC = Buffer.from('7a0a25690b86fda0','hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, 'ECM', dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );

    test(
        'MAC_encrypt: verify MAC for ciphered Sync frame (PWT) #1 (type 0x)',
        () =>
        {
            //26.239422 CANFD   1 Rx        698  FVSyncFrame_PWT_FD__PT_FD        1 0 a 16 b3 43 0e ee ad 5b 00 00 03 e1 17 35 6c 6f c7 9b


            var type = '0x698';
            var name = 'FVSyncFrame_PWT_FD__PT_FD';
            var timestamp = '26.239422';
            var dlc = Buffer.from('16', 'hex');
            var fv = Buffer.from('b3430eeead5b', 'hex');
            var msb = Buffer.from('b3430eee' ,'hex');
            var lsb = Buffer.from('ad5b' ,'hex');
            var payload = Buffer.from('', 'hex');
            var pad = Buffer.from('0000', 'hex');
            var tMAC = Buffer.from('03e117356c6fc79b','hex');
            
            var bufferKey = Buffer.from('10357f020289ad8f512662ba988f1111', 'hex');
            var mac = new MAC(type, name, timestamp, 'ECM', dlc, tMAC, fv, payload, msb, lsb, pad);
	    expect(mac.verifyMac(bufferKey)).toBe(true);
        }
    );
    
})(this);

/*
 * vim: et:ts=4:sw=4:sts=4
 * -*- mode: JavaScript; coding: utf-8-unix; tab-width: 4 -*-
 */
