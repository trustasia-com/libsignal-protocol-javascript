/*
 * vim: ts=4:sw=4
 */

'use strict';
describe('NumericFingerprint', function() {
    this.timeout(5000);
    var ALICE_IDENTITY = [
        0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4,
        0x9c, 0xa7, 0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6,
        0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68
    ];
    var BOB_IDENTITY   = [
        0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde,
        0x97, 0x8d, 0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44,
        0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b
    ];
    var FINGERPRINT    = "098194662059693580801785814095969028954318816509279734058736";

    var alice = {
        identifier: '+14152222222',
        key: new Uint8Array(ALICE_IDENTITY).buffer
    };
    var bob = {
        identifier: '+14153333333',
        key: new Uint8Array(BOB_IDENTITY).buffer
    };
    var test = {
        identifier: '+14153333333',
        key: new Uint8Array([0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b]).buffer
    };

    it('returns the correct fingerprint', function(done) {
        var generator = new libsignal.FingerprintGenerator(1);
        generator.createFor(alice.key, bob.key
        ).then(function(fingerprint) {
            console.log(fingerprint.toString());
            assert.strictEqual(fingerprint, FINGERPRINT);
        }).then(done,done);
    });

    it ('alice and bob results match', function(done) {
        var generator = new libsignal.FingerprintGenerator(1024);
        Promise.all([
            generator.createFor(alice.key,  bob.key),
            generator.createFor(bob.key, alice.key)
        ]).then(function(fingerprints) {
            assert.strictEqual(fingerprints[0], fingerprints[1]);
        }).then(done,done);
    });

    it ('alice and !bob results mismatch', function(done) {
        var generator = new libsignal.FingerprintGenerator(1024);
        Promise.all([
            generator.createFor(alice.key, test.key),
            generator.createFor(bob.key, test.key)
        ]).then(function(fingerprints) {
            assert.notStrictEqual(fingerprints[0], fingerprints[1]);
        }).then(done,done);
    });

    it ('alice and mitm results mismatch', function(done) {
        var mitm   = libsignal.crypto.getRandomBytes(33);
        var generator = new libsignal.FingerprintGenerator(1024);
        Promise.all([
            generator.createFor(alice.key,  mitm),
            generator.createFor(bob.key,  alice.key)
        ]).then(function(fingerprints) {
            assert.notStrictEqual(fingerprints[0], fingerprints[1]);
        }).then(done,done);
    });
});
