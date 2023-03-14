(function() {
    var VERSION = 0;

    function iterateHash(data, key, count) {
        data = dcodeIO.ByteBuffer.concat([data, key]).toArrayBuffer();
        return Internal.crypto.hash(data).then(function(result) {
            if (--count === 0) {
                return result;
            } else {
                return iterateHash(result, key, count);
            }
        });
    }

    function shortToArrayBuffer(number) {
        return new Uint16Array([number]).buffer;
    }

    function getEncodedChunk(hash, offset) {
        var chunk =  ((hash[offset]&0xff)  * Math.pow(2,32) +
            (hash[offset+1]&0xff) * Math.pow(2,24) +
            (hash[offset+2]&0xff) * Math.pow(2,16) +
            (hash[offset+3]&0xff) * Math.pow(2,8) +
            (hash[offset+4]&0xff) ) % 100000;
        var s = chunk.toString();
        while (s.length < 5) {
            s = '0' + s;
        }
        return s;
    }

    function getDisplayStringFor(key) {
       var ouput =new Uint8Array(key);
        return getEncodedChunk(ouput, 0) +
            getEncodedChunk(ouput, 5) +
            getEncodedChunk(ouput, 10) +
            getEncodedChunk(ouput, 15) +
            getEncodedChunk(ouput, 20) +
            getEncodedChunk(ouput, 25);
    }

    libsignal.FingerprintGenerator = function(iterations) {
        this.iterations = iterations;
    };
    libsignal.FingerprintGenerator.prototype = {
        createFor: function( localIdentityKey, remoteIdentityKey) {
            if (
                !(localIdentityKey instanceof ArrayBuffer) ||
                !(remoteIdentityKey instanceof ArrayBuffer)) {

              throw new Error('Invalid arguments');
            }

            return Promise.all([
                getDisplayStringFor( localIdentityKey),
                getDisplayStringFor( remoteIdentityKey)
            ]).then(function(fingerprints) {
                return fingerprints.sort().join('');
            });
        }
    };

})();

