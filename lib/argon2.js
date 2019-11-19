(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], function () {
            return (root.argon2 = factory());
        });
    } else {
        root.argon2 = factory();
    }
}(this, function () {
    'use strict';

    /**
     * @enum
     */
    var ArgonType = {
        Argon2d: 0,
        Argon2i: 1
    };

    var loadArgon2WrapperPromise;
    function loadScript(src) {
        return new Promise(function (resolve, reject) {
            if (typeof importScripts  === 'function') {
                try {
                  importScripts(src);
                  resolve();
                } catch (error) {
                  reject(error)
                }
            } else {
                var el = document.createElement("script");
                el.src = src;
                el.onload = function () { resolve(); };
                el.onerror = function (error) { reject('Error loading script: ' + error); };
                document.body.appendChild(el);
            }
        })
    }

    function allocateArray(strOrArr) {
        var arr = strOrArr instanceof Uint8Array || strOrArr instanceof Array ? strOrArr
            : Module.intArrayFromString(strOrArr);
        return Module.allocate(arr, 'i8', Module.ALLOC_NORMAL);
    }

    /**
     * Argon2 hash
     * @param {string} params.pass - password string
     * @param {string} params.salt - salt string
     * @param {number} [params.time=1] - the number of iterations
     * @param {number} [params.mem=1024] - used memory, in KiB
     * @param {number} [params.hashLen=24] - desired hash length
     * @param {number} [params.parallelism=1] - desired parallelism (will be computed in parallel only for PNaCl)
     * @param {number} [params.type=0] - hash type: argon2.ArgonType.Argon2d or argon2.ArgonType.Argon2i
     * @param {string} params.asmFileUrl - asm.js script exact location
     * @param {string} params.wasmFileUrl - argon2.wasm script exact location
     * @param {string} params.argon2FileUrl - argon2.min.js script exact location
     *
     * @return Promise
     *
     * @example
     *  argon2.hash({ pass: 'password', salt: 'somesalt' })
     *      .then(h => console.log(h.hash, h.hashHex, h.encoded))
     *      .catch(e => console.error(e.message, e.code))
     */

    var globalModuleIsFullyLoaded = null

    function argon2Hash(params) {
        // First we check if WebAssembly is supported by the browser or if a wasm file AND a argon2 file are passed.
        // If not we fallback on asm.js
        if (!global.WebAssembly || !params.wasmFileUrl || !params.argon2FileUrl) {
            return loadScript(params.asmFileUrl)
                .then(function () {
                    return calcHash(params);
                })
                .catch(function (error) {
                    throw new Error("Error loading argon2-asm.min.js: " + error);
                });
        }

        //WebAssembly is supported by the browser

        return new Promise(function (resolve, reject) {
            /**
             * argon2Hash method can be called many times. At the first call, global.Module is undefined.
             * So We instantiate the WASM Module and the JS wrapper.
             *
             * When we call the argon2Hash method for the second time, then we are not 100% sure that
             * everything is fully loaded and instantiated. So we recall the method 10ms later and stop the current process.
             */
            if (global.Module && !globalModuleIsFullyLoaded) {
                setTimeout(function () { argon2Hash(params).then(resolve).catch(reject) }, 10)
                return;
            }

            /**
             * If the WASM module and the JS wrapper are fully loaded and instantiated then there is no need
             * to load them again. We can directly tringger the key derivation.
             */
            if (global.Module && global.Module.wasmJSMethod === 'native-wasm' && globalModuleIsFullyLoaded) {
                if (!loadArgon2WrapperPromise) {
                    loadArgon2WrapperPromise = loadScript(params.argon2FileUrl)
                }
                loadArgon2WrapperPromise.then(function () {
                    setTimeout(function () { resolve(calcHash(params)) }, 10);
                })
                    .catch(function (error) {
                        reject("Error loading argon2.min.js (WASM already loaded): " + error);
                    });
                return
            }

            // Here WASM Module has not been instantiated yet.
            var KB = 1024 * 1024;
            var MB = 1024 * KB;
            var GB = 1024 * MB;
            var WASM_PAGE_SIZE = 64 * 1024;

            var totalMemory = (2 * GB - 64 * KB) / 1024 / WASM_PAGE_SIZE;
            var initialMemory = Math.min(Math.max(Math.ceil(params.mem * 1024 / WASM_PAGE_SIZE), 256) + 256, totalMemory);
            var wasmMemory = new WebAssembly.Memory({
                initial: initialMemory,
                maximum: totalMemory
            });

            global.Module = {
                wasmBinary: null,
                wasmJSMethod: 'native-wasm',
                asmjsCodeFile: params.asmFileUrl,
                wasmBinaryFile: params.wasmFileUrl,
                wasmMemory: wasmMemory,
                buffer: wasmMemory.buffer,
                TOTAL_MEMORY: initialMemory * WASM_PAGE_SIZE
            };

            var xhr = new XMLHttpRequest();
            xhr.open('GET', params.wasmFileUrl, true);
            xhr.responseType = 'arraybuffer';
            xhr.onload = function () {
                global.Module.wasmBinary = xhr.response;
                global.Module.postRun = function () {
                    /**
                     * We know that Wasm module and JS wrapper are fully loaded only
                     * when this postRun method is triggered for the first time.
                     */
                    globalModuleIsFullyLoaded = true;
                    return resolve(calcHash(params))
                }

                /**
                 * When we are sure that the WASM Module has been fully loaded then we can trigger the load of the JS wrapper.
                 * This is this trigger that will trigger the global.Module.postRun method which will trigger the key derivation.
                 */
                if (!loadArgon2WrapperPromise) {
                    loadArgon2WrapperPromise = loadScript(params.argon2FileUrl)
                }
                loadArgon2WrapperPromise.catch(function (error) {
                    reject("Error loading argon2.min.js (WASM already loaded): " + error);
                });
            };
            xhr.onerror = function () {
                reject("Error loading wasm " + params.cacheKey)
            };
            xhr.send(null);
        })
    }

    function calcHash(params) {
        var tCost = params.time || 1;
        var mCost = params.mem || 1024;
        var parallelism = params.parallelism || 1;
        var pwd = allocateArray(params.pass);
        var pwdlen = params.pass.length;
        var salt = allocateArray(params.salt);
        var saltlen = params.salt.length;
        var hash = Module.allocate(new Array(params.hashLen || 24), 'i8', Module.ALLOC_NORMAL);
        var hashlen = params.hashLen || 24;
        var encoded = Module.allocate(new Array(512), 'i8', Module.ALLOC_NORMAL);
        var encodedlen = 512;
        var argon2Type = params.type || ArgonType.Argon2d;
        var version = 0x13;
        var err;
        try {
            var res = Module._argon2_hash(tCost, mCost, parallelism, pwd, pwdlen, salt, saltlen,
                hash, hashlen, encoded, encodedlen, argon2Type, version);
        } catch (e) {
            err = e;
        }
        var result;
        if (res === 0 && !err) {
            var hashStr = '';
            var hashArr = new Uint8Array(hashlen);
            for (var i = 0; i < hashlen; i++) {
                var byte = Module.HEAP8[hash + i];
                hashArr[i] = byte;
                hashStr += ('0' + (0xFF & byte).toString(16)).slice(-2);
            }
            var encodedStr = Module.Pointer_stringify(encoded);
            result = { hash: hashArr, hashHex: hashStr, encoded: encodedStr };
        } else {
            try {
                if (!err) {
                    err = Module.Pointer_stringify(Module._argon2_error_message(res))
                }
            } catch (e) {
            }
            result = { message: err, code: res };
        }
        try {
            Module._free(pwd);
            Module._free(salt);
            Module._free(hash);
            Module._free(encoded);
        } catch (e) { }
        if (err) {
            throw result;
        } else {
            return result;
        }
    }

    return {
        ArgonType: ArgonType,
        hash: argon2Hash
    };
}));

