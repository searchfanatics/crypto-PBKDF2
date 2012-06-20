crypto-PBKDF2
=============

[crypto.js'](http://code.google.com/p/crypto-js/) PBKDF2 standalone implementation for npm.

Usage (based on Stack Exchange's PBKDF2 implementation):
```js
var CryptoJS = require("crypto-PBKDF2");

var DEFAULT_HASH_ITERATIONS = 4000;

var SALT_SIZE: 192/8;

var KEY_SIZE = 768/32;

/**
 * Convenience wrapper around CryptoJS.lib.WordArray.random to grab a new salt value.
 * Treat this value as opaque, as it captures iterations.
 *
 * @param {number} explicitIterations An integer
 * @return {string} Return iterations and salt together as one string ({hex-iterations}.{base64-salt})
*/
function generateSalt(explicitIterations){
    var defaultHashIterations = DEFAULT_HASH_ITERATIONS;

    if(explicitIterations !== null && explicitIterations !== undefined){
        // make sure explicitIterations is an integer
        if( parseInt(explicitIterations, 10) === explicitIterations ){
            throw new Error("explicitIterations must be an integer");
        }
        // and that it is smaller than our default hash iterations
        if( explicitIterations < DEFAULT_HASH_ITERATIONS){
            throw new Error("explicitIterations cannot be less than " + DEFAULT_HASH_ITERATIONS);
        }
    }

    // get some random bytes
    var bytes = CryptoJS.lib.WordArray.random(SALT_SIZE);

    // convert iterations to Hexadecimal
    var iterations = (explicitIterations || defaultHashIterations).toString(16);

    // concat the iterations and random bytes together.
    return iterations + "." + bytes.toString(CryptoJS.enc.Base64);
}

function hashPassword( value, salt ){
    var i = salt.indexOf(".");
    var iters = parseInt(salt.substring(0, i), 16);
    var key = CryptoJS.PBKDF2(value, salt, { "keySize": KEY_SIZE, "iterations": iters });

    return key.toString(CryptoJS.enc.Base64);
}

function checkPassword(candidate, salt, hashed){
    return hashPassword( candidate, salt ) === hashed;
}

/* Save BOTH the salt and the hashedPassword to your database so you can validate the password later */
var salt = generateSalt();
var hashedPassword = hashPassword( "password", salt );
var isPassword = checkPassword( "password", salt, hashedPassword ); // true
```