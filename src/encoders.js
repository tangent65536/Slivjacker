'use strict';

const zlib = require('zlib');

function decodeGzip(buf)
{
  return zlib.gunzipSync(buf);
}

function encodeGzip(buf)
{
  return zlib.gzipSync(buf);
}

function setupModdedBase64CharMap()
{
  const xb64chars = Buffer.from('a0b2c5def6hijklmnopqr_st-uvwxyzA1B3C4DEFGHIJKLM7NO9PQR8ST+UVWXYZ');
  const b64chars = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/');

  let ret = {
    enc: Buffer.allocUnsafe(256),
    dec: Buffer.allocUnsafe(256)
  };
  for(let i = 0 ; i < 64 ; i++)
  {
    ret.dec[xb64chars[i]] = b64chars[i];
    ret.enc[b64chars[i]] = xb64chars[i];
  }

  return ret;
}

function decodeBase64x(buf)
{
  if(!module.mapping)
  {
    module.mapping = setupModdedBase64CharMap();
  }
  
  let transformed = Buffer.allocUnsafe(buf.length);
  for(let i = 0 ; i < buf.length ; i++)
  {
    transformed[i] = module.mapping.dec[buf[i]];
  }

  return Buffer.from(transformed.toString('ascii'), 'base64');
}

function encodeBase64x(buf)
{
  if(!module.mapping)
  {
    module.mapping = setupModdedBase64CharMap();
  }

  let transformed = Buffer.from(buf.toString('base64').split('=', 1)[0], 'ascii');
  for(let i = 0 ; i < transformed.length ; i++)
  {
    transformed[i] = module.mapping.enc[transformed[i]];
  }

  return transformed;
}

function decodeGzipBase64x(buf)
{
  return decodeGzip(decodeBase64x(buf));
}

function encodeGzipBase64x(buf)
{
  return encodeBase64x(encodeGzip(buf));
}

function decodeHex(buf)
{
  return Buffer.from(buf.toString('ascii'), 'hex');
}

function encodeHex(buf)
{
  return Buffer.from(buf.toString('hex'), 'ascii');
}

function decodeEnglish(buf)
{
  let i, j = 0;
  let spaceFlag = true;
  let ret = Buffer.allocUnsafe(buf.length);
  for(i = 0 ; i < buf.length ; i++)
  {
    if(buf[i] === 0x20) // Space char
    {
      if(!spaceFlag)
      {
        spaceFlag = true;
        j++;
      }
      continue;
    }

    if(spaceFlag)
    {
      ret[j] = 0;
      spaceFlag = false;
    }

    ret[j] += buf[i];
  }

  return ret.subarray(0, j + (spaceFlag ? 0 : 1));
}

function setupPseudoWords() // Well. Lmao.
{
  let ret = new Array(256);
  let remaining = ret.length;
  let counter = 0, cache;
  while(remaining)
  {
    cache = counter;
    let str = '';
    do
    {
      str += String.fromCharCode(0x41 + cache % 26);
      cache = Math.floor(cache / 26);
    }
    while(cache);

    let buf = Buffer.from(str);
    for(let i = 1 ; i < buf.length ; i++)
    {
      buf[0] += buf[i];
    }
    if(!ret[buf[0]])
    {
      ret[buf[0]] = str;
      remaining--;

      // console.log('0x%s => %s', buf[0].toString(16), str);
    }

    counter++;
  }
  return ret;
}

function encodeEnglish(buf)
{
  if(!module.pseudoWordMap)
  {
    module.pseudoWordMap = setupPseudoWords();
  }

  if(buf.length <= 0)
  {
    return Buffer.allocUnsafe(0);
  }

  let ret = module.pseudoWordMap[buf[0]];

  for(let i = 1 ; i < buf.length ; i++)
  {
    ret += ` ${module.pseudoWordMap[buf[i]]}`;
  }

  return Buffer.from(ret, 'ascii');
}

function decodeEnglishGzip(buf)
{
  return decodeEnglish(decodeGzip(buf));
}

function encodeEnglishGzip(buf)
{
  return encodeGzip(encodeEnglish(buf));
}

module.exports = {
  13: {
    encode: encodeBase64x,
    decode: decodeBase64x
  },
  31: {
    encode: encodeEnglish,
    decode: decodeEnglish
  },
  45: {
    encode: encodeEnglishGzip,
    decode: decodeEnglishGzip
  },
  49: {
    encode: encodeGzip,
    decode: decodeGzip
  },
  64: {
    encode: encodeGzipBase64x,
    decode: decodeGzipBase64x
  },
  92: {
    encode: encodeHex,
    decode: decodeHex
  },
};