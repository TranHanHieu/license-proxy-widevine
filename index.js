const express = require("express");
const http = require("http");
const app = express();
const moment = require("moment");
const parse = require("url-parse");
const Base64 = require("js-base64").Base64;
const urllib = require("urllib");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const sizeof = require("object-sizeof");

// # Content Information
const CONTENT_ID = Base64.encode("*");
const CONTENT_KEY = Buffer.from("0a237b0752cbf1a827e2fecfb87479a2", "hex").toString("base64")
const KEY_ID = Buffer.from("d58ce954203b7c9a9a9d467f59839249", "hex").toString("base64")

// License Values
const LICENSE_SERVER_URL = "https://license.uat.widevine.com/cenc/getlicense";
const ALLOWED_TRACK_TYPES = "SD_HD";

// Provider Information
// # Replace PROVIDER and _KEY and _IV with your provider credentials
const _KEY = Buffer.from(
  "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9",
  "hex"
);
const _IV = Buffer.from("d58ce954203b7c9a9a9d467f59839249", "hex");
const PROVIDER = "widevine_test";

function buildLicenseServerRequest(message_body) {
  const message = buildLicenseMessage(message_body);
  console.log("message ----:", message);

  const request = Buffer.from(message).toString("base64");
  const signature = generateSignature(message);
  console.log("request ----:", request);

  console.log("signature ----:", signature);

  return dumps(JSON.stringify({ request, signature, signer: PROVIDER }));
}

function buildLicenseMessage(message_body) {
  const payload = Buffer.from(message_body).toString('base64');
  const CONTENT_KEY_SPECS = [{ key_id: KEY_ID, key: CONTENT_KEY }];
  console.log("CONTENT_KEY_SPECS: ", CONTENT_KEY_SPECS);
  const message = dumps(
    JSON.stringify({
      content_id: CONTENT_ID,
      content_key_specs: CONTENT_KEY_SPECS,
      payload, //: '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',
      provider: PROVIDER,
      // allowed_track_types: ALLOWED_TRACK_TYPES,
    })
  );
  console.log("buildLicenseMessage: ", message);
  return message

}

function buildCertificateRequest(message_body) {
  const message = buildCertificateMessage(message_body);
  const request = Base64.encode(message);
  const signature = generateSignature(message);
  const certificate_request = {
    request,
    signature,
    signer: PROVIDER
  };
  console.log("certificate_request ----:", certificate_request);
  return dumps(JSON.stringify(certificate_request));
}

function buildCertificateMessage(message_body) {
  let payload = Buffer.from(message_body, "utf-8").toString("base64");
  const request = { payload: "CAQ=" };
  console.log("Certificate Request ----:", request);
  return dumps(JSON.stringify(request));
}

function sendRequest(message_body) {
  return new Promise((resolve, reject) => {
    try {
      urllib.request(
        LICENSE_SERVER_URL + "/" + PROVIDER,
        { method: "POST", data: message_body },
        function(err, data, res) {
          if (err) {
            console.log("err", err);
            reject({
              status: 500,
              message: "License Request Failed"
            });
          }
          resolve(data.toString());
        }
      );
    } catch (err) {
      console.log("err", err);
      reject({
        status: 500,
        message: "License Request Failed"
      });
    }
  });
}

function generateSignature(text_to_sign) {
  const signature = encryptAES_256(text_to_sign);
  console.log("signature ----:", signature);

  return signature;
}

function encryptAES_256(text_to_sign) {
  const hashed_text = crypto
    .createHash("sha1")
    .update(text_to_sign)
    .digest();
  const padding = getPadding(hashed_text);
  console.log(_KEY.toString("utf16le"));

  const cipher = crypto.createCipheriv("aes-256-cbc", _KEY, _IV);
  cipher.setAutoPadding(false);

  let encrypted = cipher.update(
    Buffer.concat(
      [hashed_text, padding],
      hashed_text.byteLength + padding.byteLength
    ),
    "utf8",
    "base64"
  );
  encrypted += cipher.final("base64");

  return encrypted;
}

function getPadding(hashed_text) {
  if (hashed_text.length % 16 == 0) return "";
  let str = "";
  for (let i = 1; i <= 16 - (hashed_text.length % 16); i++) {
    str += "00";
  }
  return Buffer.from(str, "hex");
}

function processLicenseResponse(response) {
  const license_response = JSON.parse(response);
  console.log('Server response', license_response)
  if (license_response.status == "OK") {
    if (license_response.license)
      return {
        status_ok: true,
        response: Buffer.from(license_response.license, "base64").toString(
          "utf-8"
        )
      };
    console.log("PARSE_ONLY request, no 'license' found.");
  } else {
    return { status_ok: false, response: license_response.status };
  }
}

function send400(res, text) {
  res.status(400).send(text);
}

function send500(res, text) {
  res.status(500).send(text);
}

function dumps(value) {
  return value.replace(/\:"/g, ': "').replace(/\:\[/g, ': [').replace(/\,"/g, ', "');
}

const options = {
  // key: fs.readFileSync('key.pem'),
  // cert: fs.readFileSync('cert.pem'),
  key:
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEA3IDFzxorKO8xWeCOosuK1pCPoTUMlhOkis4pWO9CLCv0o0Q7\nyUCZlHzPYWM49+QmWe5u3Xbl1rhkFsoeYowH1bts5r6HY8xYHexvU+6zEyxOU4Q7\nP7EXkFfW5h7WsO6uaEyEBVdniTIjK4c8hzjy7h6hNIvM+kEAAy1UFatMKmOwsp4Z\ns4+oCmS4ZPlItAMbRv/4a5DCopluOS7WN8UwwJ6zRrY8ZVFnkKPThflnwiaIy2Qh\nGgTwLANIUlWPQMh+LLHnV56NOlj1VUO03G+pKxTJ6ZkfYefaD41Ez4iPc7nyg4iD\njqnqFX+jYOLRoCktztYd9T43Sgb2sfgrlY0ENwIDAQABAoIBAQCoznyg/CumfteN\nMvh/cMutT6Zlh7NHAWqqSQImb6R9JHl4tDgA7k+k+ZfZuphWTnd9yadeLDPwmeEm\nAT4Zu5IT8hSA4cPMhxe+cM8ZtlepifW8wjKJpA2iF10RdvJtKYyjlFBNtogw5A1A\nuZuA+fwgh5pqG8ykmTZlOEJzBFye5Z7xKc/gwy9BGv3RLNVf+yaJCqPKLltkAxtu\nFmrBLuIZMoOJvT+btgVxHb/nRVzURKv5iKMY6t3JM84OSxNn0/tHpX2xTcqsVre+\nsdSokKGYoyzk/9miDYhoSVOrM3bU5/ygBDt1Pmf/iyK/MDO2P9tX9cEp/+enJc7a\nLg5O/XCBAoGBAPNwayF6DLu0PKErsdCG5dwGrxhC69+NBEJkVDMPMjSHXAQWneuy\n70H+t2QHxpDbi5wMze0ZClMlgs1wItm4/6iuvOn9HJczwiIG5yM9ZJo+OFIqlBq3\n1vQG+oEXe5VpTfpyQihxqTSiMuCXkTYtNjneHseXWAjFuUQe9AOxxzNRAoGBAOfh\nZEEDY7I1Ppuz7bG1D6lmzYOTZZFfMCVGGTrYmam02+rS8NC+MT0wRFCblQ0E7SzM\nr9Bv2vbjrLY5fCe/yscF+/u/UHJu1dR7j62htdYeSi7XbQiSwyUm1QkMXjKDQPUw\njwR3WO8ZHQf2tywE+7iRs/bJ++Oolaw03HoIp40HAoGBAJJwGpGduJElH5+YCDO3\nIghUIPnIL9lfG6PQdHHufzXoAusWq9J/5brePXU31DOJTZcGgM1SVcqkcuWfwecU\niP3wdwWOU6eE5A/R9TJWmPDL4tdSc5sK4YwTspb7CEVdfiHcn31yueVGeLJvmlNr\nqQXwXrWTjcphHkwjDog2ZeyxAoGBAJ5Yyq+i8uf1eEW3v3AFZyaVr25Ur51wVV5+\n2ifXVkgP28YmOpEx8EoKtfwd4tE7NgPL25wJZowGuiDObLxwOrdinMszwGoEyj0K\nC/nUXmpT0PDf5/Nc1ap/NCezrHfuLePCP0gbgD329l5D2p5S4NsPlMfI8xxqOZuZ\nlZ44XsLtAoGADiM3cnCZ6x6/e5UQGfXa6xN7KoAkjjyO+0gu2AF0U0jDFemu1BNQ\nCRpe9zVX9AJ9XEefNUGfOI4bhRR60RTJ0lB5Aeu1xAT/OId0VTu1wRrbcnwMHGOo\nf7Kk1Vk5+1T7f1QbTu/q4ddp22PEt2oGJ7widRTZrr/gtH2wYUEjMVQ=\n-----END RSA PRIVATE KEY-----\n",
  cert:
    "-----BEGIN CERTIFICATE-----\nMIIC+zCCAeOgAwIBAgIJANnDRcmEqJssMA0GCSqGSIb3DQEBBQUAMBQxEjAQBgNV\nBAMMCWxvY2FsaG9zdDAeFw0xNzA5MTIyMjMxMDRaFw0yNzA5MTAyMjMxMDRaMBQx\nEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\nggEBANyAxc8aKyjvMVngjqLLitaQj6E1DJYTpIrOKVjvQiwr9KNEO8lAmZR8z2Fj\nOPfkJlnubt125da4ZBbKHmKMB9W7bOa+h2PMWB3sb1PusxMsTlOEOz+xF5BX1uYe\n1rDurmhMhAVXZ4kyIyuHPIc48u4eoTSLzPpBAAMtVBWrTCpjsLKeGbOPqApkuGT5\nSLQDG0b/+GuQwqKZbjku1jfFMMCes0a2PGVRZ5Cj04X5Z8ImiMtkIRoE8CwDSFJV\nj0DIfiyx51eejTpY9VVDtNxvqSsUyemZH2Hn2g+NRM+Ij3O58oOIg46p6hV/o2Di\n0aApLc7WHfU+N0oG9rH4K5WNBDcCAwEAAaNQME4wHQYDVR0OBBYEFJBSho+nF530\nsxpoBxYqD/ynn/t0MB8GA1UdIwQYMBaAFJBSho+nF530sxpoBxYqD/ynn/t0MAwG\nA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAJFAh3X5CYFAl0cI6Q7Vcp4H\nO0S8s/C4FHNIsyUu54NcRH3taUwn3Fshn5LiwaEdFmouALbxMaejvEVw7hVBtY9X\nOjqt0mZ6+X6GOFhoUvlaG1c7YLOk5x51TXchg8YD2wxNXS0rOrAdZaScOsy8Q62S\nHehBJMN19JK8TiR3XXzxKVNcFcg0wyQvCGgjrHReaUF8WePfWHtZDdP01kBmMEIo\n6wY7E3jFqvDUs33vTOB5kmWixIoJKmkgOVmbgchmu7z27n3J+fawNr2r4IwjdUpK\nc1KvFYBXLiT+2UVkOJbBZ3C8mKfhXKHs2CrI3cSa4+E0sxTy4joG/yzlRs5l954=\n-----END CERTIFICATE-----\n",
  secureProtocol: "SSLv23_method"
};

app.set("port", "3001");
app.set("etag", false);
app.disable("x-powered-by", false);

// parse application/json
// app.use(cors());
// app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
var server = http.createServer(app);
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.set("Cache-Control", "no-cache");
  next();
});

app.use("/public", express.static(__dirname + "/public"));

app.post("/", async (req, res) => {
  let body = "";
  req.on("data", chunk => {
    body += chunk.toString(); // convert Buffer to string
  });
  req.on("end", async () => {
    console.log("body", body);
    // res.end('ok');
    if (!body) {
      console.log("Empty Request");
      res.status(400).send("Empty Request");
      return;
    }
    let response = null;
    res.set("Access-Control-Allow-Methods", "POST");
    res.set("Access-Control-Allow-Credentials", true);

    if (!req.referer) res.set("Access-Control-Allow-Origin", "*");
    else {
      referer = parse(req.referer);
      res.set(
        "Access-Control-Allow-Origin",
        referer.protocol + "://" + referer.host
      );
    }

    try {
      console.log(
        "Handle Request: ",
        sizeof(Base64.encode((body)))
      );
      if (sizeof(Base64.encode(body)) < 50) {
        response = await sendRequest(
          buildCertificateRequest(body)
        );
      } else {
        response = await sendRequest(
          buildLicenseServerRequest((body))
        );
      }
      const result = processLicenseResponse(response);
      console.log("result: ", result);
      response = result.response;
      if (result.status_ok) {
        res.send(response);
      } else send500(res, response);
    } catch (err) {
      console.log(err);
      send400(res, "Invalid License Request");
    }
  });
});

app.get("/", function(req, res) {
  res.send("GET Not Supported");
});

server.listen(app.get("port"), function() {
  console.log(
    `${moment().format(
      "YYYY/MM/DD hh:mm:ss"
    )}: Express server listening on port ${app.get("port")}, mode: ${process.env
      .NODE_ENV || "development"}`
  );
});
