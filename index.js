const { PKPass } = require("passkit-generator");
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");
const https = require("https");
const http = require("http");

const WORDPRESS_API_URL =
  process.env.WORDPRESS_API_URL ||
  "http://turismo.comune.caldarola.mc.it";

const WALLET_GENERATOR_KEY =
  process.env.WALLET_GENERATOR_KEY;

const WALLET_PASS_ID =
  process.env.WALLET_PASS_ID || "1";

/**
 * Converte il certificato WWDR EC in un oggetto minimale
 * compatibile con certificateToAsn1() di node-forge.
 */
function parseEcCertificateForPkcs7(pem) {
  const messages = forge.pem.decode(pem);

  if (!messages || !messages.length) {
    throw new Error("APPLE_WWDR_CERT non contiene un PEM valido.");
  }

  const message = messages[0];

  if (message.type !== "CERTIFICATE") {
    throw new Error(
      "APPLE_WWDR_CERT non contiene un certificato PEM."
    );
  }

  const certAsn1 = forge.asn1.fromDer(
    message.body,
    false
  );

  if (
    certAsn1.tagClass !== forge.asn1.Class.UNIVERSAL ||
    certAsn1.type !== forge.asn1.Type.SEQUENCE ||
    !certAsn1.constructed ||
    certAsn1.value.length < 3
  ) {
    throw new Error(
      "Il certificato WWDR non ha una struttura X.509 valida."
    );
  }

  const tbsCertificate = certAsn1.value[0];
  const signatureAlgorithm = certAsn1.value[1];
  const signatureValue = certAsn1.value[2];

  if (
    !signatureAlgorithm.value ||
    !signatureAlgorithm.value.length
  ) {
    throw new Error(
      "Il certificato WWDR non contiene il Signature Algorithm."
    );
  }

  const signatureOid = forge.asn1.derToOid(
    signatureAlgorithm.value[0].value
  );

  let signatureParameters;

  if (signatureAlgorithm.value.length > 1) {
    signatureParameters = signatureAlgorithm.value[1];
  }

  if (
    !signatureValue.value ||
    signatureValue.value.length < 1
  ) {
    throw new Error(
      "Il certificato WWDR non contiene una Signature Value valida."
    );
  }

  let signatureBytes;

  if (typeof signatureValue.value === "string") {
    signatureBytes = signatureValue.value;
  } else {
    signatureBytes = Buffer.from(
      signatureValue.value
    ).toString("latin1");
  }

  if (signatureBytes.length < 1) {
    throw new Error(
      "Il WWDR contiene una Signature Value vuota."
    );
  }

  const signature = signatureBytes.substring(1);

  console.log(
    "-> WWDR EC analizzato senza usare certificateFromPem()."
  );

  console.log(
    "-> WWDR signature OID: " + signatureOid
  );

  return {
    tbsCertificate,
    signatureOid,
    signatureParameters,
    signature
  };
}

function fetchWalletPass() {
  return new Promise((resolve, reject) => {

    function requestUrl(url, redirectCount = 0) {

      if (!WALLET_GENERATOR_KEY) {
        reject(
          new Error(
            "Manca la variabile WALLET_GENERATOR_KEY."
          )
        );
        return;
      }

      if (redirectCount > 5) {
        reject(
          new Error(
            "Troppi redirect durante la chiamata a WordPress."
          )
        );
        return;
      }

      const client =
        url.startsWith("https://")
          ? https
          : http;

      const request =
        client.get(
          url,
          {
            headers: {
              "X-Wallet-Generator-Key":
                WALLET_GENERATOR_KEY,

              "Accept":
                "application/json"
            }
          },
          response => {

            // ====================================================
            // REDIRECT HTTP
            // ====================================================

            if (
              response.statusCode >= 300 &&
              response.statusCode < 400 &&
              response.headers.location
            ) {

              const redirectUrl =
                new URL(
                  response.headers.location,
                  url
                ).toString();

              console.log(
                "-> WordPress redirect HTTP " +
                response.statusCode +
                ": " +
                redirectUrl
              );

              response.resume();

              requestUrl(
                redirectUrl,
                redirectCount + 1
              );

              return;
            }

            // ====================================================
            // RISPOSTA NORMALE
            // ====================================================

            let body = "";

            response.setEncoding("utf8");

            response.on(
              "data",
              chunk => {
                body += chunk;
              }
            );

            response.on(
              "end",
              () => {

                if (
                  response.statusCode < 200 ||
                  response.statusCode >= 300
                ) {
                  reject(
                    new Error(
                      "WordPress API HTTP " +
                      response.statusCode +
                      ": " +
                      body
                    )
                  );

                  return;
                }

                try {

                  const data =
  JSON.parse(body.replace(/^\uFEFF/, ""));

                  resolve(data);

                } catch (error) {

                  reject(
                    new Error(
                      "Risposta WordPress non valida: " +
                      error.message
                    )
                  );

                }

              }
            );
          }
        );

      request.on(
        "error",
        error => {
          reject(
            new Error(
              "Errore connessione WordPress: " +
              error.message
            )
          );
        }
      );
    }

    const url =
      WORDPRESS_API_URL.replace(/\/+$/, "") +
      "/wp-json/wallet/v1/generator/pass/" +
      encodeURIComponent(WALLET_PASS_ID);

    requestUrl(url);
  });
}

async function createPass() {
  try {
    const base64Cert = process.env.APPLE_PASS_CERT;
    const passphrase = process.env.APPLE_PASS_PASSWORD;
    let rawWwdr = process.env.APPLE_WWDR_CERT;

    if (!base64Cert || !passphrase || !rawWwdr) {
      throw new Error(
        "Mancano APPLE_PASS_CERT, APPLE_PASS_PASSWORD o APPLE_WWDR_CERT."
      );
    }

    if (rawWwdr.includes("\\\n")) {
      rawWwdr = rawWwdr.replace(/\\\n/g, "\n");
    }

    // ============================================================
    // LETTURA E APERTURA DEL .p12
    // ============================================================

    const p12Buffer = Buffer.from(
      base64Cert,
      "base64"
    );

    if (!p12Buffer.length) {
      throw new Error(
        "APPLE_PASS_CERT non contiene un .p12 valido."
      );
    }

    const p12Asn1 = forge.asn1.fromDer(
      p12Buffer.toString("binary"),
      false
    );

    const p12 = forge.pkcs12.pkcs12FromAsn1(
      p12Asn1,
      false,
      passphrase
    );

    // ============================================================
    // ESTRAZIONE CHIAVE PRIVATA
    // ============================================================

    const keyBags = p12.getBags({
      bagType: forge.pki.oids.pkcs8ShroudedKeyBag
    });

    const keyBagList =
      keyBags[forge.pki.oids.pkcs8ShroudedKeyBag];

    if (
      !keyBagList ||
      !keyBagList.length ||
      !keyBagList[0].key
    ) {
      throw new Error(
        "Nel p12 non e stata trovata una chiave privata."
      );
    }

    const privateKeyPem = forge.pki.privateKeyToPem(
      keyBagList[0].key
    );

    // ============================================================
    // ESTRAZIONE CERTIFICATO RSA DEL PASS
    // ============================================================

    const certBags = p12.getBags({
      bagType: forge.pki.oids.certBag
    });

    const certBagList =
      certBags[forge.pki.oids.certBag];

    if (
      !certBagList ||
      !certBagList.length ||
      !certBagList[0].cert
    ) {
      throw new Error(
        "Nel p12 non e stato trovato un certificato."
      );
    }

    const certificatePem =
      forge.pki.certificateToPem(
        certBagList[0].cert
      );

    console.log("-> p12 aperto correttamente.");
    console.log("-> Certificato e chiave privata estratti.");

    // ============================================================
    // WWDR EC
    // ============================================================

    const wwdrCertificate =
      parseEcCertificateForPkcs7(rawWwdr);

    // ============================================================
    // PATCH node-forge
    // ============================================================

    const originalCertificateFromPem =
      forge.pki.certificateFromPem;

    const wwdrPemMessage =
      forge.pem.decode(rawWwdr);

    if (
      !wwdrPemMessage ||
      !wwdrPemMessage.length ||
      wwdrPemMessage[0].type !== "CERTIFICATE"
    ) {
      throw new Error(
        "APPLE_WWDR_CERT non contiene un certificato PEM valido."
      );
    }

    const wwdrDerHex =
      forge.util
        .bytesToHex(
          wwdrPemMessage[0].body
        )
        .toLowerCase();

    forge.pki.certificateFromPem =
      function(pem) {
        if (typeof pem === "string") {
          try {
            const decoded =
              forge.pem.decode(pem);

            if (
              decoded &&
              decoded.length &&
              decoded[0].type === "CERTIFICATE"
            ) {
              const candidateDerHex =
                forge.util
                  .bytesToHex(
                    decoded[0].body
                  )
                  .toLowerCase();

              if (
                candidateDerHex === wwdrDerHex
              ) {
                return wwdrCertificate;
              }
            }
          } catch (_) {
            // Il parser originale gestira eventuali certificati non validi.
          }
        }

        return originalCertificateFromPem.call(
          forge.pki,
          pem
        );
      };

    // ============================================================
    // IMMAGINI
    // ============================================================

    const modelPath = path.resolve(
      __dirname,
      "./MioPass.raw"
    );

    const iconPath = path.join(
      modelPath,
      "icon.png"
    );

    const logoPath = path.join(
      modelPath,
      "logo.png"
    );

    if (!fs.existsSync(iconPath)) {
      throw new Error(
        "File mancante: MioPass.raw/icon.png"
      );
    }

    if (!fs.existsSync(logoPath)) {
      throw new Error(
        "File mancante: MioPass.raw/logo.png"
      );
    }

    const iconBuffer =
      fs.readFileSync(iconPath);

    const logoBuffer =
      fs.readFileSync(logoPath);

        // ============================================================
    // DATI WALLET DA WORDPRESS
    // ============================================================

    console.log(
      "-> Recupero dati del pass da WordPress..."
    );

    const walletData =
      await fetchWalletPass();

    if (
      !walletData ||
      !walletData.id ||
      !walletData.pass_uuid ||
      !walletData.auth_token ||
      !walletData.serial_number ||
      !Array.isArray(walletData.channels)
    ) {
      throw new Error(
        "Risposta WordPress incompleta o non valida."
      );
    }

    console.log(
      "-> Pass WordPress: " +
      walletData.id
    );

    console.log(
      "-> UUID: " +
      walletData.pass_uuid
    );

    console.log(
      "-> Serial: " +
      walletData.serial_number
    );

    const enabledChannels =
      walletData.channels.filter(
        channel =>
          channel &&
          channel.enabled === true &&
          channel.id &&
          channel.name
      );

    if (!enabledChannels.length) {
      throw new Error(
        "Nessun canale informativo attivo in WordPress."
      );
    }

    console.log(
      "-> Canali informativi attivi: " +
      enabledChannels.length
    );

    enabledChannels.forEach(
      channel => {
        console.log(
          "   - " +
          channel.id +
          ": " +
          channel.name +
          " [" +
          (
            channel.preference_enabled === true
              ? "ATTIVO"
              : "DISATTIVO"
          ) +
          "]"
        );
      }
    );

    // ============================================================
    // CREAZIONE PASS
    // ============================================================

    const pass = new PKPass(
      {
        "icon.png": iconBuffer,
        "logo.png": logoBuffer
      },
      {
        wwdr: rawWwdr,
        signerCert: certificatePem,
        signerKey: privateKeyPem,
        signerKeyPassphrase: passphrase
      },
      {
        passTypeIdentifier:
          "pass.com.task.mio-pass",

        serialNumber: walletData.serial_number,

        teamIdentifier:
          "P8MH6VJGC7",

        organizationName:
          "T.A.S.K. SRL",

        description:
          "Informazioni comunali",

        foregroundColor:
          "rgb(255, 255, 255)",

        backgroundColor:
          "rgb(60, 60, 60)"
      }
    );

    // ============================================================
    // DATI WALLET
    // ============================================================

    pass.type = "generic";
    pass.formatVersion = 1;

    pass.primaryFields.push({
      key: "information",
      label: "Informazioni comunali",
      value: "Canali attivi"
    });

    // Primi due canali
    enabledChannels
      .slice(0, 2)
      .forEach(
        (channel, index) => {
          pass.secondaryFields.push({
            key:
              "channel_" +
              index,

            label:
              "Canale",

            value:
              channel.name
          });
        }
      );

    // Canali successivi
    enabledChannels
      .slice(2, 6)
      .forEach(
        (channel, index) => {
          pass.auxiliaryFields.push({
            key:
              "channel_aux_" +
              index,

            label:
              "Canale",

            value:
              channel.name
          });
        }
      );

    // Descrizioni sul retro
    enabledChannels.forEach(
      channel => {
        pass.backFields.push({
          key:
            "channel_description_" +
            channel.id,

          label:
            channel.name,

          value:
            channel.description || "",

          attributedValue:
            channel.url
              ? `<a href="${channel.url}">${channel.name}</a>`
              : undefined
        });
      }
    );

    // ============================================================
    // QR CODE
    // ============================================================

    pass.barcodes = [
      {
        format:
          "PKBarcodeFormatQR",

        message:
          "https://tuosito.com",

        messageEncoding:
          "iso-8859-1"
      }
    ];

    // ============================================================
    // GENERAZIONE E FIRMA
    // ============================================================

    console.log(
      "-> Compressione e firma del pass in corso..."
    );

    const actualPass =
      await pass.getAsBuffer();

    const outputPath =
      path.join(
        process.cwd(),
        "MioPass.pkpass"
      );

    fs.writeFileSync(
      outputPath,
      actualPass
    );

    console.log(
      "-> FILE SCRITTO SUL DISCO CON SUCCESSO!"
    );

    console.log(
      "-> Percorso di output: " +
      outputPath
    );

    console.log(
      "-> Dimensione: " +
      actualPass.length +
      " byte"
    );

  } catch (error) {
    console.error(
      "!!! ERRORE CRITICO NELLO SCRIPT !!!"
    );

    console.error(error);

    process.exit(1);
  }
}

createPass();
