const { PKPass } = require("passkit-generator");
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");

/**
 * Converte il certificato WWDR EC G6 in un oggetto minimale
 * compatibile con certificateToAsn1() di node-forge.
 *
 * node-forge 1.4.x rifiuta i certificati X.509 con chiave EC
 * durante certificateFromPem(). Per il WWDR ci serve però
 * soltanto reinserire il certificato originale nel PKCS#7.
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

  // BIT STRING: il primo byte indica il numero di bit inutilizzati.
  // A seconda della versione/runtime di node-forge il valore può essere
  // una stringa binaria oppure un array/Uint8Array.
  let signatureBytes;

  if (typeof signatureValue.value === "string") {
    signatureBytes = signatureValue.value;
  } else {
    signatureBytes = Buffer.from(signatureValue.value).toString("latin1");
  }

  if (signatureBytes.length < 1) {
    throw new Error(
      "Il WWDR contiene una Signature Value vuota."
    );
  }

  // Rimuove il byte iniziale "unused bits".
  // certificateToAsn1() lo aggiungerà nuovamente.
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

    // Normalizza eventuali \n memorizzati letteralmente nel Secret GitHub
    if (rawWwdr.includes("\\n")) {
      rawWwdr = rawWwdr.replace(/\\n/g, "\n");
    }

    // ============================================================
    // LETTURA E APERTURA DEL .p12
    // ============================================================

    const p12Buffer = Buffer.from(base64Cert, "base64");

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

    const certificatePem = forge.pki.certificateToPem(
      certBagList[0].cert
    );

    console.log("-> p12 aperto correttamente.");
    console.log("-> Certificato e chiave privata estratti.");

    // ============================================================
    // WWDR EC G6
    // ============================================================

    const wwdrCertificate =
      parseEcCertificateForPkcs7(rawWwdr);

    // ============================================================
    // PATCH TEMPORANEA DI node-forge
    // ============================================================
    //
    // passkit-generator passa il WWDR a:
    //
    //   signature.addCertificate(wwdr)
    //
    // e successivamente node-forge chiama:
    //
    //   certificateToAsn1(cert)
    //
    // Il normale certificateFromPem() non supporta EC.
    //
    // Sovrascriviamo quindi solo certificateFromPem per
    // riconoscere il nostro WWDR EC e restituire l'oggetto
    // ASN.1 minimale.
    //
    // Il certificato RSA del Pass continua a essere gestito
    // normalmente.

    const originalCertificateFromPem =
      forge.pki.certificateFromPem;

    // Confrontiamo il DER del certificato invece del testo PEM,
    // così CRLF/LF e newline del Secret GitHub non sono rilevanti.
    const wwdrPemMessage = forge.pem.decode(rawWwdr);

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
        .bytesToHex(wwdrPemMessage[0].body)
        .toLowerCase();

    forge.pki.certificateFromPem = function(pem) {
      if (typeof pem === "string") {
        try {
          const decoded = forge.pem.decode(pem);

          if (
            decoded &&
            decoded.length &&
            decoded[0].type === "CERTIFICATE"
          ) {
            const candidateDerHex =
              forge.util
                .bytesToHex(decoded[0].body)
                .toLowerCase();

            if (candidateDerHex === wwdrDerHex) {
              return wwdrCertificate;
            }
          }
        } catch (_) {
          // Il parser originale gestirà eventuali certificati non validi.
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

    const iconBuffer = fs.readFileSync(iconPath);
    const logoBuffer = fs.readFileSync(logoPath);

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
      }
    );

    // ============================================================
    // DATI WALLET
    // ============================================================

    pass.type = "generic";
    pass.formatVersion = 1;

    pass.passTypeIdentifier =
      "pass.com.task.mio-pass";

    pass.serialNumber = "123456";

    pass.teamIdentifier =
      "P8MH6VJGC7";

    pass.organizationName =
      "T.A.S.K. SRL";

    pass.description =
      "Tessera Socio";

    pass.foregroundColor =
      "rgb(255, 255, 255)";

    pass.backgroundColor =
      "rgb(60, 60, 60)";

    pass.generic = {
      primaryFields: [
        {
          key: "member",
          label: "Membro",
          value: "Mario Rossi"
        }
      ]
    };

    // ============================================================
    // QR CODE
    // ============================================================

    pass.barcodes = [
      {
        format: "PKBarcodeFormatQR",
        message: "https://tuosito.com",
        messageEncoding: "iso-8859-1"
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


