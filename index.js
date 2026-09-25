const { PKPass } = require("passkit-generator");
const forge = require("node-forge");
const fs = require("fs");
const path = require("path");

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
      throw new Error("APPLE_PASS_CERT non contiene un .p12 valido.");
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

    if (!keyBagList || !keyBagList.length || !keyBagList[0].key) {
      throw new Error(
        "Nel p12 non e stata trovata una chiave privata."
      );
    }

    const privateKeyPem = forge.pki.privateKeyToPem(
      keyBagList[0].key
    );

    // ============================================================
    // ESTRAZIONE CERTIFICATO
    // ============================================================

    const certBags = p12.getBags({
      bagType: forge.pki.oids.certBag
    });

    const certBagList =
      certBags[forge.pki.oids.certBag];

    if (!certBagList || !certBagList.length || !certBagList[0].cert) {
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
    // IMMAGINI
    // ============================================================

    const modelPath = path.resolve(__dirname, "./MioPass.raw");

    const iconPath = path.join(modelPath, "icon.png");
    const logoPath = path.join(modelPath, "logo.png");

    if (!fs.existsSync(iconPath)) {
      throw new Error("File mancante: MioPass.raw/icon.png");
    }

    if (!fs.existsSync(logoPath)) {
      throw new Error("File mancante: MioPass.raw/logo.png");
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

    pass.passTypeIdentifier = "pass.com.task.mio-pass";
    pass.serialNumber = "123456";

    pass.teamIdentifier = "P8MH6VJGC7";

    pass.organizationName = "T.A.S.K. SRL";
    pass.description = "Tessera Socio";

    pass.foregroundColor = "rgb(255, 255, 255)";
    pass.backgroundColor = "rgb(60, 60, 60)";

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

    console.log("-> Compressione e firma del pass in corso...");

    const actualPass = await pass.getAsBuffer();

    const outputPath = path.join(
      process.cwd(),
      "MioPass.pkpass"
    );

    fs.writeFileSync(outputPath, actualPass);

    console.log("-> FILE SCRITTO SUL DISCO CON SUCCESSO!");
    console.log("-> Percorso di output: " + outputPath);
    console.log("-> Dimensione: " + actualPass.length + " byte");

  } catch (error) {
    console.error("!!! ERRORE CRITICO NELLO SCRIPT !!!");
    console.error(error);
    process.exit(1);
  }
}

createPass();
