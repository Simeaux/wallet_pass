const { PKPass } = require("passkit-generator");
const forge = require("node-forge"); // Usiamo forge per spacchettare il .p12
const fs = require("fs");
const path = require("path");

async function createPass() {
  try {
    const base64Cert = process.env.APPLE_PASS_CERT; 
    const passphrase = process.env.APPLE_PASS_KEY;
    let rawWwdr = process.env.APPLE_WWDR_CERT;

    if (!base64Cert || !passphrase || !rawWwdr) {
      throw new Error("Mancano le configurazioni nei segreti di GitHub (CERT, PASSWORD o WWDR).");
    }

    // 1. Sanatizzazione del certificato WWDR (ripristina gli a capo corretti se GitHub li ha appiattiti)
    if (rawWwdr.includes("\\n")) {
      rawWwdr = rawWwdr.replace(/\\n/g, "\n");
    }

    // 2. Estrazione di Signer Certificate e Signer Key direttamente dal Buffer .p12
    const p12Buffer = Buffer.from(base64Cert, "base64");
    const p12Asn1 = forge.asn1.fromDer(p12Buffer.toString("binary"), false);
    const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, passphrase);

    // Estraiamo la chiave privata in formato PEM
    const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    const bagKey = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag][0];
    const privateKeyPem = forge.pki.privateKeyToPem(bagKey.key);

    // Estraiamo il certificato in formato PEM
    const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
    const bagCert = certBags[forge.pki.oids.certBag][0];
    const certificatePem = forge.pki.certificateToPem(bagCert.cert);

    // Carichiamo le immagini obbligatorie dal modello
    const modelPath = path.resolve(__dirname, "./MioPass.raw");
    const iconBuffer = fs.readFileSync(path.join(modelPath, "icon.png"));
    const logoBuffer = fs.readFileSync(path.join(modelPath, "logo.png"));

    // 3. Inizializziamo PKPass passando i PEM estratti e validi
    const pass = new PKPass({
      "icon.png": iconBuffer,
      "logo.png": logoBuffer
    }, {
      wwdr: rawWwdr,
      signerCert: certificatePem, // PEM del certificato estratto dal .p12
      signerKey: privateKeyPem,     // PEM della chiave estratta dal .p12
      signerKeyPassphrase: passphrase
    });

    // Impostiamo le proprietà del pass
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

    pass.barcodes = [
      {
        format: "PKBarcodeFormatQR",
        message: "https://tuosito.com",
        messageEncoding: "iso-8859-1"
      }
    ];

    console.log("-> Compressione e firma del pass in corso...");
    const actualPass = await pass.getAsBuffer();
    
    const outputPath = path.join(process.cwd(), "MioPass.pkpass");
    fs.writeFileSync(outputPath, actualPass);
    
    console.log("-> FILE SCRITTO SUL DISCO CON SUCCESSO!");
    console.log("-> Percorso di output: " + outputPath);
    
  } catch (error) {
    console.error("!!! ERRORE CRITICO NELLO SCRIPT !!!");
    console.error(error);
    process.exit(1);
  }
}

createPass();
