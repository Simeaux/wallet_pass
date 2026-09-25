const { PKPass } = require("passkit-generator");
const fs = require("fs");
const path = require("path");

async function createPass() {
  try {
    const base64Cert = process.env.APPLE_PASS_CERT; 
    const passphrase = process.env.APPLE_PASS_PASSWORD;
    const rawWwdr = process.env.APPLE_WWDR_CERT;

    if (!base64Cert || !passphrase || !rawWwdr) {
      throw new Error("Mancano le configurazioni nei segreti di GitHub (CERT, PASSWORD o WWDR).");
    }

    const p12Buffer = Buffer.from(base64Cert, "base64");

    // Carichiamo le immagini obbligatorie dal modello
    const modelPath = path.resolve(__dirname, "./MioPass.raw");
    const iconBuffer = fs.readFileSync(path.join(modelPath, "icon.png"));
    const logoBuffer = fs.readFileSync(path.join(modelPath, "logo.png"));

    // 1. Inizializziamo PKPass passando SOLO i certificati e i file multimediali iniziali
    const pass = new PKPass({
      "icon.png": iconBuffer,
      "logo.png": logoBuffer
    }, {
      wwdr: rawWwdr,
      signerCert: p12Buffer,
      signerKey: p12Buffer,
      signerKeyPassphrase: passphrase
    });

    // 2. Impostiamo il tipo di pass (stile) e i campi usando i metodi ufficiali dell'istanza
    pass.type = "generic"; // Questo risolve l'errore "type is missing" al momento del close()
    
    // Assegniamo i metadati principali direttamente alle proprietà dell'istanza
    pass.formatVersion = 1;
    pass.passTypeIdentifier = "pass.com.task.mio-pass";
    pass.serialNumber = "123456";
    pass.teamIdentifier = "P8MH6VJGC7";
    pass.organizationName = "T.A.S.K. SRL";
    pass.description = "Tessera Socio";
    pass.foregroundColor = "rgb(255, 255, 255)";
    pass.backgroundColor = "rgb(60, 60, 60)";

    // Definiamo la struttura del pass
    pass.generic = {
      primaryFields: [
        {
          key: "member",
          label: "Membro",
          value: "Mario Rossi"
        }
      ]
    };

    // Definiamo i codici a barre
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
