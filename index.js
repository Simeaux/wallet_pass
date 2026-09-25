const { PKPass } = require("passkit-generator");
const fs = require("fs");
const path = require("path");

async function createPass() {
  try {
    const base64Cert = process.env.APPLE_PASS_CERT; 
    const passphrase = process.env.APPLE_PASS_PASSWORD;
    const rawWwdr = process.env.APPLE_WWDR_CERT; // Prende il certificato PEM direttamente da GitHub Secrets

    // Controllo di sicurezza preventivo
    if (!base64Cert || !passphrase || !rawWwdr) {
      throw new Error("Mancano le configurazioni nei segreti di GitHub (CERT, PASSWORD o WWDR).");
    }

    // Il file .p12 (base64) contiene sia certificato che chiave privata
    const p12Buffer = Buffer.from(base64Cert, "base64");

    // Carichiamo le immagini obbligatorie dal modello
    const modelPath = path.resolve(__dirname, "./MioPass.raw");
    const iconBuffer = fs.readFileSync(path.join(modelPath, "icon.png"));
    const logoBuffer = fs.readFileSync(path.join(modelPath, "logo.png"));

    // Inizializzazione ufficiale di passkit-generator: 
    // 1° parametro: Dati del Pass (JSON)
    // 2° parametro: Certificati
    const pass = new PKPass({
      type: "generic",
      formatVersion: 1,
      passTypeIdentifier: "pass.com.task.mio-pass",
      serialNumber: "123456",
      teamIdentifier: "P8MH6VJGC7",
      organizationName: "T.A.S.K. SRL",
      description: "Tessera Socio",
      foregroundColor: "rgb(255, 255, 255)",
      backgroundColor: "rgb(60, 60, 60)",
      generic: {
        primaryFields: [
          {
            key: "member",
            label: "Membro",
            value: "Mario Rossi"
          }
        ]
      },
      barcodes: [
        {
          format: "PKBarcodeFormatQR",
          message: "https://tuosito.com",
          messageEncoding: "iso-8859-1"
        }
      ]
    }, {
      wwdr: rawWwdr, // Iniezione diretta del testo PEM del segreto GitHub
      signerCert: p12Buffer,
      signerKey: p12Buffer,
      signerKeyPassphrase: passphrase
    });

    // Iniezione dei file multimediali obbligatori
    pass.addBuffer("icon.png", iconBuffer);
    pass.addBuffer("logo.png", logoBuffer);

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
