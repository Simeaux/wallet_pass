const { PKPass } = require("passkit-generator");
const fs = require("fs");
const path = require("path");

async function createPass() {
  try {
    const base64Cert = process.env.APPLE_PASS_CERT; 
    const passphrase = process.env.APPLE_PASS_PASSWORD;
    const rawWwdr = process.env.APPLE_WWDR_CERT; // Legge il segreto PEM che hai salvato su GitHub

    if (!base64Cert || !passphrase || !rawWwdr) {
      throw new Error("Mancano le configurazioni nei segreti di GitHub (CERT, PASSWORD o WWDR).");
    }

    const signerCert = Buffer.from(base64Cert, "base64");

    // Converte il certificato WWDR nel buffer corretto (accetta sia testo PEM che Base64)
    const wwdrCert = rawWwdr.includes("-----BEGIN CERTIFICATE-----") 
      ? Buffer.from(rawWwdr, "utf-8") 
      : Buffer.from(rawWwdr, "base64");

    // Carichiamo le immagini obbligatorie
    const modelPath = path.resolve(__dirname, "./MioPass.raw");
    const iconBuffer = fs.readFileSync(path.join(modelPath, "icon.png"));
    const logoBuffer = fs.readFileSync(path.join(modelPath, "logo.png"));

    // Creazione del pass con iniezione dinamica dei buffer
    const pass = new PKPass({
      model: {
        "icon.png": iconBuffer,
        "logo.png": logoBuffer
      },
      certificates: {
        wwdr: wwdrCert,
        signerCert: signerCert,
        signerKeyPassphrase: passphrase
      }
    }, {
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
    });

    // Forza l'attesa asincrona per la firma e compressione
    console.log("-> Compressione e firma del pass in corso...");
    const actualPass = await pass.getAsBuffer();
    
    // Salvataggio nella cartella root principale
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
