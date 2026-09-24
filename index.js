const { PKPass } = require("passkit-generator");
const fs = require("fs");
const path = require("path");

async function createPass() {
  try {
    const base64Cert = process.env.APPLE_PASS_CERT; 
    const passphrase = process.env.APPLE_PASS_PASSWORD;

    if (!base64Cert || !passphrase) {
      throw new Error("Mancano le configurazioni nei segreti di GitHub.");
    }

    const signerCert = Buffer.from(base64Cert, "base64");

    // Configurazione aggiornata secondo le ultime specifiche della libreria
    const pass = new PKPass({
      model: path.resolve(__dirname, "./MioPass.raw"),
      type: "generic", // Forzatura esplicita dello stile del pass
      certificates: {
        signerCert: signerCert,
        signerKeyPassphrase: passphrase
      },
      overrides: {
        // Reinseriamo l'informazione anche nelle opzioni di override per sicurezza
        type: "generic"
      }
    });

    const actualPass = pass.getAsBuffer();
    
    const outputPath = path.resolve(__dirname, "./MioPass.pkpass");
    fs.writeFileSync(outputPath, actualPass);
    
    console.log("-> FILE GENERATO CON SUCCESSO IN: " + outputPath);
  } catch (error) {
    console.error("!!! ERRORE CRITICO NELLO SCRIPT !!!");
    console.error(error);
    process.exit(1);
  }
}

createPass();
