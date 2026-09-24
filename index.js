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

    // Trasforma la stringa di testo di GitHub nel buffer binario del file .p12
    const signerCert = Buffer.from(base64Cert, "base64");

    // Nuovo formato corretto: Inizializzazione della classe con l'oggetto di configurazione
    const pass = new PKPass({
      model: path.resolve(__dirname, "./MioPass.raw"), // La cartella con immagini e pass.json
      certificates: {
        signerCert: signerCert,
        signerKeyPassphrase: passphrase
      }
    });

    // Compila i file e genera il pacchetto finale
    const actualPass = pass.getAsBuffer();
    
    // Salva il file definitivo nella root
    const outputPath = path.resolve(__dirname, "./MioPass.pkpass");
    fs.writeFileSync(outputPath, actualPass);
    
    console.log("-> FILE GENERATO CON SUCCESSO IN: " + outputPath);
  } catch (error) {
    console.error("!!! ERRORE CRITICO NELLO SCRIPT !!!");
    console.error(error);
    process.exit(1); // Forza il fallimento su GitHub se qualcosa va storto
  }
}

createPass();
