const { Pass } = require("passkit-generator");
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

    // Inizializza il pass
    const pass = await Pass.fromFolder(path.resolve(__dirname, "./MioPass.raw"));
    
    // Configura le chiavi per la firma
    pass.setSigner(signerCert, passphrase);

    // Compila
    const actualPass = await pass.getAsBuffer();
    
    // Salva il file nella root principale
    const outputPath = path.resolve(__dirname, "./MioPass.pkpass");
    fs.writeFileSync(outputPath, actualPass);
    
    console.log("-> FILE GENERATO CON SUCCESSO IN: " + outputPath);
  } catch (error) {
    console.error("!!! ERRORE CRITICO DURANTE LA GENERAZIONE !!!");
    console.error(error);
    process.exit(1); // Forza il fallimento della build di GitHub per mostrarci i dettagli
  }
}

createPass();
