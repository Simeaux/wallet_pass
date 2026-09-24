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

    // Carica il certificato intermedio WWDR e il certificato signer
    const signerCert = Buffer.from(base64Cert, "base64");

    // Nuovo metodo corretto di istanziazione per passkit-generator
    const pass = await PKPass.fromFolder(path.resolve(__dirname, "./MioPass.raw"));
    
    // Associa le chiavi di firma
    pass.setSigner(signerCert, passphrase);

    // Compila il buffer fisico del pass
    const actualPass = pass.getAsBuffer();
    
    // Salva il file definitivo nella root
    const outputPath = path.resolve(__dirname, "./MioPass.pkpass");
    fs.writeFileSync(outputPath, actualPass);
    
    console.log("-> COMPILATO CON SUCCESSO IN: " + outputPath);
  } catch (error) {
    console.error("!!! ERRORE CRITICO NELLO SCRIPT !!!");
    console.error(error);
    process.exit(1);
  }
}

createPass();
