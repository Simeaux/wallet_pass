const { Pass } = require("passkit-generator");
const fs = require("fs");
const path = require("path");

async function createPass() {
  const base64Cert = process.env.APPLE_PASS_CERT; 
  const passphrase = process.env.APPLE_PASS_PASSWORD;

  if (!base64Cert || !passphrase) {
    throw new Error("Mancano le configurazioni nei segreti di GitHub.");
  }

  const signerCert = Buffer.from(base64Cert, "base64");

  // Nota: usiamo il nome esatto della tua cartella "MioPass.raw"
  const pass = await Pass.fromFolder(path.resolve(__dirname, "./MioPass.raw"));
  pass.setSigner(signerCert, passphrase);

  const actualPass = pass.getAsBuffer();
  fs.writeFileSync("./MioPass.pkpass", actualPass);
  console.log("Pass compilato e firmato con successo!");
}

createPass().catch(console.error);
