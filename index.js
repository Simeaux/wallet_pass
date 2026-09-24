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

    // Leggiamo esplicitamente i file delle immagini obbligatorie dalla cartella
    const modelPath = path.resolve(__dirname, "./MioPass.raw");
    const iconBuffer = fs.readFileSync(path.join(modelPath, "icon.png"));
    const logoBuffer = fs.readFileSync(path.join(modelPath, "logo.png"));

    // Creazione del pass con iniezione programmatica dei dati e del tipo
    const pass = new PKPass({
      // Passiamo i file multimediali come buffer associati
      model: {
        "icon.png": iconBuffer,
        "logo.png": logoBuffer
      },
      certificates: {
        signerCert: signerCert,
        signerKeyPassphrase: passphrase
      }
    }, {
      // Iniezione diretta dell'oggetto pass.json per evitare problemi di lettura
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

    // Compila il pass finale
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
