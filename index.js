const { PKPass } = require("passkit-generator");
const fs = require("fs");
const path = require("path");

// Certificato ufficiale Apple WWDR Authority (G4) integrato direttamente in formato PEM standard
const appleWWDRCertificate = `-----BEGIN CERTIFICATE-----
MIIDFjCCApygAwIBAgIUIsGhRwp0c2nvU4YSycafPTjzbNcwCgYIKoZIzj0EAwMw
ZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBD
ZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkG
A1UEBhMCVVMwHhcNMjEwMzE3MjAzNzEwWhcNMzYwMzE5MDAwMDAwWjB1MUQwQgYD
VQQDDDtBcHBsZSBXb3JsZHdpZGUgRGV2ZWxvcGVyIFJlbGF0aW9ucyBDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0eTELMAkGA1UECwwCRzYxEzARBgNVBAoMCkFwcGxlIElu
Yy4xCzAJBgNVBAYTAlVTMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbsQKC94PrlWm
ZXnXgtxzdVJL8T0SGYngDRGpngn3N6PT8JMEb7FDi4bBmPhCnZ3/sq6PF/cGcKXW
sL5vOteRhyJ45x3ASP7cOB+aao90fcpxSv/EZFbniAbNgZGhIhpIo4H6MIH3MBIG
A1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgwFoAUu7DeoVgziJqkipnevr3rr9rL
JKswRgYIKwYBBQUHAQEEOjA4MDYGCCsGAQUFBzABhipodHRwOi8vb2NzcC5hcHBs
ZS5jb20vb2NzcDAzLWFwcGxlcm9vdGNhZzMwNwYDVR0fBDAwLjAsoCqgKIYmaHR0
cDovL2NybC5hcHBsZS5jb20vYXBwbGVyb290Y2FnMy5jcmwwHQYDVR0OBBYEFD8v
lCNR01DJmig97bB85c+lkGKZMA4GA1UdDwEB/wQEAwIBBjAQBgoqhkiG92NkBgIB
BAIFADAKBggqhkjOPQQDAwNoADBlAjBAXhSq5IyKogMCPtw490BaB677CaEGJXuf
QB/EqZGd6CSjiCtOnuMTbXVXmxxcxfkCMQDTSPxarZXvNrkxU3TkUMI33yzvFVVR
T4wxWJC994OsdcZ4+RGNsYDyR5gmdr0nDGg=
-----END CERTIFICATE-----
`;
async function createPass() 
{
    try {
        const base64Cert = process.env.APPLE_PASS_CERT;
        const passphrase = process.env.APPLE_PASS_PASSWORD;
        if (!base64Cert || !passphrase) {
            throw new Error("Mancano le configurazioni nei segreti di GitHub (CERT o PASSWORD).");
        }
        const signerCert = Buffer.from(base64Cert, "base64");
        // Carichiamo le immagini obbligatorie localmenteconst 
        modelPath = path.resolve(__dirname, "./MioPass.raw");
        const iconBuffer = fs.readFileSync(path.join(modelPath, "icon.png"));
        const logoBuffer = fs.readFileSync(path.join(modelPath, "logo.png"));
        // Creazione della classe con tutti i certificati iniettati programmaticamente
        
        const pass = new PKPass({
            model: {
                "icon.png": iconBuffer,
                "logo.png": logoBuffer
            },
            certificates: {
                wwdr: appleWWDRCertificate, // Iniezione diretta della costante PEM fissa (G4)
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
                primaryFields: [{
                    key: "member",
                    label: "Membro",
                    value: "Mario Rossi"
                }]
            },
            barcodes: [{
                format: "PKBarcodeFormatQR",
                message: "https://tuosito.com",
                messageEncoding: "iso-8859-1"
            }]
        });
const actualPass = await pass.getAsBuffer();
// Sostituisci la vecchia configurazione di outputPath con questa:
const outputPath = path.join(process.cwd(), "MioPass.pkpass");
fs.writeFileSync(outputPath, actualPass);

console.log("-> FILE GENERATO CON SUCCESSO IN: " + outputPath);

console.log("-> FILE GENERATO CON SUCCESSO IN: " + outputPath);
} catch (error) {
    console.error("!!! ERRORE CRITICO NELLO SCRIPT !!!");
    console.error(error);
    process.exit(1);
}
}
createPass();