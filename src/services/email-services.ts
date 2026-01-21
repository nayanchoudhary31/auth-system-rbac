import nodemailer from "nodemailer";
import dotenv from 'dotenv'

dotenv.config();


type SendEmailInput = {
    to: string;
    subject: string;
    html: string;
}

let cachedTransporter: nodemailer.Transporter | null = null;

export async function getTransporter() {
    if (cachedTransporter) return cachedTransporter;

    const provider = process.env.EMAIL_PROVIDER || "ethereal";

    console.log(`Using the testing ethereal ${provider}`)
    const testAccount = await nodemailer.createTestAccount()

    cachedTransporter = nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
            user: testAccount.user,
            pass: testAccount.pass
        }
    })

    console.log("Ethereal account ready:", {
        user: testAccount.user,
        pass: testAccount.pass,
    });

    return cachedTransporter;
}


export async function sendEmail(input: SendEmailInput) {
    const transporter = await getTransporter();

    const from = process.env.SMTP_FROM || "no-reply@example.com";
    const info = await transporter.sendMail({
        from,
        to: input.to,
        subject: input.subject,
        html: input.html,
    });

    // Ethereal preview URL (only works for ethereal)
    const previewUrl = nodemailer.getTestMessageUrl(info);
    if (previewUrl) console.log("Email preview:", previewUrl);

    return info;
}




