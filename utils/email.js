const nodemailer = require('nodemailer');
const pug = require('pug');
const {htmlToText} = require('html-to-text');
const sendgridTransport = require('nodemailer-sendgrid-transport');
const dotenv = require('dotenv');
dotenv.config(); // Looks for .env in root
 //console.log('Using API Key:', process.env.MAIL_API_KEY ? 'Found' : 'Missing or undefined');
 //console.log('Using Email From:', process.env.EMAIL_FROM ? 'Found' : 'Missing or undefined');
//const sgMail = require('@sendgrid/mail');
module.exports = class Email {
  constructor(user, url) {
    this.to = user.email;
    this.firstName = user.fullName;
    this.url = url;
    this.from = process.env.EMAIL_FROM;
   

  }

// sgMail.setApiKey('');

  newTransport() {
    if (process.env.NODE_ENV === 'development') {
      return nodemailer.createTransport(
        sendgridTransport({
          auth: {
            api_key:process.env.EMAIL_API_KEY    
          },
        })
      );
    }
  }
  async send(template, subject) {
    const html = pug.renderFile(`${__dirname}/../views/email/${template}.pug`, {
      firstName: this.firstName,
      url: this.url,
      subject
    });

   // console.log(html)
    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      html,
      text: htmlToText(html)
    };

    await this.newTransport().sendMail(mailOptions);
  }

  async sendWelcome() {

    await this.send('welcome', 'Welcome to the Electro Zenix Family!');
  }
  async sendLogin() {

    await this.send('login', 'Login Successfull to Electro Zenix!');
  }
  async sendPasswordReset() {
    await this.send(
      'passwordReset',
      'Your password reset token (valid for only 10 minutes)'
    );
  }
};
