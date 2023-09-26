import nodemailer from 'nodemailer';
import { User } from '../entities/user.entity';
import config from 'config';
import pug from 'pug';
import { convert } from 'html-to-text';

const smtp = config.get<{
  host: string;
  port: number;
  user: string;
  pass: string;
}>('smtp');

export default class Email {
  firstName: string;
  to: string;
  from: string;
  constructor(public user: User, public url: string) {
    this.firstName = user.name.split(' ')[0];
    this.to = user.email;
    this.from = `Codevo ${config.get<string>('emailFrom')}`;
  }

  private newTransport() {
    // if (process.env.NODE_ENV === 'production') {
    //   console.log('Hello')
    // }

    return nodemailer.createTransport({
      ...smtp,
      auth: {
        user: smtp.user,
        pass: smtp.pass,
      },
    });
  }

  private async send(template: string, subject: string) {
 
    const html = pug.renderFile(`${__dirname}/../views/${template}.pug`, {
      firstName: this.firstName,
      subject,
      url: this.url,
    });

    const mailOptions = {
      from: this.from,
      to: this.to,
      subject,
      text: convert(html),
      html,
    };

    const info = await this.newTransport().sendMail(mailOptions);
    console.log(nodemailer.getTestMessageUrl(info));
  }

  async sendVerificationCode() {
    await this.send('verificaçãoCode', 'Sua conta foi verificada');
  }

  async sendPasswordResetToken() {
    await this.send(
      'resetSenha',
      'Sua senha foi resetada com token (valido por 10 minutos )'
    );
  }
}
