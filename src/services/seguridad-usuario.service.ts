import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import {repository} from '@loopback/repository';
import {Credenciales, Usuario} from '../models';
import {UsuarioRepository} from '../repositories';

const generator = require('generate-password');
const MD5 = require("crypto-js/md5");



@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository

  ) { }

  /*
   * Add service methods here
   */

  /**
   * crea clave aleatoria con n caracteres
   * @returns cadena con clave aleatoria
   */
  crearTextoAleatorio(n: number): string {
    let clave = generator.generate({
      length: n,
      numbers: true
    });
    return clave;
  }

  /**
   *
   * @param cadena cifra una cadena entrante
   * @returns devuelve un string de la cadena entrante cifrada
   */

  cifrarTexto(cadena: string): string {

    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada
  }

  /**
   * se busca un usuario por sus credenciales de aceso
   * @param credenciales credenciales del usuario
   * @returns usuario encontrado o null
   */

  async identificarUsuario(credenciales: Credenciales): Promise<Usuario | null> {
    let usuario = await this.repositorioUsuario.findOne({
      where: {
        correo: credenciales.correo,
        clave: credenciales.clave
      }

    });

    return usuario as Usuario
  }

}
