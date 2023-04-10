import {AuthenticationBindings, AuthenticationMetadata, AuthenticationStrategy} from '@loopback/authentication';
import {Request} from '@loopback/rest/dist/types';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {serialize} from 'v8';
import {SeguridadUsuarioService} from '../services';
import {inject, service} from '@loopback/core';
import {RolMenu} from '../models';
import {RolMenuRepository} from '../repositories';
import {repository} from '@loopback/repository';
import {HttpErrors} from '@loopback/rest';



export class AuthStrategy implements AuthenticationStrategy {
  name: string = 'auth';

  constructor(
    @service(SeguridadUsuarioService)
    private servicioSeguridad: SeguridadUsuarioService,
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata,
    @repository(RolMenuRepository)
    private repositorioRolMenu: RolMenuRepository
  ) {

  }

  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request);
    if (token) {
      let idRol = this.servicioSeguridad.obtenerRolDdesdeToken(token);
      let idMenu: string = this.metadata.options![0];
      let accion: string = this.metadata.options![1];

      let permiso = await this.repositorioRolMenu.findOne({
        where: {
          rolId: idRol,
          menuId: idMenu
        }
      });
      let continuar: boolean = false;

      if (permiso) {
        switch (accion) {
          case "guardar":
            continuar = permiso.guardar;
            break;
          case "listar":
            continuar = permiso.listar;
            break;
          case "eliminar":
            continuar = permiso.eliminar;
            break;
          case "descargar":
            continuar = permiso.descargar;
            break;
          case "editar":
            continuar = permiso.editar;
            break;
          default:
            throw new HttpErrors[401]("No es posible ejecutar la accion No existe.");

        }
        if (continuar) {
          let perfil: UserProfile = Object.assign({
            permitido: "OK"
          });
          return perfil
        } else {
          return undefined;
        }


      } else {
        throw new HttpErrors[401]("No es posible ejecutar la accion por falta de permisos");
      }

    }
    throw new HttpErrors[401]("No es posible ejecutar la accion por falta de un token");
  }


}
