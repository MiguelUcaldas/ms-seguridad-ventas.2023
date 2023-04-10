import {authenticate} from '@loopback/authentication';
import {service} from '@loopback/core';
import {
  Count,
  CountSchema,
  Filter,
  FilterExcludingWhere,
  repository,
  Where,
} from '@loopback/repository';
import {
  del,
  get,
  getModelSchemaRef,
  HttpErrors,
  param,
  patch,
  post,
  put,
  requestBody,
  response,
} from '@loopback/rest';
import {Credenciales, FactorDeAutentificacionPorCodigo, Login, Usuario} from '../models';
import {LoginRepository, UsuarioRepository} from '../repositories';
import {SeguridadUsuarioService} from '../services';

export class UsuarioController {
  constructor(
    @repository(UsuarioRepository)
    public usuarioRepository: UsuarioRepository,
    @service(SeguridadUsuarioService)
    public servicioSeguridad: SeguridadUsuarioService,
    @repository(LoginRepository)
    public repositoriLogin: LoginRepository

  ) { }

  @post('/usuario')
  @response(200, {
    description: 'Usuario model instance',
    content: {'application/json': {schema: getModelSchemaRef(Usuario)}},
  })
  async create(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {
            title: 'NewUsuario',
            exclude: ['_id'],
          }),
        },
      },
    })
    usuario: Omit<Usuario, '_id'>,
  ): Promise<Usuario> {

    // crear clave

    let clave = this.servicioSeguridad.crearTextoAleatorio(10);

    console.log(clave);


    //cifrar clave

    let claveCifrada = this.servicioSeguridad.cifrarTexto(clave);

    //asignar clave cifrada al usuario

    usuario.clave = claveCifrada;

    //enviar correo electronico de notificacion

    // queda pendiente

    return this.usuarioRepository.create(usuario);
  }

  @get('/usuario/count')
  @response(200, {
    description: 'Usuario model count',
    content: {'application/json': {schema: CountSchema}},
  })
  async count(
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.count(where);
  }
  @authenticate('auth')
  @get('/usuario')
  @response(200, {
    description: 'Array of Usuario model instances',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: getModelSchemaRef(Usuario, {includeRelations: true}),
        },
      },
    },
  })
  async find(
    @param.filter(Usuario) filter?: Filter<Usuario>,
  ): Promise<Usuario[]> {
    return this.usuarioRepository.find(filter);
  }

  @patch('/usuario')
  @response(200, {
    description: 'Usuario PATCH success count',
    content: {'application/json': {schema: CountSchema}},
  })
  async updateAll(
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
    @param.where(Usuario) where?: Where<Usuario>,
  ): Promise<Count> {
    return this.usuarioRepository.updateAll(usuario, where);
  }

  @get('/usuario/{id}')
  @response(200, {
    description: 'Usuario model instance',
    content: {
      'application/json': {
        schema: getModelSchemaRef(Usuario, {includeRelations: true}),
      },
    },
  })
  async findById(
    @param.path.string('id') id: string,
    @param.filter(Usuario, {exclude: 'where'}) filter?: FilterExcludingWhere<Usuario>
  ): Promise<Usuario> {
    return this.usuarioRepository.findById(id, filter);
  }

  @patch('/usuario/{id}')
  @response(204, {
    description: 'Usuario PATCH success',
  })
  async updateById(
    @param.path.string('id') id: string,
    @requestBody({
      content: {
        'application/json': {
          schema: getModelSchemaRef(Usuario, {partial: true}),
        },
      },
    })
    usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.updateById(id, usuario);
  }

  @put('/usuario/{id}')
  @response(204, {
    description: 'Usuario PUT success',
  })
  async replaceById(
    @param.path.string('id') id: string,
    @requestBody() usuario: Usuario,
  ): Promise<void> {
    await this.usuarioRepository.replaceById(id, usuario);
  }

  @del('/usuario/{id}')
  @response(204, {
    description: 'Usuario DELETE success',
  })
  async deleteById(@param.path.string('id') id: string): Promise<void> {
    await this.usuarioRepository.deleteById(id);
  }


  /**
   * metodos personalizados para la API
   */

  @post('/identificar-usuario')
  @response(200, {
    description: "identificar un usuario por correo y clave",
    content: {'aplication/json': {schema: getModelSchemaRef(Usuario)}}
  })
  async identificarUsuario(
    @requestBody(
      {
        content: {
          'aplication/json': {
            schema: getModelSchemaRef(Credenciales)
          }
        }
      }

    )
    credenciales: Credenciales

  ): Promise<object> {

    let usuario = await this.servicioSeguridad.identificarUsuario(credenciales);
    if (usuario) {
      let codigo2 = this.servicioSeguridad.crearTextoAleatorio(5);
      let login: Login = new Login();
      login.usuarioId = usuario._id!;
      login.codigo2fa = codigo2;
      login.estadoCodigo2fa = false;
      login.token = "";
      login.estadoToken = false;
      this.repositoriLogin.create(login);
      //notificar al usuario via correo o sms
      usuario.clave = "";
      return usuario;
    }

    return new HttpErrors[401]("Credenciales incorrectas")

  }

  // segunda funcion

  @post('/verificar-2fa')
  @response(200, {
    description: "validar un codigo de segundo valor de autentificacion",
    content: {'aplication/json': {schema: getModelSchemaRef(FactorDeAutentificacionPorCodigo)}}
  })
  async verificarCodigo2fa(
    @requestBody(
      {
        content: {
          'aplication/json': {
            schema: getModelSchemaRef(FactorDeAutentificacionPorCodigo)
          }
        }
      }

    )
    credenciales: FactorDeAutentificacionPorCodigo

  ): Promise<object> {

    let usuario = await this.servicioSeguridad.valirdarCodigo2fa(credenciales);
    if (usuario) {
      let token = this.servicioSeguridad.crearToken(usuario);
      if (usuario) {
        usuario.clave = "";
        try {
          let login = await this.repositoriLogin.findOne({
            where: {
              usuarioId: usuario._id,
              estadoCodigo2fa: false
            }
          });
          login!.estadoCodigo2fa = true;
          this.repositoriLogin.updateById(login?._id, login!);
        } catch {
          console.log("No se ha almacenado el cambio del estado del token en la base de datos")
        }
        return {
          user: usuario,
          token: token
        };
      }
    }
    return new HttpErrors[401]("Codigo 2fa invalido para el usuario definido");

  }


}
