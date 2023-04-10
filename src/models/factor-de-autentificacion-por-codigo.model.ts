import {Model, model, property} from '@loopback/repository';

@model()
export class FactorDeAutentificacionPorCodigo extends Model {
  @property({
    type: 'string',
    required: true,
  })
  usuarioId: string;

  @property({
    type: 'string',
    required: true,
  })
  codigo2fa: string;


  constructor(data?: Partial<FactorDeAutentificacionPorCodigo>) {
    super(data);
  }
}

export interface FactorDeAutentificacionPorCodigoRelations {
  // describe navigational properties here
}

export type FactorDeAutentificacionPorCodigoWithRelations = FactorDeAutentificacionPorCodigo & FactorDeAutentificacionPorCodigoRelations;
