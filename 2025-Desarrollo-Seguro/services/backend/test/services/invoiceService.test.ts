import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

import InvoiceService from '../../src/services/invoiceService';
import db from '../../src/db';
import { Invoice } from '../../src/types/invoice';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>


describe('AuthService.generateJwt', () => {
  beforeEach (() => {
    jest.resetModules();
  });

  beforeAll(() => {
  });

  afterAll(() => {
  });

  it('listInvoices', async () => {
    const userId = 'user123';
    const state = 'paid';
    const operator = '='; // Cambiado de 'eq' a '=' para que sea válido
    const mockInvoices: Invoice[] = [
      { id: 'inv1', userId, amount: 100, dueDate: new Date(), status: 'paid' },
      { id: 'inv2', userId, amount: 200, dueDate: new Date(), status: 'paid' }
    ];
    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue(mockInvoices),
    };
    mockedDb.mockReturnValue(selectChain as any);

    const invoices = await InvoiceService.list(userId, state, operator);

    expect(mockedDb().where).toHaveBeenCalledWith({ userId });
    expect(mockedDb().andWhere).toHaveBeenCalledWith('status', operator, state);
    expect(mockedDb().select).toHaveBeenCalled();
    expect(invoices).toEqual(mockInvoices);
  });

  it('listInvoices no state', async () => {
    const userId = 'user123';
    const mockInvoices: Invoice[] = [
      { id: 'inv1', userId, amount: 100, dueDate: new Date(), status: 'paid' },
      { id: 'inv2', userId, amount: 200, dueDate: new Date(), status: 'unpaid' }
    ];
    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      select: jest.fn().mockResolvedValue(mockInvoices),
    };
    mockedDb.mockReturnValue(selectChain as any);
    const invoices = await InvoiceService.list(userId);

    expect(mockedDb().where).toHaveBeenCalledWith({ userId });
    expect(mockedDb().andWhere).not.toHaveBeenCalled();
    expect(mockedDb().select).toHaveBeenCalled();
    expect(invoices).toEqual(mockInvoices);
  });
  
  /**
   * PRUEBA DE SEGURIDAD: SQL Injection Prevention
   * 
   * Esta prueba verifica que el sistema esté protegido contra SQL Injection
   * en la funcionalidad de listado de facturas. Un atacante podría intentar
   * inyectar código SQL malicioso en los parámetros 'status' u 'operator'
   * para obtener datos no autorizados o manipular la base de datos.
   * 
   * Escenario de ataque:
   * - El atacante envía parámetros maliciosos en la URL:
   *   /invoices?status=paid' OR '1'='1&operator==
   * - Si el código es vulnerable (usa andWhereRaw con concatenación),
   *   la consulta SQL se manipula y devuelve todas las facturas
   * 
   * Mitigación esperada:
   * - Validar que 'operator' esté en lista blanca de operadores permitidos
   * - Validar que 'status' esté en lista blanca de estados permitidos
   * - Usar consultas parametrizadas en lugar de concatenación SQL
   * 
   * Esta prueba debe:
   * - FALLAR en la rama 'main' (código vulnerable con andWhereRaw)
   * - PASAR en la rama 'practico-2' (código mitigado con validaciones)
   */
  describe('SQL Injection Prevention', () => {
    
    it('should reject malicious SQL injection in status parameter', async () => {
      const userId = 'user123';
      // Intento de SQL injection: cerrar la cadena y agregar condición siempre verdadera
      const maliciousStatus = "paid'; DROP TABLE invoices; --";
      const operator = '=';
      
      // Con el código mitigado, esto debe lanzar un error
      await expect(InvoiceService.list(userId, maliciousStatus, operator))
        .rejects.toThrow('Invalid status');
    });

    it('should reject malicious SQL injection in operator parameter', async () => {
      const userId = 'user123';
      const status = 'paid';
      // Intento de SQL injection a través del operador
      const maliciousOperator = "= OR 1=1 --";
      
      // Con el código mitigado, esto debe lanzar un error
      await expect(InvoiceService.list(userId, status, maliciousOperator))
        .rejects.toThrow('Invalid operator');
    });

    it('should reject SQL injection attempting to bypass authentication', async () => {
      const userId = 'user123';
      // Intento clásico de SQL injection: hacer que la condición siempre sea verdadera
      const maliciousStatus = "paid' OR '1'='1";
      const operator = '=';
      
      // Con el código mitigado, esto debe lanzar un error
      await expect(InvoiceService.list(userId, maliciousStatus, operator))
        .rejects.toThrow('Invalid status');
    });

    it('should reject SQL injection with UNION attack', async () => {
      const userId = 'user123';
      // Intento de UNION SQL injection para extraer datos de otras tablas
      const maliciousStatus = "paid' UNION SELECT * FROM users --";
      const operator = '=';
      
      // Con el código mitigado, esto debe lanzar un error
      await expect(InvoiceService.list(userId, maliciousStatus, operator))
        .rejects.toThrow('Invalid status');
    });

    it('should accept valid status and operator values', async () => {
      const userId = 'user123';
      const validStatus = 'paid';
      const validOperator = '=';
      const mockInvoices: Invoice[] = [
        { id: 'inv1', userId, amount: 100, dueDate: new Date(), status: 'paid' }
      ];
      
      const selectChain = {
        where: jest.fn().mockReturnThis(),
        andWhere: jest.fn().mockReturnThis(),
        select: jest.fn().mockResolvedValue(mockInvoices),
      };
      mockedDb.mockReturnValue(selectChain as any);

      // Con valores válidos, la consulta debe ejecutarse correctamente
      const invoices = await InvoiceService.list(userId, validStatus, validOperator);
      
      expect(invoices).toEqual(mockInvoices);
      expect(selectChain.andWhere).toHaveBeenCalledWith('status', validOperator, validStatus);
    });

    it('should only allow whitelisted operators', async () => {
      const userId = 'user123';
      const status = 'paid';
      
      // Operadores válidos que deben ser aceptados
      const validOperators = ['=', '!=', '<>', '<', '>', '<=', '>='];
      
      for (const operator of validOperators) {
        const selectChain = {
          where: jest.fn().mockReturnThis(),
          andWhere: jest.fn().mockReturnThis(),
          select: jest.fn().mockResolvedValue([]),
        };
        mockedDb.mockReturnValue(selectChain as any);
        
        // No debe lanzar error con operadores válidos
        await expect(InvoiceService.list(userId, status, operator)).resolves.toBeDefined();
      }
      
      // Operadores inválidos que deben ser rechazados
      const invalidOperators = ['LIKE', 'IN', 'OR', 'AND', '; DROP TABLE'];
      
      for (const operator of invalidOperators) {
        await expect(InvoiceService.list(userId, status, operator))
          .rejects.toThrow('Invalid operator');
      }
    });

    it('should only allow whitelisted status values', async () => {
      const userId = 'user123';
      const operator = '=';
      
      // Estados válidos que deben ser aceptados
      const validStatuses = ['pending', 'paid', 'cancelled', 'overdue'];
      
      for (const status of validStatuses) {
        const selectChain = {
          where: jest.fn().mockReturnThis(),
          andWhere: jest.fn().mockReturnThis(),
          select: jest.fn().mockResolvedValue([]),
        };
        mockedDb.mockReturnValue(selectChain as any);
        
        // No debe lanzar error con estados válidos
        await expect(InvoiceService.list(userId, status, operator)).resolves.toBeDefined();
      }
      
      // Estados inválidos que deben ser rechazados
      const invalidStatuses = ['invalid', 'hacked', "'; DROP TABLE invoices; --"];
      
      for (const status of invalidStatuses) {
        await expect(InvoiceService.list(userId, status, operator))
          .rejects.toThrow('Invalid status');
      }
    });
  });

});
