# Práctico 2 - Desarollo de Software Seguro

## Detección de Vulnerabilidades:

### 1. Inyección SQL (sqli)
Esta vulnerabilidad se encontraba en el backend; archivo invoiceService.ts en la línea 19 donde decía esto:

    if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");

El flujo de la vulnerabilidad empieza en invoiceController.ts en las lineas 7-8:

    const state = req.query.status as string | undefined;
    const operator = req.query.operator as string | undefined;

Aquí entran los parámetros y se pasan directamente al servicio sin validación.
Un atacante puede venir y directamente desde el navegador, poner un URL malicioso como por ejemplo:

"_https://tuapp.com/invoices?status=paid'%20OR%201=1%20--%20&operator==_"

El %20 es espacio y -- es comentario SQL, entonces si eso lo convertimos queda como **status = "paid' OR 1=1 -- "** lo que significa que primero cierra la cadena original, y depsués manda una condición que siempre va dar true, mientras commenta el resto de la consulta.Esto hace que después el atacante obtenga _todas_ las facturas de _todos_ los usuarios.

Después de corregirlo, se modifiqué el archivo invoiceService.test.ts poniéndo esta línea de código donde confirma que la validación funciona.

    await expect(InvoiceService.list(userId, maliciousState, operator)).rejects.toThrow('Invalid operator');

---
### 2. Credenciales embebidas (Hard Coded Credentials).

Esta vulnerabilidad estaba en el archivo auth.middleware.ts:

    const decoded = jwt.verify(token, "secreto_super_seguro");

En este caso, un atacante puede acceder al repositorio/despliegue donde el código está disponible y leer la clave secreta. Después puede crear un token jwt falso y lo firma usando la clave; despupes envía el token al backend, específicamente en el header (_Authorization: Bearer <token_falso>_) y le da acceso como si fuera el usuario del payload.

Para mitigarlo modifiqué el código para que la clave secreta la tome desde una variable de entorno que está creada en .env.example en el backend. Ahora sí la clave ya no está expuesta.

Lo probé en Postman para verificar que estuviera andando.

![Login autorizado en Postman](services/frontend/src/photos/loginAutorizadoPostman.png)