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

Para mitigarlo modifiqué el código para que la clave secreta la tome desde una variable de entorno que está creada en .env en el backend. Ahora sí la clave ya no está expuesta.

Lo probé en Postman para verificar que estuviera andando con un POST /auth/login y un GET /invoices:

![Login autorizado en Postman](2025-Desarrollo-Seguro/services/frontend/src/photos/loginAutorizadoPostman.png)


![Solicitud Protegida](2025-Desarrollo-Seguro/services/frontend/src/photos/solicitudProtegida.png)

---
### 3. Falsificación de Peticiones del Lado del Servidor (Server Side Request Fogery - SSRF)

En el método setPaymentCard de invoiceService.ts se ubica esta vulnerabilidad:

    const paymentResponse = await axios.post(`http://${paymentBrand}/payments`, {
    ccNumber,
    ccv,
    expirationDate
    });

Esto es porque el parámetro paymentBrand viene de la solicitud del usuario y se usa directamente para construir una URL externa. Un atacante puede manipular este valor para hacer que el backend realice solicitudes a cualquier servidor.

Para explotar la vulnerabilidad primero se hace una solicitud al endpoint de pago y en el body se pone un valor malicioso:

    paymentBrand: "localhost:5001"

El backend construirá la URL:

    http://localhost:5001/payments

Y hará una solicitud POST con los datos de la tarjeta.

Hice un ejemplo de explotación donde el backend intentó conectarse a la dirección que puse en el campo (en este caso 127.0.0.1:5001).

![SRRFEjemplo](2025-Desarrollo-Seguro/services/frontend/src/photos/srrfEjemplo.png)

Ahora que lo mitigué editanto el archivo paymentBrand:

    const allowedBrands = ['visa', 'mastercard', 'amex'];
    if (!allowedBrands.includes(paymentBrand)) {
    throw new Error('Invalid payment brand');
    }

Si el valor no está en la lista, el backend rechaza la solicitud y no intenta conectarse a la URL que le da el usuario.

![SRRFEjemploSolucionado](2025-Desarrollo-Seguro/services/frontend/src/photos/srrfEjemploSolucionado.png)

---
### 4. Recorrido de directorios (Path Traversal)

Esta vulnerabilidad está en el método getReceipt del archivo invoiceService.ts:

    const filePath = `/invoices/${pdfName}`;
    const content = await fs.readFile(filePath, 'utf-8');

En el parámetro pdfName viene directamente la solicitud del usuario y se usa para construir la ruta del archivo sin validación alguna.

Para explotar esta vulnerabilidad primero se hace una solicitud al endpoint que llama ese método, y luego en el parámetro pdfName le ingresas un valor malicioso: **../../../../etc/passwd**. 

El backend va a construir la ruta y tratará de leer el archivo y terminará devolviendo lo que le pidieron; dejando que el atacante pueda acceder a archivos sensibles.

Hice una prueba con postman para verificarlo:

![pathTraversalEjemplo](2025-Desarrollo-Seguro/services/frontend/src/photos/pathTraversalEjemplo.png)

El backend respondió **200 OK** y trató de devolver el contenido de passwd, aunque postman no pudo mostrarlo como pdf.

Para mitigarlo primero agregué una validación para que solo se acepten nombres de archivos seguros y que terminen en .pdf y después con con un path.join verifiqué que el archivo esté dentro de lo permitido.

![pathTraversalEjemploSolucionado](2025-Desarrollo-Seguro/services/frontend/src/photos/pathTraversalEjemploSolucionado.png)

---
### 5. Falta de autorización (Missing Authorization).
