# Practico2-Seguridad

## Detección de Vulnerabilidades:

### 1. Inyección SQL
Esta vulnerabilidad se encontraba en el backend; archivo invoiceService.ts en la línea 19 donde decía esto:

    if (status) q = q.andWhereRaw(" status "+ operator + " '"+ status +"'");

El flujo de la vulnerabilidad empieza en invoiceController.ts en las lineas 7-8:

    const state = req.query.status as string | undefined;
    const operator = req.query.operator as string | undefined;

Aquí entran los parámetros y se pasan directamente al servicio sin validación.
Un atacante puede venir y directamente desde el navegador, poner un URL malicioso como por ejemplo:

"_https://tuapp.com/invoices?status=paid'%20OR%201=1%20--%20&operator==_"

El %20 es espacio y -- es comentario SQL, entonces si eso lo convertimos queda como **status = "paid' OR 1=1 -- "** lo que significa que primero cierra la cadena original, y depsués manda una condición que siempre va dar true, mientras commenta el resto de la consulta.Esto hace que después el atacante obtenga _todas_ las facturas de _todos_ los usuarios.


