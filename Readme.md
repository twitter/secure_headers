Encabezados seguros Construir + Probar
rama principal representa la línea 6.x . Consulte el documento de actualización a 4.x , actualización a 5.x doc o actualización a 6.x doc para obtener instrucciones sobre cómo actualizar. Las correcciones de errores deberían ir en la rama 5.x por ahora.

La gema aplicará automáticamente varios encabezados relacionados con la seguridad. Esto incluye:

Política de seguridad de contenido (CSP): ayuda a detectar / prevenir XSS, contenido mixto y otras clases de ataque. Especificación CSP 2
https://csp.withgoogle.com
https://csp.withgoogle.com/docs/strict-csp.html
https://csp-evaluator.withgoogle.com
HTTP Strict Transport Security (HSTS): garantiza que el navegador nunca visite la versión http de un sitio web. Protege de ataques SSLStrip / Firesheep. Especificación HSTS
X-Frame-Options (XFO): evita que su contenido sea enmarcado y potencialmente secuestrado. Especificación de opciones de X-Frame
X-XSS-Protection: filtro heurístico de secuencias de comandos entre sitios para IE / Chrome
X-Content-Type-Options: evitar el rastreo de tipos de contenido
X-Download-Options: evita que se abran las descargas de archivos
Políticas de dominio cruzado X-Permitidas: restringe el acceso de Adobe Flash Player a los datos
Política de referencia: borrador de la Política de referencia
Expect-CT: utilice solo certificados que estén presentes en los registros de transparencia de certificados. Especificación de borrador de Expect-CT .
Clear-Site-Data: borrando los datos del navegador para el origen. Especificación Clear-Site-Data .
También puede marcar todas las cookies http con los atributos Secure, HttpOnly y SameSite. Está de forma predeterminada, pero se puede desactivar mediante config.cookies = SecureHeaders::OPT_OUT.

secure_headers es una biblioteca con una configuración global, anulaciones por solicitud y middleware en rack que le permite personalizar la configuración de su aplicación.

Documentación
Anulaciones y anexos con nombre
Configuración por acción
Galletas
Hashes
Configuración de Sinatra
Configuración
Si no proporciona una defaultconfiguración, se generarán excepciones. Si desea utilizar una configuración predeterminada (que está bastante bloqueada), simplemente llame SecureHeaders::Configuration.defaultsin ningún argumento o bloqueo.

Todos los nilvalores volverán a sus valores predeterminados. SecureHeaders::OPT_OUTdesactivará el encabezado por completo.

Advertencia: la siguiente no es una configuración predeterminada per se. Sirve como ejemplo de implementación de la configuración. Debería leer más sobre estos encabezados y determinar qué es apropiado para sus requisitos.

SecureHeaders :: Configuración . hacer por defecto  | config |
  config . cookies = { seguro : verdadero , # marcar todas las cookies como "Seguro" http : true , # marcar todas las cookies como "HttpOnly" samesite : { lax : true # marcar todas las cookies como SameSite = lax } } # Agregar "; precargar" y envíe el sitio a hstspreload.org para obtener la mejor protección. config . hsts = "max-age = # { 1 .  
     
     
    
       
    
  
  
    week.to_i}"
  config.x_frame_options = "DENY"
  config.x_content_type_options = "nosniff"
  config.x_xss_protection = "1; mode=block"
  config.x_download_options = "noopen"
  config.x_permitted_cross_domain_policies = "none"
  config.referrer_policy = %w(origin-when-cross-origin strict-origin-when-cross-origin)
  config.csp = {
    # valores "meta". estos darán forma al encabezado, pero los valores no se incluyen en el encabezado. 
    preserve_schemes : verdadero ,  # predeterminado: falso. Los esquemas se eliminan de las fuentes de host para ahorrar bytes y desalentar el contenido mixto. 
    disable_nonce_backwards_compatibility : verdadero ,  # predeterminado: falso. Si es falso, se agregará `unsafe-inline` automáticamente al usar nonces. Si es cierto, no lo será. Vea el # 403 para saber por qué querría esto.

    # valores de directiva: estos valores se traducirán directamente en directivas de origen 
    default_src : % w ( 'none' ) , 
    base_uri : % w ( 'self' ) , 
    block_all_mixed_content : true ,  # ver http://www.w3.org/TR/ Mixed-content / 
    child_src : % w ( 'self' ) ,  # si no se admite child-src, se establecerá el valor de frame-src. 
    connect_src : % w ( WSS: ) , 
    font_src : % w ( 'yo'  datos: ) , 
    form_action: % W ( 'auto'  github.com ) , 
    frame_ancestors : % w ( 'none' ) , 
    img_src : % w ( mycdn.com  datos: ) , 
    manifest_src : % w ( 'auto' ) , 
    media_src : % w ( utoob .com ) , 
    object_src : % w ( 'self' ) , 
    sandbox : true ,  # true y [] establecerán una configuración máximamente restrictiva 
    plugin_types : % w (application / x-shockwave-flash ) , 
    script_src : % w ( 'self' ) , 
    style_src : % w ( 'unsafe-inline' ) , 
    worker_src : % w ( 'self' ) , 
    upgrade_insecure_requests : true ,  # ver https: / /www.w3.org/TR/upgrade-insecure-requests/ 
    report_uri : % w ( https://report-uri.io/example-csp ) 
  } 
  # Esto solo está disponible desde 3.5.0; utilice la configuración `report_only: true` para 3.4.1 y versiones anteriores. 
  config . csp_report_only  =  config. csp . merge ( { 
    img_src : % w ( somewhereelse.com ) , 
    report_uri : % w ( https://report-uri.io/example-csp-report-only ) 
  } ) 
final
Valores predeterminados
Todos los encabezados, excepto PublicKeyPins y ClearSiteData, tienen un valor predeterminado. El conjunto predeterminado de encabezados es:

Content-Security-Policy: default-src 'self' https:; font-src 'self' https: data:; img-src 'self' https: data:; object-src 'none'; script-src https:; style-src 'self' https: 'unsafe-inline'
Strict-Transport-Security: max-age=631138519
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Frame-Options: sameorigin
X-Permitted-Cross-Domain-Policies: none
X-Xss-Protection: 1; mode=block
Configuraciones de API
Los encabezados que decida utilizar para las respuestas de la API es una elección totalmente personal. Cosas como X-Frame-Options parecen no tener lugar en una respuesta de API y estarían desperdiciando bytes. Si bien esto es cierto, los navegadores pueden hacer cosas raras con respuestas que no son HTML. Como mínimo, sugerimos CSP:

SecureHeaders :: Configuración . anular ( : api )  hacer | config |
  config . csp  =  {  default_src : 'none'  } 
  config . hsts  =  SecureHeaders :: OPT_OUT 
  config . x_frame_options  =  SecureHeaders :: OPT_OUT 
  config . x_content_type_options  =  SecureHeaders :: OPT_OUT 
  config . x_xss_protection  = SecureHeaders :: OPT_OUT 
  config . x_permitted_cross_domain_policies  =  SecureHeaders :: OPT_OUT 
end
Sin embargo, consideraría estos encabezados de todos modos dependiendo de sus requisitos de carga y ancho de banda.

Agradecimientos
Este proyecto se originó dentro del equipo de seguridad de Twitter. Una bifurcación archivada desde el punto de transición está aquí: https://github.com/twitter-archive/secure_headers .

Los colaboradores incluyen:

Neil Matatall @oreoshake
Chris Aniszczyk
Artur Dryomov
Bjørn Mæland
Arthur Chiu
Jonathan Viney
Jeffrey Horn
David Collazo
Brendon Murphy
William Makley
Reed Loden
Noah Kantrowitz
Wyatt Anderson
Salimane Adjao Moustapha
Francois Chagnon
Jeff Hodges
Ian Melven
Darío Javier Cravero
Logan Hasson
Raúl E Rangel
Steve Agalloco
Nate Collings
Josh Kalderimis
Alex Kwiatkowski
Julich Mera
Jesse Storimer
Tom Daniels
Kolja Dummann
Jean-Philippe Doyle
Blake Hitchcock
Vanderhoorn
pedante-ortográfico
Narsimham Chelluri
Si ha hecho una contribución y ve que su nombre no aparece en la lista, ¡haga un PR y agréguelo!

Bibliotecas similares
Rack rack-secure_headers
Casco y capucha Node.js (express)
Node.js (HAPI) blankie
ASP.NET - NWebsec
Python: django-csp + commonware ; django-seguridad
Ir - secureheader
Elixir Secure_headers
Dropwizard dropwizard-web-security
Ember.js ember-cli-content-security-policy
Encabezados seguros PHP
