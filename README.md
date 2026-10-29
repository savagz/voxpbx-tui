# voxpbx-tui — v3

TUI (ratatui) para monitorear un servidor Asterisk: estado del core, uptime, CPU/RAM/disco del host, llamadas activas, extensiones registradas, colas y trazado SIP en vivo estilo Wireshark filtrable por extensión.

Pensada para correr **directamente en el servidor Asterisk** (así CPU/RAM/disco y la captura de paquetes son locales, sin infraestructura extra).

## Novedades de la v3 respecto de la v2

- **Asistente de primer arranque**: si no hay configuración, la app arranca pidiendo host, puerto, usuario y contraseña de AMI en pantalla, en vez de fallar pidiendo un TOML y una variable de entorno.
- **Chequeo e instalación de la librería de análisis SIP**: el asistente verifica `libpcap` (runtime, headers) y el permiso de captura, y ofrece ejecutar el comando de instalación/permisos con el gestor de paquetes detectado (`apt`, `dnf`, `yum`, `pacman`, `apk`, `zypper`, `brew`).
- **Panel de configuración con la app andando**: tecla `C`. Los cambios se aplican **en caliente**: la conexión AMI y la captura se rehacen solas, sin reiniciar el proceso.
- **Prueba de conexión** (`F5`): conecta y hace login contra AMI con los datos del formulario, sin tocar la sesión de monitoreo en curso.
- **Captura consciente de la capa de enlace**: soporta Ethernet, cooked capture de Linux (`any`) y loopback. La v2 asumía Ethernet siempre, así que con `any` o loopback la pestaña SIP Trace quedaba vacía sin dar ningún error.
- **Rediseño industrial**: paleta de chapa oscura con ámbar de señalización y cian de instrumento, botonera lateral con LEDs, placas de título grabadas, gauges segmentados y franjas de peligro.

## Instalación

Las releases publican un binario para Linux x86_64 estático (musl, con `libpcap` enlazada adentro) que corre en cualquier distribución sin instalar nada más.

```sh
curl -fsSL https://raw.githubusercontent.com/savagz/voxpbx-tui/main/install.sh | sh
```

Sin `curl`, con `wget`:

```sh
wget -qO- https://raw.githubusercontent.com/savagz/voxpbx-tui/main/install.sh | sh
```

El script baja la última release, verifica su checksum SHA-256, instala `voxpbx-tui` en `/usr/local/bin` (usando `sudo` sólo si hace falta) y le da al binario las capabilities `cap_net_raw,cap_net_admin` para que el SIP Trace pueda capturar sin correr como root. La última release se resuelve siguiendo la redirección de `github.com/savagz/voxpbx-tui/releases/latest`, no la API de GitHub, así que no sufre su rate limit. Las opciones se pasan después de `sh -s --`:

```sh
# Fijar una versión ("v0.1.0" y "0.1.0" valen igual)
curl -fsSL https://raw.githubusercontent.com/savagz/voxpbx-tui/main/install.sh | sh -s -- --version v0.1.0

# Instalar sin root (el directorio se crea si no existe)
curl -fsSL https://raw.githubusercontent.com/savagz/voxpbx-tui/main/install.sh | sh -s -- --prefix ~/.local/bin

# No tocar las capabilities
curl -fsSL https://raw.githubusercontent.com/savagz/voxpbx-tui/main/install.sh | sh -s -- --no-setcap

# Desinstalar (pasando el mismo --prefix que al instalar)
curl -fsSL https://raw.githubusercontent.com/savagz/voxpbx-tui/main/install.sh | sh -s -- --uninstall
```

La versión también se puede fijar con la variable `VOXPBX_VERSION`. `--help` lista las opciones.

Si el repositorio es privado, el one-liner no funciona sin autenticación: bajá los assets de la release a mano.

### Instalación manual

Bajá `voxpbx-tui-<tag>-x86_64-linux.tar.gz` y su `.sha256` desde la [página de releases](https://github.com/savagz/voxpbx-tui/releases) y:

```sh
sha256sum -c voxpbx-tui-<tag>-x86_64-linux.tar.gz.sha256
tar -xzf voxpbx-tui-<tag>-x86_64-linux.tar.gz
sudo install -m 0755 voxpbx-tui-<tag>-x86_64-linux/voxpbx-tui /usr/local/bin/
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/voxpbx-tui
```

### Publicar una release

1. Subí `version` en `Cargo.toml` y commiteá.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. El workflow `release` de GitHub Actions compila `libpcap` estática contra musl, corre los tests, compila y publica los assets. También se puede lanzar a mano (`workflow_dispatch`) para compilar sin publicar.

### Línea de comandos

```
voxpbx-tui [OPCIONES]

    -V, --version    Muestra la versión y sale
    -h, --help       Muestra esta ayuda y sale
```

## Requisitos para compilar desde el código

- Rust (instalado vía [rustup](https://rustup.rs)).
- `libpcap` en el sistema (dependencia de enlace del crate `pcap`). Si falta, el asistente lo detecta y ofrece instalarlo:
  - Debian/Ubuntu: `sudo apt install libpcap-dev`
  - RHEL/CentOS/Fedora: `sudo dnf install libpcap-devel`
  - macOS: ya viene con el sistema.
- Un usuario de AMI con permisos de lectura (`read = system,call,agent`, sin necesidad de `write`) en `manager.conf`.

## Correr

```sh
cargo run --release
```

En el primer arranque aparece el asistente:

| Tecla | Acción |
|-------|--------|
| `↑` `↓` `Tab` | moverse entre campos |
| `←` `→` | ciclar las interfaces detectadas (campo interfaz) |
| `Espacio` | activar/desactivar el análisis SIP |
| `F2` | mostrar/ocultar la contraseña |
| `F5` | probar la conexión AMI |
| `F9` | volver a chequear dependencias |
| `F10` | ejecutar el comando de instalación/permisos sugerido |
| `Enter` | guardar y entrar al tablero |
| `Esc` | salir sin guardar |

Ya en el tablero: `Tab`/`Shift+Tab` cambia de vista, `↑`/`↓` (o `j`/`k`) navega la lista en SIP Trace, `g`/`Home` va al principio, `G`/`End` vuelve a seguir el tráfico en vivo, `f` cicla el filtro por extensión, `s` inicia/detiene una captura para diagnóstico, **`c` abre la configuración**, `q` o `Ctrl+C` sale.

### SIP Trace

La lista **sigue al último paquete capturado** por defecto; navegar con `↑`/`↓` congela la vista y `G` vuelve a engancharla al tráfico en vivo (el pie del panel dice en cuál de los dos estados está).

Arriba de la lista, la barra **MEZCLA** desglosa lo capturado por tipo de mensaje (`OPTIONS 120 · 200 45 · INVITE 2`), para no tener que recorrer la tabla para saber qué está pasando.

El filtro por extensión (`f`) no se apoya sólo en la IP que reporta AMI — que puede estar vacía, ser la de un NAT o no coincidir con el tráfico real — sino también en el usuario de las URIs `From`/`To`. Si aun así la extensión elegida no aparece en la captura, se muestra una banda **SIN COINCIDENCIAS** con la IP que AMI reportó.

## Configuración

El asistente escribe el archivo solo:

- `./config/voxpbx.toml` si ya existe (modo dev, dentro del checkout).
- `~/.config/voxpbx-tui/config.toml` en cualquier otro caso.

El archivo se guarda con permisos **0600** porque contiene el secret de AMI. Si preferís no tener credenciales en disco, dejá el campo vacío y exportá la variable de entorno:

```sh
export VOXPBX_AMI_SECRET="el-secret-de-tu-usuario-ami"
```

La variable **gana** sobre lo guardado en el archivo, y el asistente lo muestra así (`<VOXPBX_AMI_SECRET>`) en vez de pedir la contraseña.

`config/voxpbx.example.toml` queda como referencia del formato para cargarlo a mano.

## Captura de paquetes: interfaz y capa de enlace

No toda interfaz entrega tramas Ethernet, y el detalle no es cosmético:

| Interfaz | Capa de enlace | Cabecera |
|----------|----------------|----------|
| NIC física (`eth0`, `ens18`, `en0`) | `EN10MB` (Ethernet II) | 14 bytes |
| `any` en Linux | `LINUX-SLL` / `LINUX-SLL2` (cooked) | 16 / 20 bytes |
| loopback (`lo`, `lo0`) | `NULL` / `LOOP` (BSD) | 4 bytes |

La captura resuelve la capa de enlace consultando `pcap_datalink` sobre el handle abierto y desarma cada trama según corresponda. Si el formato no se reconoce, lo dice como error en vez de descartar los paquetes en silencio.

El pie de la pestaña **SIP Trace** muestra `interfaz · capa de enlace · N vistos / M SIP`: si `vistos` sube y `SIP` queda en cero, el tráfico llega pero no se está reconociendo (puertos mal elegidos o SIP sobre TLS), y aparece una banda de aviso con el filtro BPF en uso.

El asistente ordena las interfaces poniendo primero las que tienen IP ruteable y muestra las direcciones de la elegida, para no tener que adivinar entre `eth0`, `ens18` y `docker0`.

## Captura de paquetes: permisos

Abrir la interfaz de red en modo captura requiere privilegios. En vez de correr todo el proceso como root, dale la capability puntual al binario ya compilado — es exactamente lo que hace `F10` en el asistente cuando el chequeo de permisos está en rojo:

```sh
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+eip target/release/voxpbx-tui
```

En macOS el equivalente es dar lectura sobre `/dev/bpf*`.

Si la captura falla, la pestaña **SIP Trace** lo muestra como error y se deshabilita sola — el resto de la TUI (AMI, sysinfo) sigue funcionando normalmente, y desde `C` se puede corregir la interfaz o los permisos sin reiniciar.

## Logs

Nada se escribe a stdout/stderr mientras la TUI está corriendo (rompería el dibujado de la pantalla alterna). Los logs van a un archivo diario en:

- Linux: `~/.local/share/voxpbx-tui/voxpbx-tui.log.<fecha>`
- macOS: `~/Library/Application Support/voxpbx-tui/voxpbx-tui.log.<fecha>`

Controlable con `RUST_LOG` (por defecto `info`).

## Tests

```sh
cargo test
```

Cubre el parsing del protocolo AMI, el parsing de paquetes SIP capturados (Ethernet/IP/UDP → mensaje SIP) con paquetes sintéticos, la validación del formulario de configuración, y el dibujado del tablero/asistente en varios tamaños de terminal (backend de prueba, sin terminal real).
