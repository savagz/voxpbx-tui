/// Capa de enlace del handle de pcap.
///
/// No toda interfaz entrega tramas Ethernet: `any` en Linux entrega "cooked
/// capture" (SLL/SLL2) y el loopback entrega cabecera BSD de 4 bytes. Parsear
/// todo como Ethernet no falla ruidosamente — simplemente **no matchea nada** y
/// la pestaña SIP Trace queda vacía sin ningún error a la vista.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// DLT_EN10MB (1): Ethernet II, el caso normal de una NIC física.
    Ethernet,
    /// DLT_NULL (0): loopback BSD/macOS, 4 bytes con la familia de direcciones.
    Null,
    /// DLT_LOOP (108): loopback OpenBSD, igual que Null pero big-endian.
    Loop,
    /// DLT_RAW / DLT_IPV4 / DLT_IPV6: el paquete arranca directo en la cabecera IP.
    RawIp,
    /// DLT_LINUX_SLL (113): cabecera cooked de 16 bytes (interfaz `any`).
    LinuxSll,
    /// DLT_LINUX_SLL2 (276): cabecera cooked v2 de 20 bytes (libpcap ≥ 1.10).
    LinuxSll2,
}

impl LinkType {
    /// Mapea el valor crudo de `pcap_datalink`. `None` = formato que no sabemos
    /// desarmar; el llamador debe avisarlo en vez de tragarse los paquetes.
    pub fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(LinkType::Null),
            1 => Some(LinkType::Ethernet),
            12 | 101 | 228 | 229 => Some(LinkType::RawIp),
            108 => Some(LinkType::Loop),
            113 => Some(LinkType::LinuxSll),
            276 => Some(LinkType::LinuxSll2),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            LinkType::Ethernet => "EN10MB",
            LinkType::Null => "NULL/LOOPBACK",
            LinkType::Loop => "LOOP",
            LinkType::RawIp => "RAW-IP",
            LinkType::LinuxSll => "LINUX-SLL",
            LinkType::LinuxSll2 => "LINUX-SLL2",
        }
    }

    /// Bytes de cabecera de enlace a saltear para llegar a la cabecera IP.
    /// `Ethernet` no aparece acá: lo parsea etherparse con su propio decoder.
    fn ip_offset(&self) -> usize {
        match self {
            LinkType::Ethernet => 0,
            LinkType::Null | LinkType::Loop => 4,
            LinkType::RawIp => 0,
            LinkType::LinuxSll => 16,
            LinkType::LinuxSll2 => 20,
        }
    }

    /// Payload IP de la trama, o `None` si el paquete es más corto que su propia
    /// cabecera de enlace (captura truncada).
    pub fn ip_payload<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        frame.get(self.ip_offset()..)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapea_los_datalinks_que_entrega_libpcap() {
        assert_eq!(LinkType::from_raw(1), Some(LinkType::Ethernet));
        assert_eq!(LinkType::from_raw(113), Some(LinkType::LinuxSll));
        assert_eq!(LinkType::from_raw(276), Some(LinkType::LinuxSll2));
        assert_eq!(LinkType::from_raw(0), Some(LinkType::Null));
        assert_eq!(LinkType::from_raw(999), None);
    }

    #[test]
    fn saltea_la_cabecera_de_enlace_y_corta_si_esta_truncada() {
        let frame = [0u8; 20];
        assert_eq!(LinkType::LinuxSll.ip_payload(&frame).unwrap().len(), 4);
        assert_eq!(LinkType::Null.ip_payload(&frame).unwrap().len(), 16);
        assert!(LinkType::LinuxSll2.ip_payload(&[0u8; 8]).is_none());
    }
}
