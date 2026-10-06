class HumanExplainer:
    """Moteur de traduction des paquets réseau en langage humain."""
    COMMON_PORTS = {
        80: ("HTTP", "Communication Web non sécurisée (texte clair)"),
        443: ("HTTPS", "Communication Web sécurisée et chiffrée"),
        53: ("DNS", "Résolution de nom de domaine (requête/réponse d'adresse IP)"),
        22: ("SSH", "Connexion à un terminal distant sécurisé"),
        21: ("FTP", "Transfert de fichiers non sécurisé"),
        123: ("NTP", "Synchronisation de l'heure réseau"),
        1883: ("MQTT", "Protocole d'échange d'objets connectés (IoT)")
    }

    @staticmethod
    def explain_packet(packet_info: dict) -> dict:
        proto = packet_info.get("protocol", "INCONNU")
        dst_port = packet_info.get("dst_port")
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        length = packet_info.get("length", 0)

        fact = f"FAIT OBSERVÉ : Paquet {proto} de {length} octets transmis de {src_ip} vers {dst_ip}"
        if dst_port:
            fact += f" sur le port {dst_port}."

        interpretation = "INTERPRÉTATION : "
        if dst_port in HumanExplainer.COMMON_PORTS:
            service, desc = HumanExplainer.COMMON_PORTS[dst_port]
            interpretation += f"Le port {dst_port} est généralement associé au service {service} ({desc})."
        elif proto == "ICMP":
            interpretation += "Signal de contrôle réseau ou test de joignabilité (Ping)."
        else:
            interpretation += f"Échange de données standard utilisant le protocole {proto}."

        return {
            "fact": fact,
            "interpretation": interpretation,
            "summary": f"{fact}\n\n{interpretation}"
        }
