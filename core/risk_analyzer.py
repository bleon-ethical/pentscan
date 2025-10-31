# core/risk_analyzer.py
# Motor de análisis de riesgo para pentscan
# Basado en CVSS 3.1 y patrones de vulnerabilidades reales

class RiskAnalyzer:
    """
    Analiza vulnerabilidades y asigna puntuación CVSS y severidad.
    """
    
    # Rangos de CVSS 3.1
    CVSS_SEVERITY_RANGES = {
        'CRITICAL': (9.0, 10.0),
        'HIGH': (7.0, 8.9),
        'MEDIUM': (4.0, 6.9),
        'LOW': (0.1, 3.9),
        'NONE': (0.0, 0.0)
    }
    
    # Base de conocimiento: ID de vulnerabilidad → CVSS base
    VULN_KNOWLEDGE_BASE = {
        # Deserialización remota
        'INSECURE_SERIALIZATION': {'cvss': 9.8, 'severity': 'CRITICAL'},
        
        # Active Directory
        'AS_REP_ROASTING': {'cvss': 8.1, 'severity': 'HIGH'},
        'WRITABLE_SHARE': {'cvss': 8.1, 'severity': 'HIGH'},
        'CONSTRAINED_DELEGATION': {'cvss': 8.8, 'severity': 'HIGH'},
        'SHADOW_ADMIN': {'cvss': 7.2, 'severity': 'HIGH'},
        
        # Web
        'CACHE_POISONING': {'cvss': 7.5, 'severity': 'HIGH'},
        'HOST_HEADER_INJECTION': {'cvss': 6.1, 'severity': 'MEDIUM'},
        'HTTP_CGI_EXPOSED': {'cvss': 5.3, 'severity': 'MEDIUM'},
        
        # Credenciales
        'API_KEY': {'cvss': 9.8, 'severity': 'CRITICAL'},
        'FTP_ANON_ENABLED': {'cvss': 5.0, 'severity': 'MEDIUM'},
        'DEFAULT_CREDS': {'cvss': 7.2, 'severity': 'HIGH'},
        
        # Configuración
        'SMB_SIGNING_DISABLED': {'cvss': 5.3, 'severity': 'MEDIUM'},
        'WEAK_SSL_CIPHER': {'cvss': 5.3, 'severity': 'MEDIUM'},
        'OUTDATED_SERVICE': {'cvss': 7.5, 'severity': 'HIGH'},
        
        # Network
        'LLMNR_ENABLED': {'cvss': 6.5, 'severity': 'MEDIUM'},
        'NBTNS_ENABLED': {'cvss': 6.5, 'severity': 'MEDIUM'},
    }

    @staticmethod
    def analyze_vulnerability(vuln_id: str, service: str = "", version: str = "") -> dict:
        """
        Analiza una vulnerabilidad y devuelve CVSS y severidad.
        
        Args:
            vuln_id: ID de la vulnerabilidad (ej: 'API_KEY', 'WRITABLE_SHARE')
            service: Nombre del servicio (opcional)
            version: Versión del servicio (opcional)
            
        Returns:
            dict: {'cvss': float, 'severity': str}
        """
        # Buscar en base de conocimiento
        if vuln_id in RiskAnalyzer.VULN_KNOWLEDGE_BASE:
            return RiskAnalyzer.VULN_KNOWLEDGE_BASE[vuln_id].copy()
        
        # Análisis por patrones en el ID
        vuln_id_lower = vuln_id.lower()
        
        # CVEs conocidos (patrones básicos)
        if 'cve' in vuln_id_lower:
            # Extraer año del CVE para estimar criticidad
            import re
            year_match = re.search(r'cve-(\d{4})-', vuln_id_lower)
            if year_match:
                year = int(year_match.group(1))
                if year >= 2020:
                    return {'cvss': 8.1, 'severity': 'HIGH'}
                else:
                    return {'cvss': 6.5, 'severity': 'MEDIUM'}
            else:
                return {'cvss': 7.5, 'severity': 'HIGH'}
        
        # Servicios con versiones antiguas
        if 'outdated' in vuln_id_lower or 'old' in vuln_id_lower:
            return {'cvss': 7.5, 'severity': 'HIGH'}
        
        # Vulnerabilidades web genéricas
        if any(x in vuln_id_lower for x in ['xss', 'csrf', 'clickjacking']):
            return {'cvss': 6.1, 'severity': 'MEDIUM'}
        
        if any(x in vuln_id_lower for x in ['sqli', 'sql injection', 'injection']):
            return {'cvss': 8.8, 'severity': 'HIGH'}
        
        # Por defecto
        return {'cvss': 5.0, 'severity': 'MEDIUM'}

    @staticmethod
    def get_severity_from_cvss(cvss_score: float) -> str:
        """Convierte puntuación CVSS a severidad textual."""
        for severity, (low, high) in RiskAnalyzer.CVSS_SEVERITY_RANGES.items():
            if low <= cvss_score <= high:
                return severity
        return "MEDIUM"

    @staticmethod
    def adjust_for_environment(cvss_base: float, network_type: str = "internal") -> float:
        """
        Ajusta el CVSS según el entorno.
        - Perímetro externo: sin ajuste
        - Red interna: +0.5 (mayor impacto)
        """
        if network_type == "internal":
            return min(10.0, cvss_base + 0.5)
        return cvss_base

    @staticmethod
    def generate_recommendation(vuln_id: str, ip: str, port: int = None) -> str:
        """Genera una recomendación de remediación específica."""
        recommendations = {
            'API_KEY': f"Revocar claves API expuestas en {ip} y rotar credenciales.",
            'WRITABLE_SHARE': f"Restringir permisos de escritura en shares SMB de {ip}.",
            'AS_REP_ROASTING': f"Deshabilitar 'Do not require pre-auth' para usuarios en {ip}.",
            'SMB_SIGNING_DISABLED': f"Habilitar SMB signing en {ip} para prevenir ataques relay.",
            'DEFAULT_CREDS': f"Cambiar credenciales por defecto en {ip}:{port}.",
            'CACHE_POISONING': f"Configurar caché web para ignorar headers no estándar en {ip}.",
            'OUTDATED_SERVICE': f"Actualizar servicio en {ip}:{port} a la última versión estable.",
        }
        return recommendations.get(vuln_id, f"Remediar vulnerabilidad {vuln_id} en {ip}.")

# Ejemplo de uso (no se ejecuta en producción)
if __name__ == "__main__":
    analyzer = RiskAnalyzer()
    result = analyzer.analyze_vulnerability("API_KEY")
    print(f"API_KEY → CVSS: {result['cvss']}, Severidad: {result['severity']}")