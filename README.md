# Projektdokumentation – Active Directory Management Tool

## Projektinformationen

| Element              | Beschreibung                                         |
|----------------------|------------------------------------------------------|
| **Projektname**      | ADScript Overkill                                    |
| **Verantwortlich**   | Rafael Gaberell Sunrise GmbH                       |
| **Version**          | 1.0                                                  |
| **Letzte Änderung**  | 21.05.2025                                           |
| **Datei**            | `ADScript-BBW.ps1`                              |

---

## 1. Zweck

Dieses PowerShell-Skript dient der umfassenden Verwaltung und Überwachung einer Active Directory (AD)-Umgebung. Es ermöglicht Administratoren, gängige Aufgaben wie Benutzer-, Gruppen-, Computer- und OU-Management sowie Systemstatistiken zentralisiert und automatisiert über ein Konsolenmenü durchzuführen.

---

## 2. Systemvoraussetzungen

- Windows Server (2016 oder neuer empfohlen)
- PowerShell 5.1 oder höher
- Installierte Module:
  - `ActiveDirectory`
  - `GroupPolicy`
- Administratorrechte auf der Domäne

---

## 3. Aufbau des Scripts

### Hauptmodule

- **Logging-System:** Farbcodierte Logausgaben (Info, Warnung, Fehler)
- **Menüstruktur:** Hauptmenü, AD-Menü, Statistik-Menü
- **AD-Management:**
  - OU-, Gruppen-, Benutzer- und Computerverwaltung
  - Gruppenverschachtelung & Zirkularitätsprüfung
  - Passwort- und Wallpaper-Richtlinien
- **Systemmonitoring:**
  - CPU, RAM, Disk, IP, Uptime, Prozesse, Services, Events
  - Netzwerkstatus mit Performance Counter

---

## 4. Funktionsübersicht

### 4.1 Active Directory Verwaltung

| Funktion                          | Beschreibung |
|-----------------------------------|--------------|
| OU Management                     | Erstellen/Verschieben von Organisationseinheiten |
| Gruppenmanagement                 | Verwaltung inkl. Mitglieder und Verschachtelung |
| Benutzerverwaltung                | Benutzer erstellen, bearbeiten, verwalten |
| Computer-Kontenverwaltung         | Erstellen, verschieben, aktivieren/deaktivieren |
| Passwortpolitik setzen            | Validiertes Setzen von Richtlinien |
| Wallpaper GPO                     | Setzen von Gruppenrichtlinien für Desktophintergründe |
| Gruppenstruktur anzeigen          | Anzeige verschachtelter Gruppen |
| Gruppenmitgliedschaft verwalten   | Mitglieder zu Gruppen hinzufügen oder entfernen |
| AD-Objekte suchen                 | Suche nach Benutzern, Gruppen, OUs oder Computern |
| OU-Struktur anzeigen              | Hierarchische Darstellung der AD-Struktur |

---

### 4.2 Systemstatistiken

| Komponente           | Beschreibung |
|----------------------|--------------|
| CPU-Auslastung       | Live-Abfrage der Prozessorlast |
| RAM-Nutzung          | Verfügbare und belegte Speicherkapazität |
| Festplattenstatus    | Freier / verwendeter Speicher je Laufwerk |
| IP-Adressen          | Alle IPv4-Adressen ausser Loopback |
| Systemlaufzeit       | Seit dem letzten Neustart vergangene Zeit |
| Prozesse             | Top 5 Prozesse nach CPU-Auslastung |
| Netzwerkstatus       | Adapterstatus, Traffic, IPs, MAC |
| Kritische Dienste    | Zustand essenzieller Windows-Dienste |
| Systemereignisse     | Letzte Fehler/Warnungen im Systemlog |
| Gesamtstatistik      | Kombinierte Anzeige aller obigen Infos |

---

## 5. Menüstruktur

[Hauptmenü]

    Active Directory Management

    System Statistics

    Exit

[AD-Menü]
1-14: Verschiedene AD-Funktionen

[Statistik-Menü]
1-11: Überwachung von Ressourcen und Ereignissen


---

## 6. Sicherheit & Validierung

- Eingaben werden überprüft (z. B. Domainname, Passwortlängen)
- Schutz gegen zirkuläre Gruppenmitgliedschaften
- Fehlerhafte Operationen werden geloggt
- Aktionen erfordern explizite Bestätigungen

---

## 7. Protokollierung

Alle Vorgänge werden in einem zeitgestempelten Logfile im Verzeichnis `.\Logs` gespeichert. Dies ermöglicht eine vollständige Nachvollziehbarkeit aller ausgeführten Aktionen.

Beispiel:

2025-05-21 14:34:12 [Info] - Connected to domain: bbw.lab
2025-05-21 14:35:00 [Warning] - Invalid password age specified: 10
2025-05-21 14:36:44 [Error] - Failed to get CPU usage: ...


---

## 8. Bekannte Einschränkungen

- Nur für Windows-Betriebssysteme geeignet
- Module `ActiveDirectory` und `GroupPolicy` müssen installiert sein
- Keine GUI – nur CLI-Interaktion via PowerShell



