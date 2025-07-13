# GitHub-Repository-Verarbeitung

## Grundlegende Verwendung

Öffentliche Repositories verarbeiten:
```bash
# Mit vollständiger URL
repomix --remote https://github.com/user/repo

# Mit GitHub-Kurzform
repomix --remote user/repo
```

## Branch- und Commit-Auswahl

```bash
# Bestimmter Branch
repomix --remote user/repo --remote-branch main

# Tag
repomix --remote user/repo --remote-branch v1.0.0

# Commit-Hash
repomix --remote user/repo --remote-branch 935b695
```

## Voraussetzungen

- Git muss installiert sein
- Internetverbindung
- Lesezugriff auf das Repository

## Ausgabekontrolle

```bash
# Benutzerdefinierter Ausgabeort
repomix --remote user/repo -o custom-output.xml

# Mit XML-Format
repomix --remote user/repo --style xml

# Kommentare entfernen
repomix --remote user/repo --remove-comments
```

## Docker-Verwendung

```bash
# Verarbeitung und Ausgabe in das aktuelle Verzeichnis
docker run -v .:/app -it --rm ghcr.io/yamadashy/repomix \
  --remote user/repo

# Ausgabe in bestimmtes Verzeichnis
docker run -v ./output:/app -it --rm ghcr.io/yamadashy/repomix \
  --remote user/repo
```

## Häufige Probleme

### Zugriffsprobleme
- Stellen Sie sicher, dass das Repository öffentlich ist
- Überprüfen Sie die Git-Installation
- Überprüfen Sie die Internetverbindung

### Große Repositories
- Verwenden Sie `--include`, um bestimmte Pfade auszuwählen
- Aktivieren Sie `--remove-comments`
- Verarbeiten Sie Branches separat 
