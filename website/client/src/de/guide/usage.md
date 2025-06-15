# Grundlegende Verwendung

## Schnellstart

Packen Sie Ihr gesamtes Repository:
```bash
repomix
```

## Häufige Anwendungsfälle

### Bestimmte Verzeichnisse packen
```bash
repomix path/to/directory
```

### Bestimmte Dateien einschließen
Verwenden Sie [Glob-Muster](https://github.com/mrmlnc/fast-glob?tab=readme-ov-file#pattern-syntax):
```bash
repomix --include "src/**/*.ts,**/*.md"
```

### Dateien ausschließen
```bash
repomix --ignore "**/*.log,tmp/"
```

### Remote-Repositories
```bash
# Mit GitHub-URL
repomix --remote https://github.com/user/repo

# Mit Kurzform
repomix --remote user/repo

# Bestimmter Branch/Tag/Commit
repomix --remote user/repo --remote-branch main
repomix --remote user/repo --remote-branch 935b695
```

### Dateilisten-Eingabe (stdin)

Übergeben Sie Dateipfade über stdin für ultimative Flexibilität:

```bash
# Mit find-Befehl
find src -name "*.ts" -type f | repomix --stdin

# Mit Git für verfolgte Dateien
git ls-files "*.ts" | repomix --stdin

# Mit ls und Glob-Mustern
ls src/**/*.ts | repomix --stdin

# Aus einer Datei mit Dateipfaden
cat file-list.txt | repomix --stdin

# Direkte Eingabe mit echo
echo -e "src/index.ts\nsrc/utils.ts" | repomix --stdin
```

Die `--stdin`-Option ermöglicht es Ihnen, eine Liste von Dateipfaden an Repomix zu übertragen und bietet ultimative Flexibilität bei der Auswahl der zu packenden Dateien.

> [!NOTE]
> Bei der Verwendung von `--stdin` können Dateipfade relativ oder absolut angegeben werden, und Repomix übernimmt automatisch die Pfadauflösung und Deduplizierung.

## Ausgabeformate

### XML (Standard)
```bash
repomix --style xml
```

### Markdown
```bash
repomix --style markdown
```

### Klartext
```bash
repomix --style plain
```

## Zusätzliche Optionen

### Kommentare entfernen
```bash
repomix --remove-comments
```

### Zeilennummern anzeigen
```bash
repomix --output-show-line-numbers
```

### In die Zwischenablage kopieren
```bash
repomix --copy
```

### Sicherheitsprüfung deaktivieren
```bash
repomix --no-security-check
```

## Konfiguration

Konfigurationsdatei initialisieren:
```bash
repomix --init
```

Siehe [Konfigurationsleitfaden](/de/guide/configuration) für detaillierte Optionen. 
