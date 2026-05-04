# Translation Consistency Review — 2026-05-04

**Reviewer:** Zhora  
**Scope:** All translated .md files across EntraID, MDA, MDE, MDI, MDO, XDR, README.md, Requisitos.md  
**Translators:** Batty (EntraID, MDA, MDI), Pris (MDE, MDO, XDR, root files)

---

## Issues to Fix

### 1. Motto/Tagline Inconsistency (Pris)

MDO files and MDO baselines use:
> "Technology enables security, but discipline **is what guarantees** its effectiveness."

All other files (EntraID, MDE, MDI, MDA) use:
> "Technology enables security, but discipline **ensures** its effectiveness."

**Decision:** Standardize on "…but discipline ensures its effectiveness." across all files.

**Files to fix (Pris):**
- `MDO/Guia de Seguridad Operacional MDO tareas diarias.md`
- `MDO/Guia de Seguridad Operacional MDO Semanal.md`
- `MDO/Guia de Seguridad Operacional MDO Mensual Ad-Hoc.md`
- `MDO/Paquete MDO KQL Advance Hunting.md`
- `MDO/Línea Base/Linea base de proteccion contra Business Email Compromise (BEC).md`
- `MDO/Línea Base/Línea base para mejorar la postura de seguridad en Exchange online.md`
- `MDO/Línea Base/Priority Account Protection en Microsoft 365 Defender.md`

---

### 2. KQL Package Title Inconsistency (Pris)

MDE uses "KQL Query **Pack**" while all others use "KQL Query **Package**".

**File to fix (Pris):**
- `MDE/Paquete MDE KQL Advance Hunting.md` → change title to "# KQL Query Package (Advanced Hunting) 🛡️"

---

### 3. "Quick recommendations" Capitalization and Wording (Pris)

| File | Current | Should be |
|---|---|---|
| MDE KQL | "Quick Recommendations (before running)" | "Quick recommendations (before running)" |
| MDO KQL | "Quick recommendations (before executing)" | "Quick recommendations (before running)" |

**Files to fix (Pris):**
- `MDE/Paquete MDE KQL Advance Hunting.md`
- `MDO/Paquete MDO KQL Advance Hunting.md`

---

### 4. Section Header Terminology Inconsistency (Cross-agent)

The term "Procedimiento" / procedure steps are translated differently:
- **Batty (EntraID):** "Operational steps"
- **Batty (MDA daily/monthly):** "Procedure"
- **Batty (MDA weekly, MDI):** "Step by step"
- **Pris (MDE monthly):** "Step-by-Step Procedure"

**Decision:** Accept this variation — each product area uses slightly different document structures, and the current translations are all natural English. No fix needed.

---

### 5. "Objective" vs "Purpose" (Cross-agent)

- **Batty (EntraID, MDA):** "Objective"
- **Batty (MDI):** "Purpose"

**Decision:** Accept. MDI files use "Purpose" consistently to match their different document structure. Both are correct English.

---

### 6. Untranslated Spanish in Requisitos.md (Pris)

Lines 131–143 (PowerShell code comments):
```
# Módulos para scripts MDO (Exchange Online)
# Módulos para Domain Health Check (se instalan automáticamente por el script, pero pueden pre-instalarse)
# Módulos opcionales según modo de autenticación
```

Lines 169–171 (directory tree comments):
```
├── Config\          # Credenciales cifradas (DPAPI)
├── Reports\         # Reportes HTML generados
│   └── Logs\        # Archivos de log
```

Lines 182–185 (dependency summary):
```
  └── Sin módulos adicionales (usa Invoke-RestMethod nativo)
  └── Az.Accounts  ─ó─  Microsoft.Graph.Authentication
```

**File to fix (Pris):** `Requisitos.md`

---

### 7. Broken Anchor Links in README.md (Pris)

The TOC uses Spanish anchor slugs that won't resolve:
- `#requisitos-y-dependencias` → should be `#requirements-and-dependencies`
- `#microsoft-entra-id-identidad` → should be `#microsoft-entra-id-identity`
- `#microsoft-defender-xdr-reportes-cross-domain` → should be `#microsoft-defender-xdr-cross-domain-reports`
- `#estructura-del-repositorio` → should be `#repository-structure`

**File to fix (Pris):** `README.md` lines 34–41

---

### 8. Spanish Anchor Fragment in MDE Weekly TOC Links (Pris)

`MDE/Guia de Seguridad Operacional MDE tareas semanales.md` lines 13–18 use Spanish anchor fragments in GitHub URLs (e.g., `#análisis-de-tendencias-de-amenazas`). These should be updated to English anchors matching the translated headings.

**File to fix (Pris):** `MDE/Guia de Seguridad Operacional MDE tareas semanales.md`

---

## No Action Needed

- ✅ "Output / DoD" is consistent across Batty's files (EntraID, MDI)
- ✅ "Impact of not doing this" consistent in EntraID files
- ✅ KQL code blocks, PowerShell commands, Azure service names left untranslated (correct)
- ✅ Markdown table formatting preserved across all files
- ✅ Heading hierarchy intact
- ✅ Author attributions preserved
- ✅ Link paths to files use original Spanish filenames (correct — filenames were not renamed)

---

## Summary

| Priority | Count | Agent |
|---|---|---|
| Must fix (Spanish text) | 1 file | Pris |
| Must fix (broken anchors) | 2 files | Pris |
| Should fix (motto inconsistency) | 7 files | Pris |
| Should fix (KQL title/wording) | 3 files | Pris |
| No action needed | All Batty files | — |

**Batty's work:** Clean. Consistent terminology, no untranslated text, natural English throughout.  
**Pris's work:** Good quality overall but needs a consistency pass on the motto tagline, the Requisitos.md Spanish remnants, and broken README anchor links.
