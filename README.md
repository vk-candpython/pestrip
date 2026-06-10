# ✂️ pestrip


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Windows-blue?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Language](https://img.shields.io/badge/language-C-00599C?logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Extreme PE metadata stripper — Remove everything non‑essential, keep execution*

</div>

> **⚠️ WARNING**  
> This tool is for educational purposes and authorized security auditing only.  
> The author is not responsible for any misuse.

---

## 📥 Download | Скачать

**Precompiled binary (Windows x64) is available in the release:**  
**Готовый бинарник (Windows x64) в релизе:**

👉 **[Download / Скачать pestrip v1.0.0](https://github.com/vk-candpython/pestrip/releases/tag/v1.0.0)** 👈

Go to **Assets** → click `pestrip.exe` → run from command line:  
Перейдите в **Assets** → нажмите `pestrip.exe` → запускайте из командной строки:

```cmd
pestrip.exe <your-pe-file>
```

---

## 📖 Table of Contents | Оглавление

- [English](#english)
  - [Overview](#overview)
  - [Features](#features)
  - [Quick Start](#quick-start)
  - [Example](#example)
  - [Requirements](#requirements)
  - [Troubleshooting](#troubleshooting)
- [Русский](#русский)
  - [Обзор](#обзор)
  - [Возможности](#возможности)
  - [Быстрый старт](#быстрый-старт)
  - [Пример](#пример)
  - [Требования](#требования)
  - [Устранение неполадок](#устранение-неполадок)

---

# English

## Overview

**pestrip** — is an extreme PE (Portable Executable) stripper that removes **all non‑critical metadata** from Windows executables and DLLs. It goes far beyond standard linker optimizations or simple section removal:

- **Collapses** the DOS stub and shifts the entire NT headers to the minimum possible offset, reclaiming space.
- **Zeroes out** obsolete COFF fields in section headers (names, relocations, line numbers), leaving only essential layout information.
- **Removes** non‑mandatory data directories: debug information, security certificates, architecture stubs, bound imports.
- **Strips** compiler and linker metadata: time‑date stamp, linker versions, image versions, checksum, legacy load flags.
- **Eliminates** debug and telemetry sections completely (`.debug*`, `.comment`, `.ident`, `.msvcjmc`, `.drectve`, symtab/strtab sections).
- **Trims trailing zeros** from every section’s raw data area and re‑aligns the physical size to the file alignment boundary.
- **Compacts** the section header table, physically sliding section bodies leftward to eliminate gaps, then recalculates `SizeOfHeaders` and `SizeOfImage`.
- **Wipes all alignment slacks** between relocated sections with zeros and truncates the file to the 8‑byte aligned final size.
- **Preserves** everything critical for execution: all flagged `PT_LOAD`-equivalent sections, imports, exports, relocations, TLS, resources, and thread‑local storage.
- **Resolves** long section names from the COFF string table to apply removal heuristics even on unnamed debug sections.
- **Outputs clear statistics**: old size, new size, and percentage reduction with one decimal.

The result: a **compact, clean** PE that runs exactly like the original but can be **40‑75 % smaller** (depending on original debug data).

## Features

| Feature | Description |
|---------|-------------|
| 🗜️ **DOS Stub Removal** | Moves NT headers down, eliminating the DOS stub and aligning to file alignment |
| 🧹 **COFF Metadata Wipe** | Zeroes section names, relocations, line numbers, and symbolic debug pointers |
| 📦 **Section Compaction** | Drops garbage sections, slides remaining headers and bodies left, rebuilds layout |
| 🧠 **Virtual Size Rebuild** | Recalculates `SizeOfImage` from compacted sections, preserving alignment |
| 🛡️ **Safe Data Directory Prune** | Removes only non‑essential directories (debug, security, bound import, etc.) |
| 🧬 **Smart Debug Drop** | Deletes `.debug*`, `.comment`, `.ident`, `.msvcjmc`, `.drectve`, and MinGW symbol/string tables |
| 📉 **Optional Header Sanitization** | Zeroes linker versions, timestamps, image versions, checksum, loader flags |
| 📏 **Trailing Zero Truncation** | Cuts physical zeros at the end of every section, shrinks raw data size |
| 🕳️ **Alignment Gap Wiping** | Fills all slack space between compacted sections with zeros |
| 📐 **8‑Byte Final Alignment** | Truncates final file size to an 8‑byte boundary |
| 🏳️ **Long Name Resolution** | Reads COFF string table to identify sections with `/nnn` names |
| 📊 **Statistics** | Prints old → new size in bytes and percentage reduction |
| 🔧 **In‑Place Modification** | Modifies target file directly (backup recommended) |
| ⚡ **No Dependencies** | Single C file, compiles with MSVC/MinGW, uses only Windows API |

## Quick Start

### Download precompiled binary (from release)

```cmd
# Download from https://github.com/vk-candpython/pestrip/releases/tag/v1.0.0
curl -LO https://github.com/vk-candpython/pestrip/releases/download/v1.0.0/pestrip.exe
```

### Or compile from source

```cmd
:: Using MSVC
cl /O2 /Os pestrip.c /link /subsystem:console

:: Using MinGW
gcc -Os -s pestrip.c -o pestrip.exe
```

### Usage

```cmd
pestrip.exe <pe-file>
```

> **⚠️ Caution:** Modifies the target file **in‑place** – make a backup if needed.

## Example

**Before stripping** – a typical debug build of a PE32+ executable:

```text
> dumpbin /headers demo.exe
...
SECTION HEADER #1
  .text name
   1000 size of raw data
    400 file pointer to raw data
...

  Debug Directories
        Time Type        Size      RVA  Pointer
    -------- ----------- -------- -------- --------
    12345678 cv           123      5678     5678   Format: RSDS, {GUID}, 1, demo.pdb
```

**After running `pestrip demo.exe`:**

```text
> pestrip demo.exe
[+] Stripped: 46872 -> 12288 bytes (-73.7%)
```

```text
> dumpbin /headers demo.exe
...
SECTION HEADER #0 (empty)
SECTION HEADER #1
  .text name
    400 size of raw data
    200 file pointer to raw data
...
  Debug Directories
       (none)
```

All debug sections removed, no symbols, DOS stub gone, file layout compressed – yet the executable runs normally.

## Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| **OS** | Windows 7+ | 64‑bit (x64) |
| **Architecture** | PE32+ (x64) | Only 64‑bit executables/DLLs |
| **Compiler** | MSVC / MinGW‑w64 | only for source build |
| **File Size** | ≥ 1024 bytes | enforced by `MIN_PE_SZ` |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `file size is below minimum PE threshold` | Input file < 1 KB; refuse to process. |
| `file is not valid PE binary` | MZ signature or PE signature missing. |
| `invalid PE-file structure` | Malformed headers, alignment violations, or overflow. |
| `PE-file architecture is not x64` | Only PE32+ supported. PE32 (32‑bit) or other architectures rejected. |
| Errors during `SetFilePointerEx` / `SetEndOfFile` | Cannot write changes; check disk space/permissions. |
| Binary crashes after stripping | Original relied on removed data directories (rare); modify directory blacklist in source. |

---

# Русский

## Обзор

**pestrip** — это экстремальный стриппер PE‑бинарников, который удаляет **все некритичные метаданные** из исполняемых файлов и DLL Windows. Он идёт гораздо дальше стандартных оптимизаций компоновщика или простого удаления секций:

- **Схлопывает** DOS‑стаб и сдвигает все NT‑заголовки до минимально возможного смещения, освобождая место.
- **Зануляет** устаревшие COFF‑поля в заголовках секций (имена, таблицы перемещений, номера строк), оставляя только необходимую для загрузки информацию.
- **Удаляет** необязательные директории данных: отладочную информацию, цифровые подписи, архитектурные заглушки, bound‑импорты.
- **Стирает** метаданные компилятора и компоновщика: временну́ю метку, версии компоновщика и образа, контрольную сумму, флаги загрузки.
- **Полностью убирает** отладочные и телеметрические секции (`.debug*`, `.comment`, `.ident`, `.msvcjmc`, `.drectve`, а также символьные таблицы MinGW).
- **Обрезает хвостовые нули** в сырых данных каждой секции и перевыравнивает физический размер по границе файлового выравнивания.
- **Уплотняет** таблицу заголовков секций, физически сдвигая тела секций влево для устранения промежутков, после чего пересчитывает `SizeOfHeaders` и `SizeOfImage`.
- **Затирает нулями** все выравнивающие зазоры между перемещёнными секциями и усекает файл до 8‑байтной границы.
- **Сохраняет** всё, что необходимо для выполнения: все секции с флагами (аналог `PT_LOAD`), импорт, экспорт, перемещения, TLS, ресурсы и локальное хранилище потоков.
- **Разрешает** длинные имена секций из COFF‑строковой таблицы, чтобы применять эвристики удаления даже к безымянным отладочным секциям.
- **Выводит понятную статистику**: старый размер, новый размер и процент уменьшения с одной десятой.

Результат: **компактный, чистый** PE, который работает точно так же, как оригинал, но может быть на **40–75 % меньше** (в зависимости от объёма отладочных данных).

## Возможности

| Функция | Описание |
|---------|----------|
| 🗜️ **Удаление DOS‑стаба** | Смещает NT‑заголовки вниз, устраняя DOS‑стаб и выравнивая по файловому границе |
| 🧹 **Зачистка COFF‑метаданных** | Обнуляет имена секций, таблицы перемещений, строки номеров и указатели символов |
| 📦 **Уплотнение секций** | Удаляет мусорные секции, сдвигает оставшиеся заголовки и тела влево, перестраивает раскладку |
| 🧠 **Пересчёт виртуального размера** | Пересчитывает `SizeOfImage` на основе уплотнённых секций, сохраняя выравнивание |
| 🛡️ **Безопасная очистка Data Directory** | Удаляет только необязательные записи (debug, security, bound import и т.д.) |
| 🧬 **Умное удаление отладки** | Убирает `.debug*`, `.comment`, `.ident`, `.msvcjmc`, `.drectve` и символьные таблицы MinGW |
| 📉 **Очистка Optional Header** | Обнуляет версии компоновщика, временную метку, версии образа, контрольную сумму, флаги загрузчика |
| 📏 **Обрезка хвостовых нулей** | Отрезает физические нули в конце каждой секции, уменьшая размер сырых данных |
| 🕳️ **Затирка выравнивающих зазоров** | Заполняет нулями всё свободное пространство между уплотнёнными секциями |
| 📐 **Финальное выравнивание по 8 байт** | Усекает итоговый размер файла до границы 8 байт |
| 🏳️ **Разрешение длинных имён** | Читает COFF‑строковую таблицу для идентификации секций с именами вида `/nnn` |
| 📊 **Статистика** | Выводит старый → новый размер в байтах и процент уменьшения |
| 🔧 **Изменение на месте** | Изменяет файл напрямую (рекомендуется бэкап) |
| ⚡ **Нет зависимостей** | Один C‑файл, компилируется MSVC/MinGW, использует только Windows API |

## Быстрый старт

### Скачать готовый бинарник (из релиза)

```cmd
# Скачать с https://github.com/vk-candpython/pestrip/releases/tag/v1.0.0
curl -LO https://github.com/vk-candpython/pestrip/releases/download/v1.0.0/pestrip.exe
```

### Или собрать из исходников

```cmd
:: Через MSVC
cl /O2 /Os pestrip.c /link /subsystem:console

:: Через MinGW
gcc -Os -s pestrip.c -o pestrip.exe
```

### Использование

```cmd
pestrip.exe <pe-файл>
```

> **⚠️ Внимание:** Изменяет файл **на месте** – сделайте бэкап при необходимости.

## Пример

**До обработки** – типичная отладочная сборка PE32+:

```text
> dumpbin /headers demo.exe
...
SECTION HEADER #1
  .text name
   1000 size of raw data
    400 file pointer to raw data
...

  Debug Directories
        Time Type        Size      RVA  Pointer
    -------- ----------- -------- -------- --------
    12345678 cv           123      5678     5678   Format: RSDS, {GUID}, 1, demo.pdb
```

**После `pestrip demo.exe`:**

```text
> pestrip demo.exe
[+] Stripped: 46872 -> 12288 bytes (-73.7%)
```

```text
> dumpbin /headers demo.exe
...
SECTION HEADER #0 (empty)
SECTION HEADER #1
  .text name
    400 size of raw data
    200 file pointer to raw data
...
  Debug Directories
       (none)
```

Все отладочные секции удалены, нет символов, DOS‑стаб убран, структура файла уплотнена – при этом исполняемый файл работает как прежде.

## Требования

| Требование | Минимум | Примечания |
|------------|---------|------------|
| **ОС** | Windows 7+ | 64‑битная (x64) |
| **Архитектура** | PE32+ (x64) | Только 64‑битные EXE/DLL |
| **Компилятор** | MSVC / MinGW‑w64 | только для сборки из исходников |
| **Размер файла** | ≥ 1024 байт | проверка `MIN_PE_SZ` |

## Устранение неполадок

| Проблема | Решение |
|----------|---------|
| `file size is below minimum PE threshold` | Входной файл < 1 КБ; обработка отклонена. |
| `file is not valid PE binary` | Отсутствуют сигнатуры MZ или PE. |
| `invalid PE-file structure` | Повреждённые заголовки, нарушение выравнивания или переполнение. |
| `PE-file architecture is not x64` | Поддерживается только PE32+. PE32 (32‑бит) или другие архитектуры отклоняются. |
| Ошибки `SetFilePointerEx` / `SetEndOfFile` | Не удалось записать изменения; проверьте место на диске и права. |
| Бинарник падает после обработки | Исходный файл полагался на удалённые директории (редко); измените чёрный список в исходнике. |

---

<div align="center">

**[⬆ Back to Top / Наверх](#-pestrip)**

*Extreme PE stripping for Windows*

</div>
