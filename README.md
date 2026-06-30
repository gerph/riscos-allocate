# riscos-allocate

`riscos-allocate` is a command line tool for working with RISC OS Allocate
request files. It reads the native binary request format, displays a readable
summary, extracts a YAML representation for editing and source control, and can
recreate a binary request from that YAML description.

The repository also contains PRM-in-XML documentation for both the tool and
the Allocate file format in [`prminxml/`](prminxml/).

## Features

- Display the contents of an Allocate request file.
- Extract a request to UTF-8 YAML with `--extract`.
- Extract a request to `Allocation.yaml` plus detached attachments with
  `--extract-files`.
- Create a new Allocate binary request from YAML with `--create`.
- Preserve filetype attachments either inline or as detached files.

## Requirements

- Python 3.10 or newer for the tool and Python package build.
- `riscos-prminxml` if you want to lint or build the bundled HTML
  documentation.

## Installation

Install from the repository with:

```sh
python3 -m pip install .
```

This installs the `riscos-allocate` command line tool.

## Usage

Display a request:

```sh
riscos-allocate request,fb0
```

Extract inline YAML:

```sh
riscos-allocate --extract request,fb0
```

Extract YAML plus detached files:

```sh
riscos-allocate --extract-files extracted request,fb0
```

Recreate a binary request from YAML:

```sh
riscos-allocate --create extracted -o rebuilt,fb0
```

## Building

Build the Python distribution artifacts:

```sh
make dist
```

Build the HTML documentation from the PRM-in-XML sources:

```sh
make docs
```

Build both release artifacts:

```sh
make
```

Generated files are written to:

- `dist/` for the Python source distribution and wheel
- `build/docs/html/` for the generated documentation

## Repository Layout

- [`riscos_allocate.py`](riscos_allocate.py) contains the tool implementation.
- [`riscos-allocate.py`](riscos-allocate.py) is a thin executable wrapper.
- [`prminxml/`](prminxml/) contains the source documentation.
- [`.github/workflows/build.yml`](.github/workflows/build.yml) builds the
  release artifacts in CI.

