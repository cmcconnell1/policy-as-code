# Documentation Structure

This document explains the documentation organization for this project.

## Overview

This project follows a clean documentation structure with ONE main README.md at the root and all supporting documentation organized in the `docs/` directory.

## Directory Structure

```
policy-as-code/
├── README.md                          # Main entry point (only top-level README)
├── CHANGELOG.md                       # Version history
├── CLAUDE.md                          # Project instructions for Claude Code
├── docs/
│   ├── guides/                        # How-to guides and tutorials
│   │   ├── getting-started.md        # Step-by-step setup guide
│   │   ├── quickstart.md             # Quick reference
│   │   └── compliance-reporting.md   # Compliance report generation
│   ├── reference/                     # Reference documentation
│   │   ├── compliance-mapping.md     # Policy-to-framework mappings
│   │   └── compliance-summary.md     # Compliance capabilities
│   └── architecture/                  # Design and architecture docs
│       ├── project-requirements.md   # Original requirements
│       └── documentation-structure.md # This file
├── policies/                          # Policy definitions
├── tests/                             # Policy tests
├── reporting/                         # Python reporting framework
├── scripts/                           # Automation scripts
└── examples/                          # Example Terraform code
```

## Documentation Categories

### Guides (`docs/guides/`)
Step-by-step tutorials and how-to guides:
- **getting-started.md** - Complete setup instructions (no cloud credentials needed)
- **quickstart.md** - Condensed quick reference for experienced users
- **compliance-reporting.md** - How to generate compliance reports

### Reference (`docs/reference/`)
Reference documentation and specifications:
- **compliance-mapping.md** - Detailed policy-to-framework control mappings
- **compliance-summary.md** - Overview of compliance capabilities

### Architecture (`docs/architecture/`)
Design decisions and project architecture:
- **project-requirements.md** - Original project requirements and specifications
- **documentation-structure.md** - This file

## Documentation Rules

### 1. Single Main README
- Only ONE `README.md` at the project root
- Acts as the main entry point and table of contents
- Contains hyperlinks to all documentation in `docs/`

### 2. No Top-Level Clutter
- No supplemental documentation files in the root directory
- All guides, references, and architecture docs go in `docs/`
- Only configuration files (pyproject.toml, Makefile, etc.) at root

### 3. Consistent Paths
- Always use relative paths: `docs/guides/getting-started.md`
- Never use absolute paths or hardcoded user paths
- Verify all links work after moving files

### 4. Clear Categories
- **guides/** - "How to" documentation
- **reference/** - "What is" documentation
- **architecture/** - "Why" documentation

### 5. Update All Links
- When moving or renaming files, update all references
- Check README.md table of contents
- Check cross-references in other docs
- Update CHANGELOG.md

## Adding New Documentation

When adding new documentation:

1. **Choose the right category:**
   - How-to guide? → `docs/guides/`
   - Reference material? → `docs/reference/`
   - Design/architecture? → `docs/architecture/`

2. **Create the file:**
   - Use descriptive names with hyphens: `my-new-guide.md`
   - Start with a clear title and purpose
   - Include cross-references to related docs

3. **Update README.md:**
   - Add link in the Documentation table
   - Update table of contents if needed

4. **Verify all links:**
   - Test that all hyperlinks work
   - Verify relative paths are correct

## Migration from Old Structure

The following files were moved during reorganization:

| Old Location | New Location |
|--------------|--------------|
| `GETTING_STARTED.md` | `docs/guides/getting-started.md` |
| `QUICKSTART.md` | `docs/guides/quickstart.md` |
| `COMPLIANCE_SUMMARY.md` | `docs/reference/compliance-summary.md` |
| `project-outline-requirement.md` | `docs/architecture/project-requirements.md` |

All references across the codebase have been updated to reflect these new locations.

## Benefits of This Structure

1. **Clean Root Directory** - Only essential files at top level
2. **Easy Navigation** - Clear categories make finding docs easy
3. **Scalability** - Can add more docs without cluttering
4. **Standard Practice** - Follows common open-source conventions
5. **Better Organization** - Related docs grouped together
6. **Single Source of Truth** - README.md is the only entry point

## Maintenance

To maintain this structure:
- Keep README.md as the only top-level documentation
- Always categorize new docs appropriately
- Update links when moving files
- Review documentation organization periodically
- Follow the rules defined in CLAUDE.md

## See Also

- [README.md](../../README.md) - Main project documentation
- [CLAUDE.md](../../CLAUDE.md) - Project instructions for Claude Code
- [Getting Started](../guides/getting-started.md) - Setup guide
