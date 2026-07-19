#include "qemu/osdep.h"
#include "policy-bpf-vm.h"
#include "policy-bpf-helpers.h"
#include "policy/policy-bpf-abi.h"

#include <elf.h>
#include <openssl/crypto.h>
#include <ubpf.h>

#define PE_BPF_MAX_RODATA_REGIONS 32U
#define PE_BPF_RODATA_REGION_BASE 16U

struct pe_bpf_rodata_region {
    const uint8_t *elf_data;
    uint8_t *copy;
    uint64_t size;
    uint32_t safe_region_id;
};

struct pe_bpf_vm {
    struct ubpf_vm *vm;
    struct pe_bpf_rodata_region rodata[PE_BPF_MAX_RODATA_REGIONS];
    uint32_t rodata_count;
};

struct pe_elf_view {
    const uint8_t *data;
    size_t size;
    const Elf64_Ehdr *header;
    const Elf64_Shdr *sections;
    const char *section_names;
    size_t section_names_size;
};

static void set_error(char **error_out, const char *message)
{
    if (error_out) {
        *error_out = g_strdup(message ? message : "unknown uBPF error");
    }
}

static void set_error_printf(char **error_out, const char *format, ...)
    G_GNUC_PRINTF(2, 3);

static void set_error_printf(char **error_out, const char *format, ...)
{
    va_list arguments;

    if (!error_out) {
        return;
    }
    va_start(arguments, format);
    *error_out = g_strdup_vprintf(format, arguments);
    va_end(arguments);
}

static bool range_valid(size_t total, uint64_t offset, uint64_t length)
{
    return offset <= total && length <= total - offset;
}

static const char *elf_string(const char *table, size_t table_size,
                              uint32_t offset)
{
    if (!table || offset >= table_size ||
        memchr(table + offset, '\0', table_size - offset) == NULL) {
        return NULL;
    }
    return table + offset;
}

static int elf_view_init(const uint8_t *elf, size_t elf_size,
                         struct pe_elf_view *view, char **error_out)
{
    const Elf64_Ehdr *header;
    const Elf64_Shdr *string_section;

    if (!elf || !view || elf_size == 0 ||
        elf_size > SXS_BPF_MAX_ARTIFACT_BYTES) {
        set_error(error_out, elf_size > SXS_BPF_MAX_ARTIFACT_BYTES
                                 ? "policy artifact exceeds 1 MiB"
                                 : "empty policy artifact");
        return -1;
    }
    if (elf_size < sizeof(*header)) {
        set_error(error_out, "truncated ELF header");
        return -1;
    }
    header = (const Elf64_Ehdr *)elf;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
        header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_ident[EI_VERSION] != EV_CURRENT ||
        header->e_type != ET_REL || header->e_machine != EM_BPF ||
        header->e_version != EV_CURRENT) {
        set_error(error_out,
                  "policy must be a 64-bit little-endian relocatable EM_BPF ELF");
        return -1;
    }
    if (header->e_ehsize != sizeof(*header) ||
        header->e_shentsize != sizeof(Elf64_Shdr) ||
        header->e_shnum == 0 || header->e_shstrndx >= header->e_shnum ||
        !range_valid(elf_size, header->e_shoff,
                     (uint64_t)header->e_shnum * sizeof(Elf64_Shdr))) {
        set_error(error_out, "invalid ELF section table");
        return -1;
    }

    memset(view, 0, sizeof(*view));
    view->data = elf;
    view->size = elf_size;
    view->header = header;
    view->sections =
        (const Elf64_Shdr *)(elf + (size_t)header->e_shoff);
    string_section = &view->sections[header->e_shstrndx];
    if (string_section->sh_type != SHT_STRTAB ||
        !range_valid(elf_size, string_section->sh_offset,
                     string_section->sh_size)) {
        set_error(error_out, "invalid ELF section-name table");
        return -1;
    }
    view->section_names =
        (const char *)(elf + (size_t)string_section->sh_offset);
    view->section_names_size = string_section->sh_size;
    return 0;
}

static int validate_relocations(const struct pe_elf_view *view,
                                const Elf64_Shdr *section, char **error_out)
{
    const Elf64_Shdr *symbols;
    const Elf64_Shdr *target;
    uint64_t symbol_count;
    uint64_t count;
    uint64_t i;

    if (section->sh_type == SHT_RELA) {
        set_error(error_out, "SHT_RELA relocations are unsupported");
        return -1;
    }
    if (section->sh_type != SHT_REL) {
        return 0;
    }
    if (section->sh_entsize != sizeof(Elf64_Rel) ||
        section->sh_size % sizeof(Elf64_Rel) != 0 ||
        section->sh_link >= view->header->e_shnum ||
        section->sh_info >= view->header->e_shnum) {
        set_error(error_out, "invalid BPF relocation section");
        return -1;
    }
    symbols = &view->sections[section->sh_link];
    target = &view->sections[section->sh_info];
    if (symbols->sh_type != SHT_SYMTAB ||
        symbols->sh_entsize != sizeof(Elf64_Sym) ||
        symbols->sh_size % sizeof(Elf64_Sym) != 0 ||
        target->sh_type != SHT_PROGBITS ||
        !(target->sh_flags & SHF_EXECINSTR)) {
        set_error(error_out, "relocations must target executable BPF code");
        return -1;
    }
    symbol_count = symbols->sh_size / sizeof(Elf64_Sym);
    count = section->sh_size / sizeof(Elf64_Rel);
    for (i = 0; i < count; i++) {
        Elf64_Rel relocation;
        uint64_t required_bytes;
        uint32_t type;

        memcpy(&relocation,
               view->data + section->sh_offset + i * sizeof(relocation),
               sizeof(relocation));
        type = ELF64_R_TYPE(relocation.r_info);
        if (type != R_BPF_64_64 && type != R_BPF_64_32) {
            set_error_printf(error_out,
                             "unsupported BPF relocation type %u", type);
            return -1;
        }
        required_bytes = type == R_BPF_64_64 ? 16 : 8;
        if (ELF64_R_SYM(relocation.r_info) >= symbol_count ||
            relocation.r_offset % 8 != 0 ||
            relocation.r_offset > target->sh_size ||
            required_bytes > target->sh_size - relocation.r_offset) {
            set_error(error_out, "invalid BPF relocation target");
            return -1;
        }
    }
    return 0;
}

static int validate_symbols(const struct pe_elf_view *view,
                            const Elf64_Shdr *symtab, char **error_out)
{
    const Elf64_Shdr *strings;
    uint64_t symbol_count;
    uint64_t i;
    unsigned int policy_main_count = 0;

    if (symtab->sh_entsize != sizeof(Elf64_Sym) ||
        symtab->sh_size % sizeof(Elf64_Sym) != 0 ||
        symtab->sh_link >= view->header->e_shnum) {
        set_error(error_out, "invalid ELF symbol table");
        return -1;
    }
    strings = &view->sections[symtab->sh_link];
    if (strings->sh_type != SHT_STRTAB ||
        !range_valid(view->size, strings->sh_offset, strings->sh_size)) {
        set_error(error_out, "invalid ELF symbol string table");
        return -1;
    }
    symbol_count = symtab->sh_size / sizeof(Elf64_Sym);
    for (i = 0; i < symbol_count; i++) {
        Elf64_Sym symbol;
        const char *name;

        memcpy(&symbol,
               view->data + symtab->sh_offset + i * sizeof(symbol),
               sizeof(symbol));
        name = elf_string((const char *)view->data + strings->sh_offset,
                          strings->sh_size, symbol.st_name);
        if (!name) {
            set_error(error_out, "invalid ELF symbol name");
            return -1;
        }
        if (strcmp(name, "policy_main") != 0) {
            continue;
        }
        if (ELF64_ST_TYPE(symbol.st_info) != STT_FUNC ||
            ELF64_ST_BIND(symbol.st_info) != STB_GLOBAL ||
            symbol.st_shndx == SHN_UNDEF ||
            symbol.st_shndx >= view->header->e_shnum ||
            !(view->sections[symbol.st_shndx].sh_flags & SHF_EXECINSTR)) {
            set_error(error_out, "policy_main must be one exported function");
            return -1;
        }
        policy_main_count++;
    }
    if (policy_main_count != 1) {
        set_error(error_out, "policy must export exactly one policy_main");
        return -1;
    }
    return 0;
}

static int validate_elf(const uint8_t *elf, size_t elf_size,
                        struct pe_elf_view *view, char **error_out)
{
    const Elf64_Shdr *symtab = NULL;
    uint64_t instruction_count = 0;
    uint16_t i;

    if (elf_view_init(elf, elf_size, view, error_out) != 0) {
        return -1;
    }
    for (i = 0; i < view->header->e_shnum; i++) {
        const Elf64_Shdr *section = &view->sections[i];
        const char *name = elf_string(view->section_names,
                                      view->section_names_size,
                                      section->sh_name);

        if (!name || (section->sh_type != SHT_NOBITS &&
                      !range_valid(elf_size, section->sh_offset,
                                   section->sh_size))) {
            set_error(error_out, "invalid ELF section");
            return -1;
        }
        if ((section->sh_flags & SHF_ALLOC) &&
            (section->sh_flags & SHF_WRITE)) {
            set_error_printf(error_out,
                             "writable allocated section '%s' is forbidden",
                             name);
            return -1;
        }
        if ((section->sh_flags & SHF_ALLOC) &&
            (section->sh_type != SHT_PROGBITS ||
             (section->sh_flags & (SHF_COMPRESSED | SHF_TLS)))) {
            set_error_printf(error_out,
                             "unsupported allocated section '%s'", name);
            return -1;
        }
        if ((section->sh_flags & SHF_EXECINSTR) &&
            !(section->sh_flags & SHF_ALLOC)) {
            set_error_printf(error_out,
                             "executable section '%s' is not allocated", name);
            return -1;
        }
        if (strcmp(name, ".data") == 0 || strcmp(name, ".bss") == 0 ||
            strcmp(name, ".maps") == 0) {
            set_error_printf(error_out, "section '%s' is forbidden", name);
            return -1;
        }
        if (section->sh_flags & SHF_EXECINSTR) {
            if (section->sh_type != SHT_PROGBITS ||
                section->sh_size % 8 != 0) {
                set_error(error_out, "invalid executable BPF section");
                return -1;
            }
            instruction_count += section->sh_size / 8;
            if (instruction_count >= 65536) {
                set_error(error_out,
                          "policy must contain fewer than 65,536 instructions");
                return -1;
            }
        }
        if (section->sh_type == SHT_SYMTAB) {
            if (symtab) {
                set_error(error_out, "multiple ELF symbol tables are unsupported");
                return -1;
            }
            symtab = section;
        }
        if (validate_relocations(view, section, error_out) != 0) {
            return -1;
        }
    }
    if (!symtab) {
        set_error(error_out, "missing ELF symbol table");
        return -1;
    }
    return validate_symbols(view, symtab, error_out);
}

static uint64_t relocate_rodata(void *opaque, const uint8_t *data,
                                uint64_t data_size, const char *symbol_name,
                                uint64_t symbol_offset, uint64_t symbol_size)
{
    struct pe_bpf_vm *policy_vm = opaque;
    uint32_t i;

    (void)symbol_name;
    if (!policy_vm || symbol_offset > data_size ||
        symbol_size > data_size - symbol_offset) {
        return 0;
    }
    for (i = 0; i < policy_vm->rodata_count; i++) {
        struct pe_bpf_rodata_region *region = &policy_vm->rodata[i];

        if (region->elf_data == data && region->size == data_size) {
            return (uint64_t)(uintptr_t)(region->copy + symbol_offset);
        }
    }
    return 0;
}

static int register_rodata(struct pe_bpf_vm *policy_vm,
                           const struct pe_elf_view *view, char **error_out)
{
    uint16_t i;

    for (i = 0; i < view->header->e_shnum; i++) {
        const Elf64_Shdr *section = &view->sections[i];
        struct pe_bpf_rodata_region *region;
        struct ubpf_safe_region safe_region;

        if (section->sh_type != SHT_PROGBITS || section->sh_size == 0 ||
            !(section->sh_flags & SHF_ALLOC) ||
            (section->sh_flags & (SHF_WRITE | SHF_EXECINSTR))) {
            continue;
        }
        if (policy_vm->rodata_count >= PE_BPF_MAX_RODATA_REGIONS) {
            set_error(error_out, "too many read-only data sections");
            return -1;
        }
        region = &policy_vm->rodata[policy_vm->rodata_count];
        region->copy = g_memdup2(view->data + section->sh_offset,
                                 section->sh_size);
        if (!region->copy) {
            set_error(error_out, "failed to allocate policy read-only data");
            return -1;
        }
        region->elf_data = view->data + section->sh_offset;
        region->size = section->sh_size;
        region->safe_region_id =
            PE_BPF_RODATA_REGION_BASE + policy_vm->rodata_count;
        memset(&safe_region, 0, sizeof(safe_region));
        safe_region.id = region->safe_region_id;
        safe_region.base = region->copy;
        safe_region.size = region->size;
        safe_region.kind = UBPF_SAFE_REGION_POINTER;
        safe_region.permissions = UBPF_SAFE_REGION_READ;
        if (ubpf_register_safe_region(policy_vm->vm, &safe_region) != 0) {
            set_error(error_out, "failed to register policy read-only data");
            return -1;
        }
        policy_vm->rodata_count++;
    }
    if (ubpf_register_data_relocation(policy_vm->vm, policy_vm,
                                      relocate_rodata) != 0) {
        set_error(error_out, "failed to register read-only data relocation");
        return -1;
    }
    return 0;
}

struct pe_bpf_vm *pe_bpf_vm_create(const uint8_t *elf, size_t elf_size,
                                    char **error_out)
{
    struct pe_bpf_vm *policy_vm;
    struct pe_elf_view view;
    char *ubpf_error = NULL;

    if (error_out) {
        *error_out = NULL;
    }
    if (validate_elf(elf, elf_size, &view, error_out) != 0) {
        return NULL;
    }

    policy_vm = g_new0(struct pe_bpf_vm, 1);
    policy_vm->vm = ubpf_create();
    if (!policy_vm->vm) {
        set_error(error_out, "failed to create uBPF VM");
        goto fail;
    }
    if (ubpf_set_execution_profile(policy_vm->vm,
                                   UBPF_EXECUTION_PROFILE_SAFE) != 0) {
        set_error(error_out, "failed to select safe uBPF execution profile");
        goto fail;
    }
    ubpf_set_instruction_limit(policy_vm->vm, PE_BPF_INSTRUCTION_LIMIT, NULL);
    if (pe_bpf_helpers_register(policy_vm->vm) != 0) {
        set_error(error_out, "failed to register the policy helper allowlist");
        goto fail;
    }
    if (register_rodata(policy_vm, &view, error_out) != 0) {
        goto fail;
    }
    if (ubpf_load_elf_ex(policy_vm->vm, elf, elf_size,
                         "policy_main", &ubpf_error) < 0) {
        set_error(error_out, ubpf_error);
        free(ubpf_error);
        goto fail;
    }
    return policy_vm;

fail:
    pe_bpf_vm_destroy(policy_vm);
    return NULL;
}

int pe_bpf_vm_validate(const uint8_t *elf, size_t elf_size, char **error_out)
{
    struct pe_bpf_vm *policy_vm =
        pe_bpf_vm_create(elf, elf_size, error_out);

    if (!policy_vm) {
        return -1;
    }
    pe_bpf_vm_destroy(policy_vm);
    return 0;
}

void pe_bpf_vm_destroy(struct pe_bpf_vm *policy_vm)
{
    uint32_t i;

    if (!policy_vm) {
        return;
    }
    if (policy_vm->vm) {
        ubpf_destroy(policy_vm->vm);
    }
    for (i = 0; i < policy_vm->rodata_count; i++) {
        g_free(policy_vm->rodata[i].copy);
    }
    g_free(policy_vm);
}

int pe_bpf_vm_execute(struct pe_bpf_vm *policy_vm, void *context,
                      size_t context_size, uint64_t *result_out)
{
    uint8_t stack[PE_BPF_STACK_BYTES];
    int rc;

    if (!policy_vm || !policy_vm->vm || !context || context_size == 0 ||
        !result_out) {
        return -1;
    }
    memset(stack, 0, sizeof(stack));
    rc = ubpf_exec_ex(policy_vm->vm, context, context_size, result_out,
                      stack, sizeof(stack));
    OPENSSL_cleanse(stack, sizeof(stack));
    return rc;
}
