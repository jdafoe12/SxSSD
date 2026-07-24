#include "qemu/osdep.h"
#include "policy-wamr-vm.h"
#include "policy-wamr-imports.h"
#include "policy-runtime.h"
#include "qemu/error-report.h"

#define WASM_ENABLE_INSTRUCTION_METERING 1
#include <wasm_export.h>
#include <openssl/crypto.h>

#define PE_WAMR_ERROR_BYTES 256U

static const uint8_t wasm_core_1_header[] = {
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
};

struct pe_wamr_vm {
    uint8_t *artifact;
    wasm_module_t module;
    wasm_module_inst_t instance;
    wasm_exec_env_t exec_env;
    wasm_function_inst_t init_function;
    wasm_function_inst_t condition_function;
    wasm_function_inst_t action_function;
    wasm_memory_inst_t memory;
    wasm_global_inst_t stack_pointer;
    uint8_t *condition_snapshot;
    uint32_t memory_bytes;
};

enum pe_wamr_runtime_state {
    PE_WAMR_RUNTIME_READY = 1,
    PE_WAMR_RUNTIME_FAILED,
};

static gsize pe_wamr_runtime_state;

static void pe_wamr_thread_environment_destroy(gpointer initialized)
{
    if (initialized) {
        wasm_runtime_destroy_thread_env();
    }
}

static GPrivate pe_wamr_thread_environment =
    G_PRIVATE_INIT(pe_wamr_thread_environment_destroy);

static void set_error(char **error_out, const char *message)
{
    if (error_out) {
        *error_out = g_strdup(message ? message : "unknown WAMR error");
    }
}

static bool read_u32_leb(const uint8_t **cursor, const uint8_t *end,
                         uint32_t *value_out)
{
    uint32_t value = 0;
    unsigned int shift;

    for (shift = 0; shift < 35 && *cursor < end; shift += 7) {
        uint8_t byte = *(*cursor)++;

        if (shift == 28 && (byte & 0xf0)) {
            return false;
        }
        value |= (uint32_t)(byte & 0x7f) << shift;
        if (!(byte & 0x80)) {
            *value_out = value;
            return true;
        }
    }
    return false;
}

static bool skip_wasm_name(const uint8_t **cursor, const uint8_t *end,
                           const uint8_t **name_out, uint32_t *length_out)
{
    uint32_t length;

    if (!read_u32_leb(cursor, end, &length) ||
        length > (uint32_t)(end - *cursor)) {
        return false;
    }
    if (name_out) {
        *name_out = *cursor;
    }
    if (length_out) {
        *length_out = length;
    }
    *cursor += length;
    return true;
}

static bool skip_limits(const uint8_t **cursor, const uint8_t *end)
{
    uint32_t flags;
    uint32_t ignored;

    if (!read_u32_leb(cursor, end, &flags) || flags > 3 ||
        !read_u32_leb(cursor, end, &ignored)) {
        return false;
    }
    return !(flags & 1) || read_u32_leb(cursor, end, &ignored);
}

static bool skip_import_description(const uint8_t **cursor,
                                    const uint8_t *end, uint8_t kind)
{
    uint32_t ignored;

    switch (kind) {
    case 0: /* function */
        return read_u32_leb(cursor, end, &ignored);
    case 1: /* table */
        if (*cursor >= end) {
            return false;
        }
        (*cursor)++;
        return skip_limits(cursor, end);
    case 2: /* memory */
        return skip_limits(cursor, end);
    case 3: /* global */
        if ((size_t)(end - *cursor) < 2) {
            return false;
        }
        *cursor += 2;
        return true;
    case 4: /* tag */
        if (*cursor >= end) {
            return false;
        }
        (*cursor)++;
        return read_u32_leb(cursor, end, &ignored);
    default:
        return false;
    }
}

static int validate_import_authority(const uint8_t *wasm, size_t wasm_size,
                                     enum pe_policy_privilege privilege,
                                     char **error_out)
{
    static const char privileged_module[] = "sxs_privileged_v1";
    const uint8_t *cursor = wasm + sizeof(wasm_core_1_header);
    const uint8_t *end = wasm + wasm_size;

    while (cursor < end) {
        const uint8_t *section_end;
        uint32_t section_size;
        uint8_t section_id = *cursor++;

        if (!read_u32_leb(&cursor, end, &section_size) ||
            section_size > (size_t)(end - cursor)) {
            goto malformed;
        }
        section_end = cursor + section_size;
        if (section_id == 2) {
            uint32_t count;

            if (!read_u32_leb(&cursor, section_end, &count)) {
                break;
            }
            for (uint32_t i = 0; i < count; i++) {
                const uint8_t *module;
                uint32_t module_length;
                uint8_t kind;

                if (!skip_wasm_name(&cursor, section_end, &module,
                                    &module_length) ||
                    !skip_wasm_name(&cursor, section_end, NULL, NULL) ||
                    cursor >= section_end) {
                    goto malformed;
                }
                kind = *cursor++;
                if (!skip_import_description(&cursor, section_end, kind)) {
                    goto malformed;
                }
                if (privilege != PE_PRIVILEGE_PRIVILEGED &&
                    module_length == sizeof(privileged_module) - 1 &&
                    !memcmp(module, privileged_module, module_length)) {
                    set_error(error_out,
                              "normal policy imports sxs_privileged_v1");
                    return -1;
                }
            }
            if (cursor != section_end) {
                goto malformed;
            }
        }
        cursor = section_end;
    }
    return 0;

malformed:
    set_error(error_out, "malformed WebAssembly import section");
    return -1;
}

static int validate_memory_declaration(const uint8_t *wasm, size_t wasm_size,
                                       char **error_out)
{
    const uint8_t *cursor = wasm + sizeof(wasm_core_1_header);
    const uint8_t *end = wasm + wasm_size;
    bool found = false;

    while (cursor < end) {
        const uint8_t *section_end;
        uint32_t section_size;
        uint8_t section_id = *cursor++;

        if (!read_u32_leb(&cursor, end, &section_size) ||
            section_size > (size_t)(end - cursor)) {
            set_error(error_out, "malformed WebAssembly section");
            return -1;
        }
        section_end = cursor + section_size;
        if (section_id == 5) {
            uint32_t count, flags, minimum, maximum;

            if (found || !read_u32_leb(&cursor, section_end, &count) ||
                count != 1 ||
                !read_u32_leb(&cursor, section_end, &flags) || flags != 1 ||
                !read_u32_leb(&cursor, section_end, &minimum) ||
                !read_u32_leb(&cursor, section_end, &maximum) ||
                minimum == 0 || minimum != maximum ||
                maximum > PE_WAMR_MAX_LINEAR_MEMORY_PAGES ||
                cursor != section_end) {
                set_error(error_out,
                          "policy must declare fixed memory of at most 2 MiB");
                return -1;
            }
            found = true;
        }
        cursor = section_end;
    }
    if (!found) {
        set_error(error_out,
                  "policy must declare fixed memory of at most 2 MiB");
        return -1;
    }
    return 0;
}

static int pe_wamr_ensure_thread_environment(char **error_out)
{
    if (g_private_get(&pe_wamr_thread_environment)) {
        return 0;
    }
    if (!wasm_runtime_init_thread_env()) {
        set_error(error_out,
                  "failed to initialize WAMR environment for QEMU thread");
        return -1;
    }
    g_private_set(&pe_wamr_thread_environment, GINT_TO_POINTER(1));
    return 0;
}

static int validate_artifact(const uint8_t *wasm, size_t wasm_size,
                             enum pe_policy_privilege privilege,
                             char **error_out)
{
    if (!wasm || wasm_size == 0 ||
        wasm_size > SXS_WASM_MAX_ARTIFACT_BYTES) {
        set_error(error_out, wasm_size > SXS_WASM_MAX_ARTIFACT_BYTES ?
                  "policy artifact exceeds 1 MiB" :
                  "empty policy artifact");
        return -1;
    }
    if (wasm_size < sizeof(wasm_core_1_header) ||
        memcmp(wasm, wasm_core_1_header, sizeof(wasm_core_1_header))) {
        set_error(error_out,
                  "policy must be a WebAssembly Core 1.0 module");
        return -1;
    }
    if (validate_memory_declaration(wasm, wasm_size, error_out) != 0) {
        return -1;
    }
    return validate_import_authority(wasm, wasm_size, privilege,
                                     error_out);
}

int pe_wamr_runtime_initialize(char **error_out)
{
    /* Initialize the process-wide runtime exactly once. */
    if (g_once_init_enter(&pe_wamr_runtime_state)) {
        RuntimeInitArgs arguments = {
            .mem_alloc_type = Alloc_With_System_Allocator,
        };
        bool initialized = wasm_runtime_full_init(&arguments);
        gsize state = PE_WAMR_RUNTIME_READY;

        if (!initialized || pe_wamr_imports_register() != 0) {
            if (initialized) {
                wasm_runtime_destroy();
            }
            state = PE_WAMR_RUNTIME_FAILED;
        }
        /* Publish the result and release threads waiting in g_once_init_enter. */
        g_once_init_leave(&pe_wamr_runtime_state, state);
    }
    if (pe_wamr_runtime_state != PE_WAMR_RUNTIME_READY) {
        set_error(error_out, "failed to initialize WAMR/import allowlist");
        return -1;
    }
    return pe_wamr_ensure_thread_environment(error_out);
}

static bool function_has_type(wasm_module_inst_t instance,
                              wasm_function_inst_t function,
                              const wasm_valkind_t *parameters,
                              uint32_t parameter_count,
                              wasm_valkind_t result)
{
    wasm_valkind_t actual_parameters[2] = {0};
    wasm_valkind_t actual_result = 0;

    if (!function || parameter_count > G_N_ELEMENTS(actual_parameters) ||
        wasm_func_get_param_count(function, instance) != parameter_count ||
        wasm_func_get_result_count(function, instance) != 1) {
        return false;
    }
    if (parameter_count) {
        wasm_func_get_param_types(function, instance, actual_parameters);
        if (memcmp(actual_parameters, parameters,
                   parameter_count * sizeof(*parameters))) {
            return false;
        }
    }
    wasm_func_get_result_types(function, instance, &actual_result);
    return actual_result == result;
}

struct pe_wamr_vm *pe_wamr_vm_create_with_config(
    const uint8_t *wasm, size_t wasm_size,
    const struct pe_wamr_load_config *config, char **error_out)
{
    struct pe_wamr_vm *vm = NULL;
    LoadArgs load = {
        .no_resolve = true,
    };
    InstantiationArgs instantiate = {
        .default_stack_size = PE_WAMR_EXEC_ENV_STACK_BYTES,
        .host_managed_heap_size = 0,
        .max_memory_pages = PE_WAMR_MAX_LINEAR_MEMORY_PAGES,
    };
    wasm_valkind_t pair_parameter = WASM_I32;
    char error[PE_WAMR_ERROR_BYTES] = {0};

    if (error_out) {
        *error_out = NULL;
    }
    if (validate_artifact(wasm, wasm_size,
                          config ? config->privilege : PE_PRIVILEGE_NORMAL,
                          error_out) != 0 ||
        pe_wamr_runtime_initialize(error_out) != 0) {
        return NULL;
    }
    vm = g_new0(struct pe_wamr_vm, 1);
    vm->artifact = g_memdup2(wasm, wasm_size);
    vm->module = wasm_runtime_load_ex(vm->artifact, wasm_size, &load,
                                      error, sizeof(error));
    if (!vm->module) {
        set_error(error_out, error);
        goto fail;
    }
    if (!wasm_runtime_resolve_symbols(vm->module)) {
        set_error(error_out,
                  config &&
                          config->privilege == PE_PRIVILEGE_PRIVILEGED
                      ? "privileged-policy imports must resolve to sxs_v1 or "
                        "sxs_privileged_v1"
                      : "policy imports must resolve to the registered "
                        "sxs_v1 API");
        goto fail;
    }
    vm->instance = wasm_runtime_instantiate_ex(vm->module, &instantiate,
                                               error, sizeof(error));
    if (!vm->instance) {
        set_error(error_out, error);
        goto fail;
    }
    if (!wasm_runtime_set_running_mode(vm->instance, Mode_Interp)) {
        set_error(error_out, "WAMR safe interpreter configuration failed");
        goto fail;
    }
    wasm_runtime_set_bounds_checks(vm->instance, true);
    if (!wasm_runtime_is_bounds_checks_enabled(vm->instance)) {
        set_error(error_out, "WAMR memory bounds checks are unavailable");
        goto fail;
    }
    vm->memory = wasm_runtime_get_default_memory(vm->instance);
    if (!vm->memory ||
        wasm_memory_get_cur_page_count(vm->memory) == 0 ||
        wasm_memory_get_cur_page_count(vm->memory) !=
            wasm_memory_get_max_page_count(vm->memory) ||
        wasm_memory_get_cur_page_count(vm->memory) >
            PE_WAMR_MAX_LINEAR_MEMORY_PAGES ||
        wasm_memory_get_bytes_per_page(vm->memory) !=
            PE_WAMR_PAGE_BYTES ||
        wasm_memory_get_shared(vm->memory)) {
        set_error(error_out,
                  "policy must define fixed memory of at most 2 MiB");
        goto fail;
    }
    vm->memory_bytes =
        wasm_memory_get_cur_page_count(vm->memory) * PE_WAMR_PAGE_BYTES;
    vm->init_function =
        wasm_runtime_lookup_function(vm->instance, "sxs_policy_init");
    vm->condition_function =
        wasm_runtime_lookup_function(vm->instance, "sxs_policy_condition");
    vm->action_function =
        wasm_runtime_lookup_function(vm->instance, "sxs_policy_action");
    if (!function_has_type(vm->instance, vm->init_function, NULL, 0, WASM_I32) ||
        !function_has_type(vm->instance, vm->condition_function,
                           &pair_parameter, 1, WASM_I32) ||
        !function_has_type(vm->instance, vm->action_function,
                           &pair_parameter, 1, WASM_I64)) {
        set_error(error_out, "missing or invalid SxSSD policy exports");
        goto fail;
    }
    if (!wasm_runtime_get_export_global_inst(vm->instance, "__stack_pointer",
                                             &vm->stack_pointer) ||
        vm->stack_pointer.kind != WASM_I32 ||
        !vm->stack_pointer.is_mutable || !vm->stack_pointer.global_data) {
        set_error(error_out, "missing mutable i32 __stack_pointer export");
        goto fail;
    }
    vm->exec_env = wasm_runtime_create_exec_env(
        vm->instance, PE_WAMR_EXEC_ENV_STACK_BYTES);
    vm->condition_snapshot = g_malloc(vm->memory_bytes);
    if (!vm->exec_env || !vm->condition_snapshot) {
        set_error(error_out, "failed to allocate WAMR execution resources");
        goto fail;
    }
    return vm;

fail:
    pe_wamr_vm_destroy(vm);
    return NULL;
}

struct pe_wamr_vm *pe_wamr_vm_create(const uint8_t *wasm, size_t wasm_size,
                                     char **error_out)
{
    const struct pe_wamr_load_config config = {
        .privilege = PE_PRIVILEGE_NORMAL,
    };

    return pe_wamr_vm_create_with_config(wasm, wasm_size, &config, error_out);
}

int pe_wamr_vm_validate(const uint8_t *wasm, size_t wasm_size,
                        char **error_out)
{
    struct pe_wamr_vm *vm = pe_wamr_vm_create(wasm, wasm_size, error_out);

    if (!vm) {
        return -1;
    }
    pe_wamr_vm_destroy(vm);
    return 0;
}

void pe_wamr_vm_destroy(struct pe_wamr_vm *vm)
{
    if (!vm) {
        return;
    }
    if (vm->exec_env) {
        wasm_runtime_destroy_exec_env(vm->exec_env);
    }
    if (vm->instance) {
        wasm_runtime_deinstantiate(vm->instance);
    }
    if (vm->module) {
        wasm_runtime_unload(vm->module);
    }
    if (vm->condition_snapshot) {
        OPENSSL_cleanse(vm->condition_snapshot, vm->memory_bytes);
    }
    g_free(vm->condition_snapshot);
    g_free(vm->artifact);
    g_free(vm);
}


// TODO: Look at this in details.
int pe_wamr_vm_execute(struct pe_wamr_vm *vm,
                       struct pe_policy_execution *execution,
                       uint64_t *result_out)
{
    wasm_function_inst_t function;
    wasm_val_t argument = { .kind = WASM_I32 };
    wasm_val_t result = {0};
    uint8_t *memory_base;
    uint32_t saved_stack_pointer = 0;
    uint32_t argument_count;
    bool condition;
    bool called;

    if (!vm || !execution || !result_out) {
        return -1;
    }
    if (pe_wamr_ensure_thread_environment(NULL) != 0) {
        return -1;
    }
    condition = execution->authoritative_phase == SXS_PHASE_CONDITION;

    // This ensures that the policy functions have correct argumments?
    switch (execution->authoritative_phase) {
    case SXS_PHASE_INIT:
        function = vm->init_function;
        result.kind = WASM_I32;
        argument_count = 0;
        break;
    case SXS_PHASE_CONDITION:
        function = vm->condition_function;
        result.kind = WASM_I32;
        argument.of.i32 = execution->pair_id;
        argument_count = 1;
        break;
    case SXS_PHASE_ACTION:
        function = vm->action_function;
        result.kind = WASM_I64;
        argument.of.i32 = execution->pair_id;
        argument_count = 1;
        break;
    default:
        return -1;
    }

    memory_base = wasm_memory_get_base_address(vm->memory);
    if (!memory_base) {
        return -1;
    }
    if (condition) {
        memcpy(vm->condition_snapshot, memory_base,
               vm->memory_bytes);
        memcpy(&saved_stack_pointer, vm->stack_pointer.global_data,
               sizeof(saved_stack_pointer));
    }
    wasm_runtime_clear_exception(vm->instance);
    wasm_runtime_set_instruction_count_limit(vm->exec_env,
                                              PE_WAMR_INSTRUCTION_LIMIT);
    wasm_runtime_set_user_data(vm->exec_env, execution);
    called = wasm_runtime_call_wasm_a(vm->exec_env, function, 1, &result,
                                      argument_count,
                                      argument_count ? &argument : NULL);
    wasm_runtime_set_user_data(vm->exec_env, NULL);
    if (condition) {
        memcpy(memory_base, vm->condition_snapshot,
               vm->memory_bytes);
        memcpy(vm->stack_pointer.global_data, &saved_stack_pointer,
               sizeof(saved_stack_pointer));
    }
    if (!called) {
        const char *exception = wasm_runtime_get_exception(vm->instance);

        if (exception) {
            error_report("[PolicyEngine] WAMR fault: %.160s", exception);
        }
        wasm_runtime_clear_exception(vm->instance);
        return -1;
    }
    if ((execution->authoritative_phase == SXS_PHASE_ACTION &&
         result.kind != WASM_I64) ||
        (execution->authoritative_phase != SXS_PHASE_ACTION &&
         result.kind != WASM_I32)) {
        return -1;
    }
    *result_out = result.kind == WASM_I64 ? (uint64_t)result.of.i64 :
                                            (uint32_t)result.of.i32;
    return 0;
}
