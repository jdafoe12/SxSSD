#include "qemu/osdep.h"
#include "policy-wamr.h"
#include "policy-api.h"
#include "qemu/error-report.h"

#define WASM_ENABLE_INSTRUCTION_METERING 1
#include <wasm_export.h>

#define PE_WAMR_ERROR_BYTES 256U

static int pe_wamr_imports_register(void);

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
                          "policy must declare fixed memory of at most 256 MiB");
                return -1;
            }
            found = true;
        }
        cursor = section_end;
    }
    if (!found) {
        set_error(error_out,
                  "policy must declare fixed memory of at most 256 MiB");
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
        .max_memory_pages = 0, /* Use the fixed maximum declared by the policy. */
    };
    wasm_valkind_t pair_parameter = WASM_I32;
    uint64_t memory_pages;
    uint64_t memory_page_bytes;
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
    memory_pages = vm->memory ?
        wasm_memory_get_cur_page_count(vm->memory) : 0;
    memory_page_bytes = vm->memory ?
        wasm_memory_get_bytes_per_page(vm->memory) : 0;
    if (!vm->memory || memory_pages == 0 || memory_page_bytes == 0 ||
        memory_pages != wasm_memory_get_max_page_count(vm->memory) ||
        memory_page_bytes >
            (uint64_t)PE_WAMR_MAX_LINEAR_MEMORY_PAGES * PE_WAMR_PAGE_BYTES /
                memory_pages ||
        wasm_memory_get_shared(vm->memory)) {
        set_error(error_out,
                  "policy must define fixed memory of at most 256 MiB");
        goto fail;
    }
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
    vm->exec_env = wasm_runtime_create_exec_env(
        vm->instance, PE_WAMR_EXEC_ENV_STACK_BYTES);
    if (!vm->exec_env) {
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
    g_free(vm->artifact);
    g_free(vm);
}


int pe_wamr_vm_execute(struct pe_wamr_vm *vm,
                       struct pe_policy_execution *execution,
                       uint64_t *result_out)
{
    wasm_function_inst_t function;
    wasm_val_t argument = { .kind = WASM_I32 };
    wasm_val_t result = {0};
    uint32_t argument_count;
    bool called;

    if (!vm || !execution || !result_out) {
        return -1;
    }
    if (pe_wamr_ensure_thread_environment(NULL) != 0) {
        return -1;
    }
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

    wasm_runtime_clear_exception(vm->instance);
    wasm_runtime_set_instruction_count_limit(vm->exec_env,
                                              PE_WAMR_INSTRUCTION_LIMIT);
    wasm_runtime_set_user_data(vm->exec_env, execution);
    called = wasm_runtime_call_wasm_a(vm->exec_env, function, 1, &result,
                                      argument_count,
                                      argument_count ? &argument : NULL);
    wasm_runtime_set_user_data(vm->exec_env, NULL);
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

QEMU_BUILD_BUG_ON(sizeof(struct sxs_execution_info) != 32);

static struct pe_policy_execution *execution_from_env(wasm_exec_env_t env)
{
    struct pe_policy_execution *execution;

    if (!env) {
        return NULL;
    }
    execution = wasm_runtime_get_user_data(env);
    if (!execution || !execution->engine || !execution->owner ||
        (execution->authoritative_phase != SXS_PHASE_INIT &&
         execution->authoritative_phase != SXS_PHASE_CONDITION &&
         execution->authoritative_phase != SXS_PHASE_ACTION)) {
        return NULL;
    }
    return execution;
}

static bool fixed_buffer_is_valid(wasm_exec_env_t env, const void *buffer,
                                  uint64_t size)
{
    wasm_module_inst_t instance;

    if (!env || !buffer) {
        return false;
    }
    instance = wasm_runtime_get_module_inst(env);
    return instance && wasm_runtime_validate_native_addr(
                           instance, (void *)(uintptr_t)buffer, size);
}

static int32_t import_execution_get(wasm_exec_env_t env,
                                    struct sxs_execution_info *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);
    struct sxs_execution_info info;

    if (!execution || !fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    info = (struct sxs_execution_info){
        .abi_version = SXS_WASM_ABI_VERSION,
        .phase = execution->authoritative_phase,
        .event_kind = execution->authoritative_event_kind,
        .pair_id = execution->pair_id,
        .policy_id = execution->owner->policy_id,
        .policy_version = execution->owner->policy_version,
        .generation = execution->owner->generation,
        .flags = execution->flags,
    };
    memcpy(output, &info, sizeof(info));
    return 0;
}

static int32_t import_nvme_event_get(wasm_exec_env_t env,
                                     struct sxs_nvme_event *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution ||
        (execution->authoritative_event_kind != SXS_EVENT_NVME_IO &&
         execution->authoritative_event_kind != SXS_EVENT_NVME_ADMIN)) {
        return -SXS_WASM_EPERM;
    }
    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(output, &execution->event_snapshot.nvme, sizeof(*output));
    return 0;
}

static int32_t import_backend_event_get(wasm_exec_env_t env,
                                        struct sxs_backend_event *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution ||
        execution->authoritative_event_kind != SXS_EVENT_BACKEND) {
        return -SXS_WASM_EPERM;
    }
    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(output, &execution->event_snapshot.backend, sizeof(*output));
    return 0;
}

static int32_t import_pswd_event_get(wasm_exec_env_t env,
                                     struct sxs_pswd_event *output)
{
    struct pe_policy_execution *execution = execution_from_env(env);

    if (!execution ||
        execution->authoritative_event_kind != SXS_EVENT_PSWD_TRANSITION) {
        return -SXS_WASM_EPERM;
    }
    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(output, &execution->event_snapshot.pswd, sizeof(*output));
    return 0;
}

static int32_t import_subscribe(wasm_exec_env_t env, uint32_t kind,
                                uint32_t selector, uint32_t pair,
                                uint32_t flags)
{
    return policy_api_subscribe(execution_from_env(env), kind, selector, pair,
                            flags);
}

static int32_t import_backend_status_get(wasm_exec_env_t env, uint64_t index,
                                         int32_t *output)
{
    int32_t native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_backend_status_get(execution_from_env(env), index,
                                       &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_geometry_get(wasm_exec_env_t env,
                                   struct sxs_geometry *output)
{
    struct sxs_geometry native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_geometry_get(execution_from_env(env), &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_layout_get(wasm_exec_env_t env, struct sxs_layout *output)
{
    struct sxs_layout native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_layout_get(execution_from_env(env), &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_eswd_get(wasm_exec_env_t env, uint32_t eswd_id,
                               struct sxs_eswd *output)
{
    struct sxs_eswd native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_eswd_get(execution_from_env(env), eswd_id, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_eswd_from_ppa(wasm_exec_env_t env, uint64_t ppa,
                                    struct sxs_eswd_location *output)
{
    struct sxs_eswd_location native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_eswd_from_ppa(execution_from_env(env), ppa,
                                  &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_dsm_range_get(wasm_exec_env_t env, uint32_t range_index,
                                    struct sxs_dsm_range *output)
{
    struct sxs_dsm_range native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_dsm_range_get(execution_from_env(env), range_index,
                                  &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_ppa_to_eswd(wasm_exec_env_t env, uint64_t ppa,
                                  struct sxs_eswd_location *output)
{
    struct sxs_eswd_location native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_ppa_to_eswd(execution_from_env(env), ppa, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_ppa_validate(wasm_exec_env_t env, uint64_t ppa)
{
    return policy_api_ppa_validate(execution_from_env(env), ppa);
}

static int64_t import_ppa_to_page_index(wasm_exec_env_t env, uint64_t ppa)
{
    return policy_api_ppa_to_page_index(execution_from_env(env), ppa);
}

static int32_t import_page_status_get(wasm_exec_env_t env, uint64_t ppa)
{
    return policy_api_page_status_get(execution_from_env(env), ppa);
}

static int64_t import_eswd_wp_get(wasm_exec_env_t env, uint32_t eswd_id)
{
    return policy_api_eswd_wp_get(execution_from_env(env), eswd_id);
}

static int32_t import_page_invalidate(wasm_exec_env_t env, uint64_t ppa)
{
    return policy_api_page_invalidate(execution_from_env(env), ppa);
}

static int32_t import_eswd_reset(wasm_exec_env_t env, uint32_t eswd_id)
{
    return policy_api_eswd_reset(execution_from_env(env), eswd_id);
}

static int32_t import_eswd_advance_wp(wasm_exec_env_t env, uint32_t eswd_id)
{
    return policy_api_eswd_advance_wp(execution_from_env(env), eswd_id);
}

static uint64_t import_eswd_erase(wasm_exec_env_t env, uint32_t eswd_id)
{
    return policy_api_eswd_erase(execution_from_env(env), eswd_id);
}

static int32_t import_request_read(wasm_exec_env_t env, uint64_t offset,
                                   void *output, uint32_t length)
{
    return policy_api_request_read(execution_from_env(env), offset, output, length);
}

static int32_t import_request_write(wasm_exec_env_t env, uint64_t offset,
                                    const void *input, uint32_t length)
{
    return policy_api_request_write(execution_from_env(env), offset, input, length);
}

static int32_t import_command_read(wasm_exec_env_t env, uint32_t offset,
                                   void *output, uint32_t length)
{
    return policy_api_command_read(execution_from_env(env), offset, output, length);
}

static int32_t import_command_write(wasm_exec_env_t env, uint32_t offset,
                                    const void *input, uint32_t length)
{
    return policy_api_command_write(execution_from_env(env), offset, input, length);
}

static int32_t import_completion_status_set(wasm_exec_env_t env,
                                            uint32_t status)
{
    return policy_api_completion_status_set(execution_from_env(env), status);
}

static int32_t import_completion_result_set(wasm_exec_env_t env,
                                            uint64_t result)
{
    return policy_api_completion_result_set(execution_from_env(env), result);
}

static uint64_t import_time_now_ns(wasm_exec_env_t env)
{
    return policy_api_time_now_ns(execution_from_env(env));
}

static int32_t import_eswd_config_stage(
    wasm_exec_env_t env, const struct sxs_eswd_config *input)
{
    struct sxs_eswd_config native_input;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    return policy_api_eswd_config_stage(execution_from_env(env), &native_input);
}

static int32_t import_namespace_config_stage(
    wasm_exec_env_t env, const struct sxs_namespace_config *input)
{
    struct sxs_namespace_config native_input;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input))) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    return policy_api_namespace_config_stage(execution_from_env(env),
                                         &native_input);
}

static int32_t import_eswd_layout_finalize_stage(wasm_exec_env_t env)
{
    return policy_api_eswd_layout_finalize_stage(execution_from_env(env));
}

static int32_t import_oob_register_stage(wasm_exec_env_t env,
                                         uint32_t object_id, uint32_t bytes)
{
    return policy_api_oob_register_stage(execution_from_env(env), object_id, bytes);
}

static int64_t import_eswd_to_ppa(wasm_exec_env_t env, uint32_t eswd,
                                  uint32_t page)
{
    return policy_api_eswd_to_ppa(execution_from_env(env), eswd, page);
}

static int32_t
import_page_read(wasm_exec_env_t env, const struct sxs_page_read_request *input,
                 void *data, uint32_t data_size, void *oob, uint32_t oob_size,
                 struct sxs_page_result *output)
{
    struct sxs_page_read_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input)) ||
        !fixed_buffer_is_valid(env, output, sizeof(*output)) ||
        (!data && data_size) ||
        (!oob && oob_size) || data_size > SXS_WASM_MAX_PAGE_BYTES) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    result = policy_api_page_read(execution_from_env(env), &native_input, data,
                              data_size, oob, oob_size, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_page_append(
    wasm_exec_env_t env, const struct sxs_page_append_request *input,
    const void *data, uint32_t data_size, const void *oob,
    uint32_t oob_size, struct sxs_page_result *output)
{
    struct sxs_page_append_request native_input;
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, input, sizeof(*input)) ||
        !fixed_buffer_is_valid(env, output, sizeof(*output)) ||
        (!data && data_size) ||
        (!oob && oob_size) || data_size > SXS_WASM_MAX_PAGE_BYTES) {
        return -SXS_WASM_EINVAL;
    }
    memcpy(&native_input, input, sizeof(native_input));
    result = policy_api_page_append(execution_from_env(env), &native_input, data,
                                data_size, oob, oob_size, &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_page_migrate(wasm_exec_env_t env, uint64_t source,
                                   uint32_t destination,
                                   struct sxs_page_result *output)
{
    struct sxs_page_result native_output;
    int32_t result;

    if (!fixed_buffer_is_valid(env, output, sizeof(*output))) {
        return -SXS_WASM_EINVAL;
    }
    result = policy_api_page_migrate(execution_from_env(env), source, destination,
                                 &native_output);
    if (result == 0) {
        memcpy(output, &native_output, sizeof(native_output));
    }
    return result;
}

static int32_t import_namespace_blob_stage(wasm_exec_env_t env, uint32_t kind,
                                           uint32_t destination,
                                           const void *source, uint32_t length)
{
    return policy_api_namespace_blob_stage(execution_from_env(env), kind,
                                       destination, source, length);
}

static int32_t import_crypto_random(wasm_exec_env_t env, void *output,
                                    uint32_t length)
{
    return policy_api_crypto_random(execution_from_env(env), output, length);
}

static int32_t
import_crypto_ed25519_verify(wasm_exec_env_t env, const void *public_key,
                             uint32_t public_length, const void *message,
                             uint32_t message_length, const void *signature,
                             uint32_t signature_length)
{
    return policy_api_crypto_ed25519_verify(execution_from_env(env), public_key,
                                        public_length, message, message_length,
                                        signature, signature_length);
}

static int32_t import_crypto_x25519_public(wasm_exec_env_t env,
                                           const void *private_key,
                                           uint32_t private_length,
                                           void *public_key,
                                           uint32_t public_length)
{
    return policy_api_crypto_x25519_public(execution_from_env(env), private_key,
                                       private_length, public_key,
                                       public_length);
}

static int32_t import_crypto_x25519_shared(wasm_exec_env_t env,
                                           const void *private_key,
                                           uint32_t private_length,
                                           const void *peer_key,
                                           uint32_t peer_length, void *output,
                                           uint32_t output_length)
{
    return policy_api_crypto_x25519_shared(execution_from_env(env), private_key,
                                       private_length, peer_key, peer_length,
                                       output, output_length);
}

static int32_t import_crypto_hmac_sha256(wasm_exec_env_t env, const void *key,
                                         uint32_t key_length,
                                         const void *message,
                                         uint32_t message_length, void *output,
                                         uint32_t output_length)
{
    return policy_api_crypto_hmac_sha256(execution_from_env(env), key, key_length,
                                     message, message_length, output,
                                     output_length);
}

static int32_t import_crypto_sha256(wasm_exec_env_t env, const void *message,
                                    uint32_t message_length, void *output,
                                    uint32_t output_length)
{
    return policy_api_crypto_sha256(execution_from_env(env), message,
                                message_length, output, output_length);
}

static int32_t import_crypto_hkdf_sha256(
    wasm_exec_env_t env, const void *key, uint32_t key_length,
    const void *info, uint32_t info_length, void *output,
    uint32_t output_length)
{
    return policy_api_crypto_hkdf_sha256(
        execution_from_env(env), key, key_length, info, info_length,
        output, output_length);
}

static int32_t import_crypto_aes256_gcm_decrypt(
    wasm_exec_env_t env,
    const void *key, uint32_t key_length,
    const void *nonce, uint32_t nonce_length,
    const void *aad, uint32_t aad_length,
    const void *ciphertext, uint32_t ciphertext_length,
    const void *tag, uint32_t tag_length,
    void *plaintext, uint32_t plaintext_length)
{
    return policy_api_crypto_aes256_gcm_decrypt(
        execution_from_env(env), key, key_length, nonce, nonce_length,
        aad, aad_length, ciphertext, ciphertext_length, tag, tag_length,
        plaintext, plaintext_length);
}

static int32_t
import_sign_key_bootstrap(wasm_exec_env_t env, const uint8_t *owner_nonce,
                          const uint8_t *owner_public,
                          const uint8_t *policy_public, uint8_t *signature)
{
    if (!fixed_buffer_is_valid(env, owner_nonce, 32) ||
        !fixed_buffer_is_valid(env, owner_public, 32) ||
        !fixed_buffer_is_valid(env, policy_public, 32) ||
        !fixed_buffer_is_valid(env, signature, 64)) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_sign_key_bootstrap(execution_from_env(env), owner_nonce,
                                     owner_public, policy_public, signature);
}

static int32_t import_privileged_storage_geometry_get(
    wasm_exec_env_t env, struct sxs_policy_storage_geometry *geometry)
{
    if (!fixed_buffer_is_valid(env, geometry, sizeof(*geometry))) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_storage_geometry_get(
        execution_from_env(env), geometry);
}

static int32_t import_privileged_block_is_claimed(
    wasm_exec_env_t env, const struct sxs_physical_block *block)
{
    if (!fixed_buffer_is_valid(env, block, sizeof(*block))) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_block_is_claimed(
        execution_from_env(env), block);
}

static int32_t import_privileged_block_claim(
    wasm_exec_env_t env, const struct sxs_physical_block *block)
{
    if (!fixed_buffer_is_valid(env, block, sizeof(*block))) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_block_claim(execution_from_env(env), block);
}

static int32_t import_privileged_block_release(
    wasm_exec_env_t env, const struct sxs_physical_block *block)
{
    if (!fixed_buffer_is_valid(env, block, sizeof(*block))) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_block_release(execution_from_env(env), block);
}

static bool valid_block_array(wasm_exec_env_t env,
                              const struct sxs_physical_block *blocks,
                              uint32_t block_count)
{
    return block_count != 0 &&
           block_count <= SXS_PRIVILEGED_MAX_POLICY_BLOCKS &&
           fixed_buffer_is_valid(env, blocks, block_count * sizeof(*blocks));
}

static int32_t import_privileged_storage_read(
    wasm_exec_env_t env, const struct sxs_physical_block *blocks,
    uint32_t block_count, void *data, uint32_t data_length)
{
    if (!valid_block_array(env, blocks, block_count) ||
        !data || data_length == 0) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_storage_read(
        execution_from_env(env), blocks, block_count, data, data_length);
}

static int32_t import_privileged_storage_write(
    wasm_exec_env_t env, const struct sxs_physical_block *blocks,
    uint32_t block_count, const void *data, uint32_t data_length)
{
    if (!valid_block_array(env, blocks, block_count) ||
        !data || data_length == 0) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_storage_write(
        execution_from_env(env), blocks, block_count, data, data_length);
}

static int32_t import_privileged_storage_erase(
    wasm_exec_env_t env, const struct sxs_physical_block *blocks,
    uint32_t block_count)
{
    if (!valid_block_array(env, blocks, block_count)) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_storage_erase(
        execution_from_env(env), blocks, block_count);
}

static int32_t import_privileged_policy_validate_image(
    wasm_exec_env_t env, const void *image, uint32_t image_size)
{
    return policy_api_privileged_policy_validate_image(
        execution_from_env(env), image, image_size);
}

static int32_t import_privileged_policy_activate_stored(
    wasm_exec_env_t env, uint32_t policy_id, uint32_t policy_version,
    uint32_t generation, uint32_t policy_size,
    const struct sxs_physical_block *blocks, uint32_t block_count)
{
    if (!valid_block_array(env, blocks, block_count)) {
        return -SXS_WASM_EINVAL;
    }
    return policy_api_privileged_policy_activate_stored(
        execution_from_env(env), policy_id, policy_version, generation,
        policy_size, blocks, block_count);
}

static int32_t import_privileged_policy_deactivate(
    wasm_exec_env_t env, uint32_t policy_id)
{
    return policy_api_privileged_policy_deactivate(
        execution_from_env(env), policy_id);
}

static int32_t import_privileged_policy_can_remove(
    wasm_exec_env_t env, uint32_t policy_id, uint32_t generation)
{
    return policy_api_privileged_policy_can_remove(
        execution_from_env(env), policy_id, generation);
}

static int32_t import_privileged_policy_remove(
    wasm_exec_env_t env, uint32_t policy_id, uint32_t generation)
{
    return policy_api_privileged_policy_remove(
        execution_from_env(env), policy_id, generation);
}

static int32_t import_privileged_device_attestation_sign(
    wasm_exec_env_t env, const void *message, uint32_t message_length,
    void *signature, uint32_t signature_length)
{
    return policy_api_privileged_device_attestation_sign(
        execution_from_env(env), message, message_length,
        signature, signature_length);
}

/*
 * Keep the WAMR host-call boundary explicit.  policy-imports.def describes the
 * same ABI for policy declarations and linker allowlists, but it does not
 * generate these runtime tables.  ABI changes must update both places.
 */
static NativeSymbol native_symbols[] = {
    {"sxs_execution_get", (void *)import_execution_get, "(*)i", NULL},
    {"sxs_nvme_event_get", (void *)import_nvme_event_get, "(*)i", NULL},
    {"sxs_backend_event_get", (void *)import_backend_event_get, "(*)i", NULL},
    {"sxs_pswd_event_get", (void *)import_pswd_event_get, "(*)i", NULL},
    {"sxs_subscribe", (void *)import_subscribe, "(iiii)i", NULL},
    {"sxs_backend_status_get", (void *)import_backend_status_get,
     "(I*)i", NULL},
    {"sxs_geometry_get", (void *)import_geometry_get, "(*)i", NULL},
    {"sxs_layout_get", (void *)import_layout_get, "(*)i", NULL},
    {"sxs_eswd_get", (void *)import_eswd_get, "(i*)i", NULL},
    {"sxs_eswd_from_ppa", (void *)import_eswd_from_ppa, "(I*)i", NULL},
    {"sxs_ppa_validate", (void *)import_ppa_validate, "(I)i", NULL},
    {"sxs_ppa_to_page_index", (void *)import_ppa_to_page_index, "(I)I", NULL},
    {"sxs_page_status_get", (void *)import_page_status_get, "(I)i", NULL},
    {"sxs_request_read", (void *)import_request_read, "(I*~)i", NULL},
    {"sxs_request_write", (void *)import_request_write, "(I*~)i", NULL},
    {"sxs_command_read", (void *)import_command_read, "(i*~)i", NULL},
    {"sxs_command_write", (void *)import_command_write, "(i*~)i", NULL},
    {"sxs_dsm_range_get", (void *)import_dsm_range_get, "(i*)i", NULL},
    {"sxs_completion_status_set", (void *)import_completion_status_set,
     "(i)i", NULL},
    {"sxs_completion_result_set", (void *)import_completion_result_set,
     "(I)i", NULL},
    {"sxs_time_now_ns", (void *)import_time_now_ns, "()I", NULL},
    {"sxs_eswd_config_stage", (void *)import_eswd_config_stage, "(*)i", NULL},
    {"sxs_namespace_config_stage", (void *)import_namespace_config_stage,
     "(*)i", NULL},
    {"sxs_eswd_layout_finalize_stage",
     (void *)import_eswd_layout_finalize_stage, "()i", NULL},
    {"sxs_oob_register_stage", (void *)import_oob_register_stage,
     "(ii)i", NULL},
    {"sxs_eswd_wp_get", (void *)import_eswd_wp_get, "(i)I", NULL},
    {"sxs_eswd_to_ppa", (void *)import_eswd_to_ppa, "(ii)I", NULL},
    {"sxs_ppa_to_eswd", (void *)import_ppa_to_eswd, "(I*)i", NULL},
    {"sxs_page_read", (void *)import_page_read, "(**~*~*)i", NULL},
    {"sxs_page_append", (void *)import_page_append, "(**~*~*)i", NULL},
    {"sxs_page_invalidate", (void *)import_page_invalidate, "(I)i", NULL},
    {"sxs_eswd_reset", (void *)import_eswd_reset, "(i)i", NULL},
    {"sxs_eswd_advance_wp", (void *)import_eswd_advance_wp, "(i)i", NULL},
    {"sxs_eswd_erase", (void *)import_eswd_erase, "(i)I", NULL},
    {"sxs_page_migrate", (void *)import_page_migrate, "(Ii*)i", NULL},
    {"sxs_namespace_blob_stage", (void *)import_namespace_blob_stage,
     "(ii*~)i", NULL},
    {"sxs_crypto_random", (void *)import_crypto_random, "(*~)i", NULL},
    {"sxs_crypto_ed25519_verify", (void *)import_crypto_ed25519_verify,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_x25519_public", (void *)import_crypto_x25519_public,
     "(*~*~)i", NULL},
    {"sxs_crypto_x25519_shared", (void *)import_crypto_x25519_shared,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_hmac_sha256", (void *)import_crypto_hmac_sha256,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_sha256", (void *)import_crypto_sha256, "(*~*~)i", NULL},
    {"sxs_crypto_hkdf_sha256", (void *)import_crypto_hkdf_sha256,
     "(*~*~*~)i", NULL},
    {"sxs_crypto_aes256_gcm_decrypt",
     (void *)import_crypto_aes256_gcm_decrypt, "(*~*~*~*~*~*~)i", NULL},
    {"sxs_sign_key_bootstrap", (void *)import_sign_key_bootstrap,
     "(****)i", NULL},
};

static NativeSymbol privileged_native_symbols[] = {
    {"sxs_privileged_storage_geometry_get",
     (void *)import_privileged_storage_geometry_get, "(*)i", NULL},
    {"sxs_privileged_block_is_claimed",
     (void *)import_privileged_block_is_claimed, "(*)i", NULL},
    {"sxs_privileged_block_claim", (void *)import_privileged_block_claim,
     "(*)i", NULL},
    {"sxs_privileged_block_release", (void *)import_privileged_block_release,
     "(*)i", NULL},
    {"sxs_privileged_storage_read", (void *)import_privileged_storage_read,
     "(*i*~)i", NULL},
    {"sxs_privileged_storage_write", (void *)import_privileged_storage_write,
     "(*i*~)i", NULL},
    {"sxs_privileged_storage_erase", (void *)import_privileged_storage_erase,
     "(*i)i", NULL},
    {"sxs_privileged_policy_validate_image",
     (void *)import_privileged_policy_validate_image, "(*~)i", NULL},
    {"sxs_privileged_policy_activate_stored",
     (void *)import_privileged_policy_activate_stored, "(iiii*i)i", NULL},
    {"sxs_privileged_policy_deactivate",
     (void *)import_privileged_policy_deactivate, "(i)i", NULL},
    {"sxs_privileged_policy_can_remove",
     (void *)import_privileged_policy_can_remove, "(ii)i", NULL},
    {"sxs_privileged_policy_remove",
     (void *)import_privileged_policy_remove, "(ii)i", NULL},
    {"sxs_privileged_device_attestation_sign",
     (void *)import_privileged_device_attestation_sign, "(*~*~)i", NULL},
};

static int pe_wamr_imports_register(void)
{
    if (!wasm_runtime_register_natives("sxs_v1", native_symbols,
                                       G_N_ELEMENTS(native_symbols)) ||
        !wasm_runtime_register_natives(
            "sxs_privileged_v1", privileged_native_symbols,
            G_N_ELEMENTS(privileged_native_symbols))) {
        return -1;
    }
    return 0;
}
