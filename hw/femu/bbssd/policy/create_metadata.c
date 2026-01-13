#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define MAX_POLICIES 20
#define PAGE_SIZE 4096

struct policy_metadata {
    uint32_t num_policies;
    struct {
        uint32_t policy_id;
        uint64_t start_lpn_offset;
        uint64_t size_in_pages;
        char policy_name[64];
    } policies[MAX_POLICIES];
};

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <policy.so> <policy_id> <policy_name> <output.bin>\n", argv[0]);
        fprintf(stderr, "Example: %s test-policy.so 1 test_policy metadata.bin\n", argv[0]);
        return 1;
    }

    const char *policy_file = argv[1];
    uint32_t policy_id = atoi(argv[2]);
    const char *policy_name = argv[3];
    const char *output_file = argv[4];

    // Read policy file size
    FILE *fp = fopen(policy_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open %s\n", policy_file);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long policy_size = ftell(fp);
    fclose(fp);

    // Calculate pages (round up)
    uint64_t size_in_pages = (policy_size + PAGE_SIZE - 1) / PAGE_SIZE;

    // Create metadata
    struct policy_metadata meta = {0};
    meta.num_policies = 1;
    meta.policies[0].policy_id = policy_id;
    meta.policies[0].start_lpn_offset = 16;  // POLICY_STORAGE_START_OFFSET
    meta.policies[0].size_in_pages = size_in_pages;
    strncpy(meta.policies[0].policy_name, policy_name, 63);
    meta.policies[0].policy_name[63] = '\0';

    // Write metadata to file
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: Cannot create %s\n", output_file);
        return 1;
    }

    fwrite(&meta, sizeof(meta), 1, out);
    
    // Pad to page size
    long written = ftell(out);
    if (written < PAGE_SIZE) {
        uint8_t zero = 0;
        for (long i = written; i < PAGE_SIZE; i++) {
            fwrite(&zero, 1, 1, out);
        }
    }

    fclose(out);

    printf("Created metadata.bin:\n");
    printf("  Policy ID: %u\n", policy_id);
    printf("  Policy name: %s\n", policy_name);
    printf("  Policy size: %ld bytes (%lu pages)\n", policy_size, size_in_pages);
    printf("  Start LPN offset: 16\n");

    return 0;
}

