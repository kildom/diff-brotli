
#include "brotli/encode.h"

#include <stdio.h>

#define TRACE(...) printf(__VA_ARGS__)

int encodeDiff(const uint8_t *base, size_t baseSize,
                const uint8_t *input, size_t inputSize,
                uint8_t *output, size_t outputSize)
{
    static uint8_t discardBuffer[65536];
    uint32_t lgwin = BROTLI_MIN_WINDOW_BITS;
    do {
        size_t winSize = ((size_t)1 << lgwin) - 16;
        if (winSize >= baseSize + inputSize) {
            break;
        }
        lgwin++;
    } while (lgwin < BROTLI_LARGE_MAX_WINDOW_BITS);
    TRACE("Window size %d\n", ((int)1 << lgwin) - 16);

    BrotliEncoderState *inst = BrotliEncoderCreateInstance(NULL, NULL, NULL);
    if (lgwin > BROTLI_MAX_WINDOW_BITS)
        BrotliEncoderSetParameter(inst, BROTLI_PARAM_LARGE_WINDOW, 1);
    BrotliEncoderSetParameter(inst, BROTLI_PARAM_QUALITY, BROTLI_MAX_QUALITY);
    BrotliEncoderSetParameter(inst, BROTLI_PARAM_LGWIN, lgwin);
    BrotliEncoderSetParameter(inst, BROTLI_PARAM_SIZE_HINT, baseSize + inputSize);
    size_t available_out;
    uint8_t *next_out;
    size_t total_out = 0;
    size_t available_in = baseSize;
    const uint8_t *next_in = base;
    available_out = sizeof(discardBuffer);
    next_out = discardBuffer;
    do {
        BROTLI_BOOL ok = BrotliEncoderCompressStream(inst, BROTLI_OPERATION_FLUSH,
            &available_in, &next_in, &available_out, &next_out, &total_out);
        if (ok == BROTLI_FALSE)
            goto error_exit;
        TRACE("Encoder flushing, produced %d, total %d\n", (int)(sizeof(discardBuffer) - available_out), (int)total_out);
        if (available_out < 16) {
            available_out = sizeof(discardBuffer) - 8;
            next_out = discardBuffer + 8;
        }
    } while (BrotliEncoderHasMoreOutput(inst) != BROTLI_FALSE);
    TRACE("%02X %02X %02X %02X\n", discardBuffer[0], discardBuffer[1], discardBuffer[2], discardBuffer[3]);
    if (discardBuffer[0] == 0x11) {
        output[0] = 0x80 | (discardBuffer[1] & 0x3F);
    } else {
        output[0] = discardBuffer[0] & 0x7F;
    }
    size_t baseOut = total_out;
    available_out = outputSize - 1;
    next_out = output + 1;
    available_in = inputSize;
    next_in = input;
    do {
        BROTLI_BOOL ok = BrotliEncoderCompressStream(inst, BROTLI_OPERATION_FINISH,
            &available_in, &next_in, &available_out, &next_out, &total_out);
        if (ok == BROTLI_FALSE)
            goto error_exit;
        TRACE("Encoding, produced %d, total %d\n", (int)(outputSize - available_out), (int)total_out);
    } while (BrotliEncoderHasMoreOutput(inst) != BROTLI_FALSE);
    TRACE("Produced %d\n", (int)(total_out - baseOut));
    return (int)(total_out - baseOut + 1);
error_exit:
    TRACE("Error\n");
    // TODO: free
    return -1;
}

int readFile(const char * path, uint8_t *buf, int n)
{
    FILE* f = fopen(path, "rb");
    int r = fread(buf, 1, n, f);
    fclose(f);
    TRACE("File size %d, %p\n", r, f);
    return r;
}

int main()
{
    static uint8_t base[1024 * 1024 * 20];
    static uint8_t input[1024 * 1024 * 20];
    static uint8_t output[1024 * 1024 * 20];
    size_t baseSize;
    size_t inputSize;
    size_t outputSize;
    baseSize = readFile("../../base.bin", base, sizeof(base));
    inputSize = readFile("../../input.bin", input, sizeof(input));
    outputSize = encodeDiff(base, baseSize, input, inputSize, output, sizeof(output));
    return 0;
}
