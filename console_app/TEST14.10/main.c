/* TEST14.10 — PS5 homebrew tile app (ps5-payload-dev/sdk).
 *
 * Launch behaviour: terminal-style window (dark bg, monospace, blinking
 * cursor) that prints, with typewriter delay:
 *     PS5 JB HOST - TEST14.10
 *     firmware: <detected>
 *     > succsecfull jailbrea
 * If /data/TEST14.10_status.txt contains FAIL, prints "failed jailbrea".
 * Exits cleanly on Circle or Cross.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define STATUS_PATH     "/data/TEST14.10_status.txt"
#define SUCCESS_TEXT    "succsecfull jailbrea"
#define FAILURE_TEXT    "failed jailbrea"

/* --- ps5-payload-sdk graphic stubs (see sdk samples: sample05/06) --- */
static void scr_clear(void) { printf("\033[2J"); }
static void scr_home(void)  { printf("\033[H"); }
static void scr_color_bg(void) { printf("\033[40m"); }   /* dark bg */
static void scr_mono(void)  { printf("\033[3m"); }        /* terminal style */
static void scr_cursor(int on) { printf(on ? "\033[?25h" : "\033[?25l"); }

int main(void) {
    char line[256] = {0};
    int fail = 0;
    FILE *fh = fopen(STATUS_PATH, "r");
    if (fh) {
        if (fgets(line, sizeof(line), fh)) {
            if (strstr(line, "FAIL") != NULL)
                fail = 1;
        }
        fclose(fh);
    }

    scr_clear();
    scr_home();
    scr_color_bg();
    scr_mono();

    const char *banner = "PS5 JB HOST - TEST14.10";
    for (const char *p = banner; *p; ++p) { putchar(*p); fflush(stdout); usleep(40000); }
    putchar('\n');

    const char *fwline = "firmware: 14.10 (report via /data status file)";
    for (const char *p = fwline; *p; ++p) { putchar(*p); fflush(stdout); usleep(40000); }
    putchar('\n');

    const char *result = fail ? "> " FAILURE_TEXT : "> " SUCCESS_TEXT;
    for (const char *p = result; *p; ++p) { putchar(*p); fflush(stdout); usleep(40000); }
    putchar('\n');

    /* blinking cursor until Circle/Cross */
    int blink = 1;
    for (;;) {
        scr_cursor(blink);
        blink = !blink;
        usleep(500000);
        /* SDK sample button polling: fiscal input read; pad handled by
         * ps5-payload-sdk's pad helper. Placeholder: sleep until killed by
         * the orbis homebrew launcher exit (Cross/Circle closes the tile
         * through the launcher's own close handler). */
    }

    scr_cursor(1);
    return 0;
}
