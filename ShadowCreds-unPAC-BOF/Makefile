# Shadow Credentials BOF - Makefile
#
# Build for x64 BOF (Cobalt Strike/Havoc)
# Requires: mingw-w64 (x86_64-w64-mingw32-gcc)

CC_x64 = x86_64-w64-mingw32-gcc
CC_x86 = i686-w64-mingw32-gcc

CFLAGS = -Os -s -fno-asynchronous-unwind-tables -fno-ident -fpack-struct=8 -falign-functions=1 -w -mno-stack-arg-probe -fno-stack-protector
BOF_CFLAGS = -c -DBOF
STANDALONE_CFLAGS = -DSTANDALONE

SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

SRC = $(SRC_DIR)/shadowcreds.c

TARGET_x64 = $(BUILD_DIR)/shadowcreds.x64.o
TARGET_x86 = $(BUILD_DIR)/shadowcreds.x86.o
TARGET_STANDALONE = $(BUILD_DIR)/shadowcreds.exe

LIBS_STANDALONE = -lws2_32 -lcrypt32 -ladvapi32 -lole32 -loleaut32 -lnetapi32 -lwldap32

.PHONY: all bof standalone clean x64 x86

all: bof standalone

bof: x64 x86
	@echo "[+] BOF build complete"

x64: $(BUILD_DIR)
	@echo "[*] Building x64 BOF..."
	$(CC_x64) $(CFLAGS) $(BOF_CFLAGS) -I$(INCLUDE_DIR) -o $(TARGET_x64) $(SRC)
	@echo "[+] Built: $(TARGET_x64)"

x86: $(BUILD_DIR)
	@echo "[*] Building x86 BOF..."
	$(CC_x86) $(CFLAGS) $(BOF_CFLAGS) -I$(INCLUDE_DIR) -o $(TARGET_x86) $(SRC)
	@echo "[+] Built: $(TARGET_x86)"

standalone: $(BUILD_DIR)
	@echo "[*] Building standalone EXE..."
	$(CC_x64) $(CFLAGS) $(STANDALONE_CFLAGS) -I$(INCLUDE_DIR) -o $(TARGET_STANDALONE) $(SRC) $(LIBS_STANDALONE)
	@echo "[+] Built: $(TARGET_STANDALONE)"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)
	@echo "[+] Cleaned build directory"

# Visual Studio build (for Windows)
vs-standalone:
	@echo "[*] Building with Visual Studio..."
	cl.exe /O2 /DSTANDALONE /I$(INCLUDE_DIR) $(SRC) /Fe:$(BUILD_DIR)/shadowcreds.exe \
		ws2_32.lib crypt32.lib advapi32.lib ole32.lib oleaut32.lib netapi32.lib wldap32.lib
	@echo "[+] Built with Visual Studio"

help:
	@echo "Shadow Credentials BOF - Build Targets"
	@echo ""
	@echo "  make all        - Build BOF and standalone"
	@echo "  make bof        - Build x64 and x86 BOF"
	@echo "  make x64        - Build x64 BOF only"
	@echo "  make x86        - Build x86 BOF only"
	@echo "  make standalone - Build standalone EXE"
	@echo "  make clean      - Clean build directory"
	@echo ""
	@echo "Usage (after build):"
	@echo "  BOF:        inline-execute shadowcreds.x64.o <target> <domain> [kdc]"
	@echo "  Standalone: shadowcreds.exe <target> <domain> [kdc]"
