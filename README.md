# Wansview A1 — Full Reverse Engineering Analysis

**Camera model**: Wansview A1 (also branded as Ajcloud T-CP2011-W32A)  
**Firmware file**: `wansview_a1-t23zn-atbm6461-stock.bin` (16 MB)  
**SoC**: Ingenic T23N (xburst1, MIPS32 R1)  
**Sensor**: OmniVision OS02G10 (2MP)  
**WiFi**: Altobeam atbm6461 (SDIO)  

This repository documents the complete reverse engineering of the stock
firmware, covering the proprietary **jzlzma** compression format, kernel
extraction, partition layout, hardware configuration, and notes for porting
to [Thingino](https://thingino.com) open-source firmware.

---

## Table of Contents

1. [Firmware Overview](#1-firmware-overview)
2. [Binwalk Analysis](#2-binwalk-analysis)
3. [The jzlzma Format](#3-the-jzlzma-format)
   - [Background](#31-background)
   - [Bit-stream Encoding](#32-bit-stream-encoding)
   - [Wire Format of jz_lzma_out.bin](#33-wire-format-of-jz_lzma_outbin)
   - [mark_rootfs_lzma Wrapper (.jzlzma)](#34-mark_rootfs_lzma-wrapper-jzlzma)
   - [Comparison with Standard LZMA](#35-comparison-with-standard-lzma)
   - [Decoding Algorithm](#36-decoding-algorithm)
   - [Decoder Implementation](#37-decoder-implementation)
4. [Kernel Extraction](#4-kernel-extraction)
   - [Archon Kernel](#41-archon-kernel)
   - [Immortal Kernel](#42-immortal-kernel)
   - [Kernel Version Strings](#43-kernel-version-strings)
5. [Initramfs Analysis](#5-initramfs-analysis)
   - [Immortal Initramfs Contents](#51-immortal-initramfs-contents)
   - [Boot Flow](#52-boot-flow)
   - [Key Executables](#53-key-executables)
6. [Squashfs Filesystems](#6-squashfs-filesystems)
   - [Base System (A98000)](#61-base-system-a98000)
   - [Application Partition (B40000)](#62-application-partition-b40000)
7. [JFFS2 Data Partition](#7-jffs2-data-partition)
8. [Audio System](#8-audio-system)
    - [Kernel Configuration](#81-kernel-configuration)
    - [OSS3 Audio Driver](#82-oss3-audio-driver)
    - [Internal Codec](#83-internal-codec)
    - [IMP Audio API (Userland)](#84-imp-audio-api-userland)
    - [Audio Processing (WebRTC)](#85-audio-processing-webrtc)
    - [Firmware Audio Binaries](#86-firmware-audio-binaries)
    - [Voice Prompts](#87-voice-prompts)
9. [Hardware Configuration](#9-hardware-configuration)
    - [SoC](#91-soc)
    - [Sensor](#92-sensor)
    - [WiFi](#93-wifi)
    - [MCU Co-processor](#94-mcu-co-processor)
    - [Flash & Storage](#95-flash--storage)
    - [GPIOs & LEDs](#96-gpios--leds)
    - [Peripherals](#97-peripherals)
10. [MTD Partition Layout](#10-mtd-partition-layout)
11. [SDK Tooling](#11-sdk-tooling)
    - [mark_rootfs/lzma Tools](#111-mark_rootfslzma-tools)
    - [Tag Generator](#112-tag-generator)
    - [librtos / MCU Communication](#113-librtos--mcu-communication)
12. [Thingino Porting Notes](#12-thingino-porting-notes)
    - [Board Definition](#121-board-definition)
    - [Kernel Configuration](#122-kernel-configuration)
    - [Sensor Integration](#123-sensor-integration)
    - [WiFi Integration](#124-wifi-integration)
    - [Audio Integration](#125-audio-integration)
    - [Tag Partition](#126-tag-partition)
    - [Partition Layout](#127-partition-layout)
13. [Tools](#13-tools)
14. [References](#14-references)

---

## 1. Firmware Overview

The firmware image `wansview_a1-t23zn-atbm6461-stock.bin` is a full 16 MB SPI
NOR flash dump for the Wansview A1 IP camera. It was extracted from a stock
device via the standard backup procedure.

### Header

```
Offset  Bytes  Value              Meaning
------  -----  -----------------  -------
0x0000   6     06 05 04 03 02 55  Magic / version marker
0x0006   2     55 aa              Additional marker
0x0008   4     aa 7f 00 00       Firmware version (LE, 0x00007faa)
0x000C   4     80 77 00 00       Unknown (LE, 0x00007780)
```

The remainder of the image is a concatenation of raw MTD partitions.

---

## 2. Binwalk Analysis

Running `binwalk` on the firmware reveals:

```
DECIMAL       HEXADECIMAL     DESCRIPTION
-----------------------------------------------------------------------
65536         0x10000         uImage header, ... Linux-3.10.14-Archon
98304         0x18000         LZ4 compressed data
622592        0x98000         uImage header, ... Linux-3.10.14-Immortal
8519680       0x820000        SquashFS filesystem, little endian...
11010048      0xA80000        SquashFS filesystem, little endian...
16000000      0xF40000        JFFS2 filesystem, little endian...
```

| Offset       | Size      | Content |
|--------------|-----------|---------|
| `0x10000`    | ~0x88000  | **Archon kernel** (jzlzma-compressed) |
| `0x98000`    | ~0x788000 | **Immortal kernel** (standard LZMA) |
| `0xA80000`   | ~0x260000 | **Squashfs A98000** — base system (curl, libs) |
| `0xB40000`   | ~0x400000 | **Squashfs B40000** — application partition |
| `0xF40000`   | ~0xC0000  | **JFFS2** — data partition (configs, OSD) |

> **Note**: Binwalk identifies the first kernel as "LZ4" but it is actually
> **jzlzma**, Ingenic's proprietary compression. The bootloader reuses LZ4's
> compression identifier for jzlzma.

### Full Structure Diagram

```
0x000000 ┌─────────────────────────────────────┐
         │  Header (0x10)                     │
0x000010 ├─────────────────────────────────────┤
         │  Bootloader / padding               │
0x010000 ├─────────────────────────────────────┤
         │  Archon Kernel (jzlzma)             │
0x098000 ├─────────────────────────────────────┤
         │  Immortal Kernel (standard LZMA)    │
0x0A8000 ├─────────────────────────────────────┤
         │  Squashfs — base system (curl etc.) │
0x0B4000 ├─────────────────────────────────────┤
         │  Squashfs — application partition   │
         │  (ajcloud, audio, upgrade, MCU FW)  │
0x0F4000 ├─────────────────────────────────────┤
         │  JFFS2 — data/config partition      │
0x100000 └─────────────────────────────────────┘
```

---

## 3. The jzlzma Format

### 3.1 Background

Ingenic Semiconductor's T23 (and related T10–T41) SoCs include a hardware
decompression block that handles a format the vendor calls **jzlzma**.
Despite the name, the format is **not** LZMA: it drops LZMA's probabilistic
range coding and encodes decisions as plain bits. This makes hardware
implementation trivial at the cost of significantly worse compression ratios.

The vendor ships a patched copy of **LZMA SDK 4.32** whose `lzma` CLI tool
produces *two* compressed files in one pass:

1. A standard `.lzma` file for host-side tool compatibility.
2. A raw `jz_lzma_out.bin` file in the custom format for the bootloader.

A companion tool `mark_rootfs_lzma` wraps `jz_lzma_out.bin` with an 8-byte
header to produce the `.jzlzma` files found on firmware partitions.

The algorithm was independently documented by **Wladimir Palant** in
December 2025 ([source](https://palant.info/2025/12/15/unpacking-vstarcam-firmware-for-fun-and-profit/)).
The decompression logic in `tools/jzlzma_decompress.py` is derived from that
work.

### 3.2 Bit-stream Encoding

Bits are stored **LSB first** within each byte. When reading multi-bit
fields, bits are consumed from LSB to MSB of the current byte, then
advancing to the next byte's LSB.

Some integer fields are stored in **reversed bit order** (the low bits of
distance values are bit-reversed within their field width).

### 3.3 Wire Format of jz_lzma_out.bin

```
Offset  Size  Field
------  ----  ------------------------------------
     0     4  Dictionary size (LE, e.g. 0x00010000 = 64 KiB)
     4     4  Uncompressed data size (LE)
     8     N  Compressed bit-stream
```

The first 8 bytes are metadata only — the compressed stream starts at
byte 8.

### 3.4 mark_rootfs_lzma Wrapper (.jzlzma)

The hardware bootloader expects this outer wrapper:

```
Offset  Size  Field
------  ----  ------------------------------------
     0     4  Size of inner data (LE)
     4     4  Magic 0x27051956 (LE)
     8     4  Dictionary size (from inner file)
    12     4  Uncompressed size (from inner file)
    16     N  Compressed bit-stream
```

The inner data is `jz_lzma_out.bin` verbatim, so the compressed stream
sits at offset 16.

### 3.5 Comparison with Standard LZMA

| Feature             | LZMA Alone                | jzlzma                          |
|---------------------|---------------------------|---------------------------------|
| Header              | 1 prop + 4 dict + 8 size | 4 dict + 4 size (no prop byte)  |
| Bit order           | MSB first                 | LSB first                       |
| Range coding        | Adaptive probability model| None (plain bits)               |
| Distance encoding   | Standard                  | Low bits are bit-reversed       |
| Match handling      | LZMA state machine        | Simplified (no state)           |

### 3.6 Decoding Algorithm

The decompressor reads a bit-stream and produces a byte stream by
interleaving **literal bytes** with **LZ77-style match references**.

**Top-level loop:**

```
while True:
    bit = read_bit()
    if bit == 0:                              # LITERAL
        byte = read_bits(8)
        emit(byte)
    else:                                     # MATCH or REP
        size = 0
        bit = read_bit()
        if bit == 0:                          # MATCH (10)
            size = decode_length()
            dist = decode_distance()
            update reps
        else:                                 # REP codes (11...)
            bit = read_bit()
            if bit == 0:                      # 110x
                bit = read_bit()
                if bit == 0: size = 1         # SHORTREP (1100)
                else: pass                    # LONGREP0 (1101)
            elif bit == 0:                    # LONGREP1 (1110)
                rotate reps[1]
            elif bit == 0:                    # LONGREP2 (11110)
                rotate reps[2]
            else:                             # LONGREP3 (11111)
                rotate reps[3]
        if size == 0:
            size = decode_length()
        copy bytes from curPos - reps[0] - 1
```

**Length decoding:**

| Prefix | Range    | Formula            |
|--------|----------|--------------------|
| `0`    | 2–9      | `2 + read_bits(3)` |
| `10`   | 10–17    | `10 + read_bits(3)`|
| `11`   | 18–273   | `18 + read_bits(8)`|

**Distance decoding:**

Six-bit `posSlot` determines the distance. Slots 0–3 are direct distances.
Larger slots use `numDirectBits` derived from the slot number, with
bit-reversal applied to the low portion of the distance value.

### 3.7 Decoder Implementation

A reference Python implementation is included at:

```
tools/jzlzma_decompress.py
```

Usage:

```bash
python3 tools/jzlzma_decompress.py input.jzlzma output.bin
```

The tool auto-detects all three format variants:
- Raw `jz_lzma_out.bin`
- `mark_rootfs_lzma`-wrapped `.jzlzma`
- Standard LZMA Alone streams

Also available at: https://github.com/CapnRon/un-jzlzma

---

## 4. Kernel Extraction

### 4.1 Archon Kernel

The primary (first) kernel is **jzlzma-compressed** with unknown uncompressed
size, stored in the standard `jz_lzma_out.bin` format (no outer wrapper).

| Property       | Value                           |
|----------------|---------------------------------|
| **File**       | `98000/Linux-3.10.14-Archon.bin`|
| **Compressed** | 2,106,723 bytes (2.0 MB)        |
| **Decompressed**| 4,528,756 bytes (4.3 MB)        |
| **Method**     | jzlzma (dict=0x10000)           |
| **Decompressed offset** | `archon[8:]` (skip dict + size header) |

Decompression:

```bash
python3 tools/jzlzma_decompress.py \
  98000/Linux-3.10.14-Archon.bin \
  archon-kernel.bin
```

### 4.2 Immortal Kernel

The secondary (backup) kernel is **standard LZMA Alone** (auto-detected by
the `0x5D` properties byte).

| Property       | Value                             |
|----------------|-----------------------------------|
| **File**       | `818000/Linux-3.10.14-Immortal.bin`|
| **Compressed** | 1,944,197 bytes (1.9 MB)          |
| **Decompressed**| 6,286,652 bytes (6.0 MB)          |
| **Method**     | Standard LZMA (prop=0x5D, dict=32MB)|

Decompression (handled automatically by the same tool):

```bash
python3 tools/jzlzma_decompress.py \
  818000/Linux-3.10.14-Immortal.bin \
  immortal-kernel.bin
```

### 4.3 Kernel Version Strings

Both kernels share the same base but were built at different times:

|                 | Archon                                    | Immortal                                    |
|-----------------|-------------------------------------------|---------------------------------------------|
| **Version**     | `3.10.14-Archon`                          | `3.10.14-Immortal`                          |
| **Compiler**    | GCC 5.4.0 (Ingenic 3.3.0, xburst1 fp32)  | same                                        |
| **libc**        | uClibc 0.9.33.2                           | same                                        |
| **Builder**     | `chenjianlin@alf`                         | same                                        |
| **Build date**  | Thu Nov 13 16:00:13 CST 2025              | Mon May 19 18:12:15 CST 2025                |
| **Build path**  | (not embedded)                            | `/data/chenjianlin/firmware/lp_T23_OS02G10_6461_S/` |

The build path `lp_T23_OS02G10_6461_S` encodes the full board configuration:

```
lp                   = product prefix (low-power?)
T23                  = SoC
OS02G10             = sensor
6461                = WiFi chip (atbm6461)
S                   = SDIO interface
```

Both kernels start with 1024 bytes of zeros (MIPS exception vector page),
followed by MIPS kernel code at offset `0x400`.

---

## 5. Initramfs Analysis

Only the **Immortal** kernel contains a meaningful initramfs (CPIO archive
with 232 files / 49 unique paths). The Archon initramfs is a stub (3 files).

### 5.1 Immortal Initramfs Contents

```
├── bin/
│   └── busybox                    # v1.22.1 (2023-10-12)
├── dev/                           # device nodes (pts, shm)
├── etc/
│   ├── banner                     # "Hello Zeratul!"
│   ├── device_info                # hw=V1.0, bl=V1.0, fw=07.31030.01.12
│   ├── fstab
│   ├── group
│   ├── hostname                   # "Recovery"
│   ├── hosts
│   ├── init.d/rcS                 # main startup script
│   ├── inittab
│   ├── mdev.conf
│   ├── passwd / shadow / group
│   ├── profile
│   ├── resolv.conf
│   ├── rsa_pub.txt
│   ├── sprite.txt
│   └── udhcpd.conf
├── lib/
│   ├── ld-uClibc-0.9.33.2.so
│   ├── libdl-0.9.33.2.so
│   ├── libgcc_s.so
│   ├── libm-0.9.33.2.so
│   ├── libpthread-0.9.33.2.so
│   ├── libresolv-0.9.33.2.so
│   ├── librt-0.9.33.2.so
│   ├── libthread_db-0.9.33.2.so
│   ├── libuClibc-0.9.33.2.so
│   ├── libutil-0.9.33.2.so
│   └── modules/
│       └── atbm6461_wifi_sdio.ko  # WiFi driver module
├── usr/
│   ├── bin/
│   │   ├── ap_update.sh
│   │   ├── apmode                 # AP mode daemon (Broadcom wl-compatible)
│   │   ├── app_init.sh            # application init script
│   │   ├── fsck_mount_mmc.sh
│   │   ├── get_fwinfo             # reads firmware version from tag partition
│   │   ├── insmod_wifi_2          # WiFi module loader
│   │   ├── led_blink.sh
│   │   ├── mcu_test               # MCU diagnostic tool
│   │   ├── net_upgrade.sh
│   │   ├── recovery
│   │   ├── sd_upgrade
│   │   ├── tag_generator          # writes/reads tag partition
│   │   ├── tf_update.sh
│   │   ├── umount_mmc.sh
│   │   ├── upgrade                # firmware upgrade tool
│   │   ├── wifi_decoder
│   │   ├── z7682_daemon           # MCU communication daemon
│   │   └── z7682_disable_wdt      # watchdog disable
│   ├── lib/
│   │   └── librtos.so             # RTOS communication library
│   └── share/udhcpc/
│       └── default.script
└── var/run/
```

### 5.2 Boot Flow

1. Kernel boots, loads initramfs.
2. BusyBox init reads `/etc/inittab`.
3. `/etc/init.d/rcS` runs:
   - Mounts `proc`, `sysfs`, `tmpfs`, `devpts`.
   - Configures `mdev` for hotplug.
   - Sets up loopback networking.
   - Starts `telnetd` for serial/network access.
   - Forks `/usr/bin/app_init.sh &`.
4. `app_init.sh`:
   - Exports GPIO 50 (RED LED), turns it on.
   - Loads WiFi module: `insmod /lib/modules/atbm6461_wifi_sdio.ko`.
   - Disables MCU watchdog: `z7682_disable_wdt`.
   - Mounts `/dev/mtdblock5` as squashfs to `/common`.
   - Checks SD card for `upgrade.conf` → runs `sd_upgrade` if present.
   - Falls back to network upgrade check if no SD card.

### 5.3 Key Executables

| Binary          | Purpose                                              |
|-----------------|------------------------------------------------------|
| `tag_generator` | Creates/rewrites the tag partition (mtdblock1) with   |
|                 | cmdline, env, bootinfo, fwinfo, sensor init,          |
|                 | ae_table, riscv_fw, sensor mode settings               |
| `get_fwinfo`    | Reads firmware version from the tag partition          |
| `z7682_daemon`  | Communicates with the z7682 MCU co-processor           |
| `z7682_disable_wdt`| Disables the MCU watchdog                           |
| `apmode`        | Wi-Fi AP mode setup with FTP-based firmware update    |
| `upgrade`       | Main firmware upgrade handler                          |
| `sd_upgrade`    | SD card-based firmware upgrade                         |
| `mcu_test`      | MCU diagnostic utility                                 |
| `wifi_decoder`  | WiFi-related tool (possibly for debugging)            |

---

## 6. Squashfs Filesystems

### 6.1 Base System (A98000)

A minimal partition containing only `curl` and its dependencies (mbedTLS,
nghttp2) for network upgrade functionality:

```
bin/
  curl
lib/
  libcurl.so.4.8.0
  libmbedcrypto.so.2.28.5
  libmbedtls.so.2.28.5
  libmbedx509.so.2.28.5
  libnghttp2.so.14.25.0
```

### 6.2 Application Partition (B40000)

The main application filesystem containing the camera application and
supporting binaries:

```
bin/
  ajcloud            (803 KB) - main camera application
  audio_play         (42 KB)  - audio playback
  iperf3             (156 KB) - network benchmark
  mcu_test           (12 KB)  - MCU diagnostic
  sd_upgrade         (215 KB) - SD card upgrade
  shutdown           (26 KB)  - system shutdown
  tag_env_info       (13 KB)  - tag environment reader
  tag_upgrade        (16 KB)  - tag partition updater
  upgrade            (219 KB) - firmware flasher

lib/modules/
  dwc2.ko            - USB gadget driver
  usbcore.ko         - USB core
  usb-common.ko
  usbnet.ko
  asix.ko            - USB Ethernet (ASIX)
  eeprom_at24.ko     - EEPROM driver

mcu_fw/
  mcu_fw.bin         (680 KB) - z7682 MCU firmware v1.0.6u7
  mcu_fw.ini
```

The `ajcloud` binary is the main application. Key device paths it uses:
- `/dev/mmcblk0` / `/dev/mmcblk0p1` — SD card
- `/dev/motor_ioctl` — motor control (PTZ)

---

## 7. JFFS2 Data Partition

The writable data partition at `0xF40000` stores persistent configuration:

```
osd/
  logo_osd_84x48_1_wansv_360p.rgba.bz2
  logo_osd_300x98_0_wansv_1296p.rgba.bz2

profiles/
  Wifi_Reconnect_Profiles.ini     # [WIFI] CONNECT_TIMES=0
  ZRT_Profile_Wifi_Debug.ini      # [WIFI] KEEPALIVE=60, ARP=60
  ZRT_Profile_Wifi_Debug_bak.ini  # backup of above
  IBT_Profiles.ini                # P2P/audio/video/power config
  alarm.info                      # binary alarm state
```

**Default credentials** from `IBT_Profiles.ini`:
- P2P User: `admin`
- P2P Pass: `888888`
- UID: `xxxx`

---

## 8. Audio System

The Wansview A1 has a full bidirectional audio subsystem with microphone
capture and speaker playback support. It uses Ingenic's custom **OSS3**
(Open Sound System v3) framework with the internal T23 codec, plus a
WebRTC-based processing stack for echo cancellation, noise suppression,
and auto gain control.

Audio encoding/decoding supports G.711 A-law, G.711 µ-law, and G.726.
The device ships with 165 AAC voice prompt files in 12 languages.

### 8.1 Kernel Configuration

| Option                        | Value  | Notes                         |
|-------------------------------|--------|-------------------------------|
| `CONFIG_SOUND`                | `y`    | Sound subsystem enabled       |
| `CONFIG_SOUND_OSS_CORE`       | `y`    | OSS core framework            |
| `CONFIG_SOUND_PRIME`          | `y`    | Ingenic OSS3 driver           |
| `CONFIG_SOUND_OSS_XBURST`     | `y`    | XBurst OSS extensions         |
| `CONFIG_SOUND_JZ_I2S_V12`     | `y`    | I2S v12 interface             |
| `CONFIG_COMPILE_JZSOUND_INTO_KO` | `y` | Built into kernel, not a module |
| `CONFIG_SND`                  | `n`    | **ALSA is disabled**          |
| `CONFIG_SOUND_JZ_PCM_V12`     | `n`    | No PCM interface              |
| `CONFIG_SOUND_JZ_SPDIF_V12`   | `n`    | No SPDIF                      |

The recovery (Immortal) kernel has **no audio** — `CONFIG_SOUND` is not set.

### 8.2 OSS3 Audio Driver

Source location in the SDK kernel tree:

```
sound/oss3/
├── audio_dsp.c                   # /dev/dsp interface
├── audio_debug.c                 # Debug /proc interface
├── boards/
│   └── t23_platform.c            # Platform device registration
├── host/
│   └── T23/
│       ├── audio_aic.c           # Core AIC driver (I2S, DMA, AEC pipes)
│       └── audio_aic.h           # AIC register definitions
├── inner_codecs/
│   └── T23/
│       ├── codec.c               # Internal T23 codec driver
│       └── codec.h               # Codec register map
└── include/
    ├── audio_common.h
    ├── audio_control.h
    ├── audio_debug.h
    └── audio_dsp.h
```

**`audio_aic.c`** (`sound/oss3/host/T23/audio_aic.c`):

- Version: `"V30-20230210a"`
- Module parameters: `internal_codec`, `excodec_name`, `excodec_addr`,
  `i2c_bus`, `samplerate`, `mic_mono_channel`
- Three audio pipes: **Mic** (capture), **SPK** (playback), **AEC**
  (echo cancellation reference), each with dedicated DMA
- I2S protocol: standard I2S, left-justified, 8/16/20/24-bit samples
- Sample rates: 8 KHz, 16 KHz (`DEFAULT_RECORD_CLK = 8000*256`)
- Volume range: -30 to 120 (0.5 dB steps)
- Gain range: 0-31
- Features: ALC (Auto Level Control), mute, HPF (High Pass Filter),
  external codec support via I2C

**`t23_platform.c`** (`sound/oss3/boards/t23_platform.c`) registers:

| Device             | Name              | Base / IRQ                 |
|--------------------|-------------------|----------------------------|
| Internal codec     | `"jz-inner-codec"`| `CODEC_IOBASE`             |
| Audio interface    | `"jz-aic"`        | `AIC0_IOBASE`, `IRQ_AIC0` |
| DSP endpoint       | `"jz-dsp"`        | `/dev/dsp`                 |

### 8.3 Internal Codec

**`codec.c`** (`sound/oss3/inner_codecs/T23/codec.c`):

- Base address: `0x10021000`
- Speaker control: `GPIO_PB(31)` with configurable active level
- Supported sample rates: 8K, 12K, 16K, 24K, 32K, 44.1K, 48K, 96K
- ADC data lengths: 16-bit, 20-bit, 24-bit, 32-bit

Board-level sound routing is defined in
`arch/mips/xburst/soc-t23/chip-t23/isvp/common/sound.c`:

```c
static struct codec_data codec_data = {
    .replay_def_route  = DACRL_TO_ALL,       // speaker + headphone
    .record_def_route  = MIC1_AN1,            // built-in microphone
    .gpio_hp_mute      = GPIO_HP_MUTE,
    .gpio_speaker_en   = GPIO_SPEAKER_EN,
    .gpio_hp_detect    = GPIO_HP_DETECT,
    .gpio_mic_detect   = GPIO_MIC_DETECT,
    .gpio_mic_select   = GPIO_MIC_SELECT,
    .gpio_handset_en   = GPIO_HANDSET_EN,
};
```

Sound routing options (from `arch/mips/xburst/soc-t23/include/mach/jzsnd.h`):

| Direction | Routes |
|-----------|--------|
| Record    | `MIC1_AN1`, `MIC1_SIN_AN2`, `MIC2_SIN_AN3`, `LINEIN1`, `LINEIN2`, call record |
| Playback  | `DACRL_TO_LO`, `DACRL_TO_HPRL`, `DACRL_TO_ALL` |
| Loopback  | `LINEIN2` bypass, `MIC` bypass |

### 8.4 IMP Audio API (Userland)

The userland audio API is provided by the Ingenic Multimedia Platform (IMP)
header at `imp-t23/include_en/imp/imp_audio.h`:

| API Prefix  | Function               | Details                                    |
|-------------|------------------------|--------------------------------------------|
| `IMP_AI_*`  | Audio Input (capture)  | Device 0 = digital MIC, Device 1 = analog MIC |
| `IMP_AO_*`  | Audio Output (playback)| Device 0 = default SPK                     |
| `IMP_AENC_*`| Audio Encoding         | `PT_G711A`, `PT_G711U`, `PT_G726`          |
| `IMP_ADEC_*`| Audio Decoding         | `PT_G711A`, `PT_G711U`, `PT_G726`          |
| `IMP_AI_EnableAec` | Echo Cancellation | WebRTC-based, config via `/etc/webrtc_profile.ini` |
| `IMP_AI_EnableNs`  | Noise Suppression | 4 levels: Low/Moderate/High/VeryHigh       |
| `IMP_AI_EnableAgc` | Auto Gain Control | Configurable target level and gain         |
| `IMP_AI_EnableHpf` | High Pass Filter  | Configurable cutoff frequency              |
| `IMP_AI_EnableHs`  | Howling Suppression |                                       |
| `IMP_AI_SetVol`    | Set Volume       | Range -30 to 120 (0.5 dB steps)            |
| `IMP_AI_SetGain`   | Set Gain         | Range 0-31 (-18 dB to +28.5 dB)            |

Supported sample rates: 8K, 12K, 16K, 24K, 32K, 44.1K, 48K, 96K
Bit width: 16-bit
Sound modes: Mono, Stereo

### 8.5 Audio Processing (WebRTC)

The library `libaudioProcess.so` (`imp-t23/lib/uclibc/libaudioProcess.so`)
provides WebRTC-based real-time audio processing:

```
libaudioProcess.so exports:
  audio_process_aec_create / process / free   # Acoustic Echo Cancellation
  audio_process_ns_create / set_config / process / free  # Noise Suppression
  audio_process_agc_create / set_config / process / free  # Auto Gain Control
  audio_process_hpf_create / process / free   # High Pass Filter
```

References WebRTC internals: `WebRtcAgc_*`, `WebRtcNs_*`,
`WebRtcNs_Analyze`, `WebRtcNs_Process`

### 8.6 Firmware Audio Binaries

**`ajcloud`** (`bin/ajcloud`, 803 KB) — main application with audio control:

- Protobuf commands: `AudioConfigRequest`, `AudioConfigResponse`,
  `SoundPlayRequest`, `SoundPlayResponse`, `SoundMonitorConfigRequest`
- Config: `mic_enable`, `mic_volume`, `speaker_volume`
- Sounds: `SirenSound`, `SirenSoundsConfigRequest`, `RingSoundConfigRequest`,
  `AlarmSoundConfigRequest`
- Callbacks: `audio_config_request_cb`, `audio_config_response_cb`,
  `sound_play_request_cb`, `sound_play_response_cb`

**`audio_play`** (`bin/audio_play`, 42 KB) — standalone AAC playback tool:

- Uses OSS `/dev/dsp` directly
- Functions: `IMP_AO_Enable`, `IMP_AO_SetVol`,
  `SNDCTL_DSP_SETFMT`, `SNDCTL_EXT_ENABLE_STREAM`
- Loads `libaudioProcess.so` dynamically
- Supports AAC playback with volume control

**Audio config** from JFFS2 (`profiles/IBT_Profiles.ini`):
```ini
[Audio]
playVol=70
```

### 8.7 Voice Prompts

The application partition contains **165 AAC sound files** across 12 languages
in `snd/`:

| Language | Code | Files |
|----------|------|-------|
| Chinese  | `zh`  | 17 (including extras: power-on, power-off, siren, ring-1, eagle, du, dudu) |
| English  | `en`  | 8     |
| German   | `de`  | 8     |
| Spanish  | `es`  | 8     |
| French   | `fr`  | 8     |
| Italian  | `it`  | 8     |
| Japanese | `ja`  | 8     |
| Korean   | `ko`  | 8     |
| Polish   | `pl`  | 8     |
| Portuguese| `pt` | 8     |
| Russian  | `ru`  | 8     |

Standard prompt set (present in all languages):
`allok`, `pairingfailed`, `qrok`, `registering`, `resetok`,
`wificonnected`, `wificonnecting`, `wifierror`

Chinese-only additions: `power-off`, `power-on`, `siren`, `ring-1`,
`eagle`, `du`, `dudu`

---

## 9. Hardware Configuration

### 9.1 SoC

| Property       | Detail                                      |
|----------------|----------------------------------------------|
| **Model**      | Ingenic T23N (XBurst 1)                     |
| **ISA**        | MIPS32 R1, little-endian                    |
| **FPU**        | FP32                                         |
| **CPU clock**  | 1.2–1.4 GHz                                 |
| **L2 cache**   | 64 KB                                        |
| **RAM**        | SIP 512 Mb DDR2                              |
| **Voltage**    | Core: 1.1V, I/O: 3.3V, DDR: 1.8V            |

### 8.2 Sensor

| Property       | Detail                                      |
|----------------|----------------------------------------------|
| **Model**      | OmniVision **OS02G10**                       |
| **Type**       | CMOS, 2 MP (1920×1080)                      |
| **Interface**  | MIPI CSI-2 (2 lanes)                         |
| **Max fps**    | 30 fps @ 1080p                               |
| **Driver**     | Loaded dynamically from tag partition        |

> Sensor driver registers, auto-exposure tables, and mode settings are not
> in the kernel. They are stored in the tag partition (`mtdblock1`) and
> loaded by `tag_generator` during init. The init files expected are:
> - `os02g10_init.bin` — register initialization table
> - `ae_table_os02g10.bin` — auto-exposure tuning
> - `os02g10_setting_mode0-3.bin` — per-resolution mode settings
> - `mclk` — master clock frequency
> - `i2c_addr` — sensor I²C address
> - `pin_mask` — GPIO pin configuration for sensor

### 8.3 WiFi

| Property       | Detail                                      |
|----------------|----------------------------------------------|
| **Chip**       | Altobeam **atbm6461** (Apollo family)        |
| **Interface**  | SDIO                                          |
| **Driver**     | `atbm6461_wifi_sdio.ko`                      |
| **Firmware**   | `ApolloD.bin`, `ApolloE.bin`, `ApolloF.bin`,  |
|                | `AthenaA.bin`, `AthenaB.bin`, `AthenaBX.bin`  |
| **Module params**| `dcxo_value`, `dpll_value`, `fw`            |
| **Storage path**| `/lib/firmware/` on the root filesystem      |
| **Control**    | `/dev/atbm_ioctl` character device            |

The driver supports multiple Altobeam chips:
- atbm6461 (primary — this device)
- atbm6041
- atbm6441

### 8.4 MCU Co-processor

| Property       | Detail                                      |
|----------------|----------------------------------------------|
| **Model**      | z7682 (8051-based or similar)                |
| **Firmware**   | `mcu_fw.bin` (680 KB, v1.0.6u7)             |
| **Interface**  | UART / custom protocol via `librtos.so`      |
| **Functions**  | Watchdog, power management, IR cut control   |
| **Init**       | Watchdog must be disabled early in boot      |

The MCU firmware is flashed to the co-processor on every boot via the
`tag_generator` tool, which writes `riscv_fw` to the tag partition. In
newer Ingenic designs this MCU is a RISC-V core.

### 8.5 Flash & Storage

| Property       | Detail                                      |
|----------------|----------------------------------------------|
| **Type**       | SPI NOR flash (16 MB)                        |
| **Controller** | `jz-sfc` (JZ SPI Flash Controller)           |
| **Quad mode**  | Supported (`sfc-quad-pa`, `sfc-quad-pb`)     |
| **SD card**    | `/dev/mmcblk0`, auto-mounted via mdev        |

Supported flash chips (from kernel driver strings):
`w25q*`, `gd25*`, `en25*`, `mx25l*`, `xt25*`, `p25q*`

### 8.6 GPIOs & LEDs

| GPIO | Function            | Details                          |
|------|---------------------|----------------------------------|
| 50   | **RED LED**         | Active high, exported via sysfs  |
| 49   | Unknown             | Also exported, used by daemon    |

Control via sysfs:
```bash
echo 50 > /sys/class/gpio/export
echo out > /sys/class/gpio/gpio50/direction
echo 1 > /sys/class/gpio/gpio50/value
```

### 8.7 Peripherals

| Peripheral | Driver           | Details                     |
|---|---|---|
| UART       | `jz-uart`        | 115200 baud, console        |
| I²C        | `jz-i2c`         | `i2c0-pa` pinmux, sensor bus|
| I²S        | `cgu_i2s_*`      | Audio codec (speaker, mic)  |
| USB OTG    | `jz-dwc2`        | Device-only mode (gadget)   |
| SDIO       | `jzmmc_v1.2`     | WiFi + SD card slots        |
| ADC        | `jz-adc`         | Battery monitoring?         |
| DMA        | `jz-dma`         | General purpose DMA         |
| Crypto     | `jz-aes`, `jz-des`| Hardware crypto engine      |
| Timer      | `jz-tcu`, `OST`  | System timers               |
| Watchdog   | `jz-wdt`         | SoC watchdog                |

---

## 10. MTD Partition Layout

Based on the firmware image structure and initramfs scripts, the expected
partition layout for a 16 MB SPI NOR flash is:

| #  | Name         | Offset     | Size       | Content                        |
|----|--------------|------------|------------|--------------------------------|
| 0  | `boot`       | `0x000000` | ~64 KB     | Bootloader (U-Boot)            |
| 1  | `tag`        | `0x010000` | ~64 KB     | Tag partition (see below)      |
| 2  | `kernel1`    | `0x020000` | ~1 MB      | Archon kernel (jzlzma)         |
| 3  | `kernel2`    | `0x120000` | ~1 MB      | Immortal kernel (LZMA)         |
| 4  | `rootfs`     | `0x220000` | ~6 MB      | Squashfs #1 (base)             |
| 5  | `app`        | `0x820000` | ~4 MB      | Squashfs #2 (application)      |
| 6  | `data`       | `0xC20000` | ~4 MB      | JFFS2 (config, logos)          |

> Note: These bounds are approximate. The actual offsets must be verified
> against the bootloader's MTD partition table from a live device.

### Tag Partition Structure

The tag partition (`mtdblock1`) is critical. It stores all board-specific
data written by `tag_generator`. No default kernel command line is
hardcoded — it comes from this partition.

Known tag fields (from `tag_generator` usage):
- `--cmdline` — kernel boot command line
- `--env` — environment variables
- `--bootinfo` — boot information
- `--fwinfo` — firmware version info
- `--user0` — user data
- `--ae_table` — auto-exposure/sensor tuning table
- `--riscv_fw` — RISC-V co-processor firmware (or MCU firmware)
- `--sensor_init` — sensor initialization register table
- `--sensor_settings` — per-mode sensor settings (mode0–3)

---

## 11. SDK Tooling

The Zeratul SDK (v3.3.0, dated 2023-09-16) was found at:

```
Zeratul_Release_20230916/tools/
├── make_tag/           # Tag partition tools
├── mark_rootfs/        # jzlzma compression tools
├── mkimg/              # Firmware image creation
└── pc_tool/            # Host utilities
```

### 11.1 mark_rootfs/lzma Tools

```
tools/mark_rootfs/
├── lzma                    # Patched LZMA SDK 4.32 binary (MIPS, static)
├── mark_rootfs_lzma        # jzlzma wrapper (x86-64, dynamic)
├── mark_rootfs_lzo         # LZO variant (x86-64, dynamic)
├── jz_lzma_out.bin         # Example output (from SDK testing)
├── lzma_enc.sh             # Compression pipeline script
└── readme                  # Chinese documentation
```

Compression pipeline (from `lzma_enc.sh`):
```bash
# Step 1: Compress with patched lzma → produces .lzma + jz_lzma_out.bin
./lzma -z -k -f -1 input_file

# Step 2: Wrap jz_lzma_out.bin with 8-byte header → .jzlzma
./mark_rootfs_lzma ./jz_lzma_out.bin output_file

# Step 3: Cleanup intermediate files
rm input_file.lzma jz_lzma_out.bin
```

### 11.2 Tag Generator

The `tag_generator` binary in the initramfs creates and manages the tag
partition. It supports subcommands for each field:

```bash
tag_generator --create-partition       # Initialize tag partition
tag_generator --cmdline "console=ttyS0,115200 ..."
tag_generator --env "KEY=VALUE"
tag_generator --bootinfo "bootinfo..."
tag_generator --fwinfo "07.31030.01.12"
tag_generator --sensor_init os02g10_init.bin
tag_generator --ae_table ae_table_os02g10.bin
tag_generator --riscv_fw riscv_fw.bin
```

### 11.3 librtos / MCU Communication

`librtos.so` implements a custom protocol over `/dev/atbm_ioctl` for
communicating with the MCU. Functions include:

```c
int rtos_cmd_init(void);               // Initialize communication
int rtos_cmd_send(cmd, data, len);     // Send command to MCU
int rtos_cmd_master_poweroff(void);    // Power off system
int rtos_cmd_mcu_upgrade(fw_data);     // Flash MCU firmware
```

---

## 12. Thingino Porting Notes

### 12.1 Board Definition

A new board target should be added to Thingino as:

```
target/linux/ingenic-t23/
└── boards/
    └── lp_T23_OS02G10_6461_S/       # Board name from SDK build path
        ├── config                    # Kernel config fragment
        ├── image                     # Partition layout + image generation
        └── patches/                  # Board-specific kernel patches
```

### 12.2 Kernel Configuration

Minimum kernel features required (all confirmed built-in or as modules in
stock kernel):

```
# Ingenic T23 platform
CONFIG_MIPS=y
CONFIG_CPU_XBURST=y
CONFIG_SOC_T23=y

# Storage
CONFIG_MTD=y
CONFIG_MTD_SPI_NOR=y
CONFIG_MTD_SPI_NOR_USE_QUAD=y
CONFIG_JZ_SFC=y

# Wireless
CONFIG_CFG80211=y
CONFIG_MAC80211=y
CONFIG_ATBM_WIFI_SDIO=m

# Multimedia
CONFIG_VIDEO_INGENIC_ISP=y
CONFIG_VIDEO_INGENIC_IPU=y

# USB
CONFIG_USB_DWC2=y

# MMC/SDIO
CONFIG_MMC_JZMMC=y

# Filesystems
CONFIG_SQUASHFS=y
CONFIG_JFFS2=y
CONFIG_TMPFS=y

# Misc
CONFIG_GPIO_SYSFS=y
CONFIG_I2C_JZ=y
CONFIG_SERIAL_JZ=y
CONFIG_WATCHDOG_JZ=y
CONFIG_DMA_JZ=y
CONFIG_CRYPTO_JZ_AES=y
```

### 12.3 Sensor Integration

The OS02G10 sensor driver needs to be ported from the Ingenic SDK or
mainline. Two approaches:

1. **Built-in driver**: Write a standard V4L2 subdev driver for OS02G10.
2. **Tag partition init** (stock approach): Use the sensor init tables
   extracted from mtdblock1 of a working device. Requires Thingino to
   support the Ingenic tag partition format.

The tag partition approach is fragile (register tables are binary blobs
tied to a specific board revision). A proper V4L2 sensor driver is
recommended for Thingino.

### 12.4 WiFi Integration

The atbm6461 SDIO driver and firmware must be included:

```
linux/drivers/net/wireless/altobeam/
├── atbm_ioctl.c
├── apollo/
│   ├── main.c
│   ├── wsm.c
│   ├── iface.c
│   ├── sta_info.c
│   ├── txrx.c
│   ├── rx.c
│   └── module_fs.c
└── sdio/
    ├── apollo_sdio.c
    ├── hwio_sdio.c
    └── bh_sdio.c
```

Required firmware files in `/lib/firmware/`:
- `ApolloD.bin`, `ApolloE.bin`, `ApolloF.bin` (main firmware)
- `AthenaA.bin`, `AthenaB.bin` (Bluetooth/WiFi combo)
- `ApolloD_TC.bin`, `ApolloF_TC.bin` (temperature compensation)
- `Apollo_FM.bin` (firmware management)

### 12.5 Audio Integration

The audio subsystem uses Ingenic's proprietary **OSS3** driver framework,
not ALSA. Thingino will need to either:

1. **Reuse OSS3 driver sources** (recommended) — the complete driver source
   is available in the SDK at `sound/oss3/`. Enable in kernel config:
   ```
   CONFIG_SOUND=y
   CONFIG_SOUND_OSS_CORE=y
   CONFIG_SOUND_PRIME=y
   CONFIG_SOUND_OSS_XBURST=y
   CONFIG_SOUND_JZ_I2S_V12=y
   CONFIG_COMPILE_JZSOUND_INTO_KO=y
   # CONFIG_SND is not set
   ```

2. **Replace with ALSA** — write an ALSA SoC driver for the T23 internal
   codec and I2S interface. This is more work but aligns with mainline.

For the userland audio stack:
- Port the IMP audio API (`IMP_AI_*`, `IMP_AO_*`, etc.) or replace with
  `libsound`/`ALSA` equivalents.
- The WebRTC audio processing library (`libaudioProcess.so`) is a
  precompiled MIPS blob — either use as-is or replace with a mainline
  WebRTC build.
- Voice prompts (165 AAC files in `snd/`) can be reused directly.
- The standalone `audio_play` binary can be used for AAC playback.

### 12.6 Tag Partition

Thingino must either:
1. **Reimplement tag_generator** — understand the Ingenic tag partition
   format to write cmdline, sensor init, and MCU firmware.
2. **Preserve the stock tag partition** — keep mtdblock1 untouched and
   only replace kernel and rootfs partitions.

Option 2 is simpler for initial bring-up. The tag partition contains all
the board-specific sensor tuning that is difficult to recreate.

### 12.7 Partition Layout

For a 16 MB SPI NOR flash, the Thingino firmware image should maintain
compatibility with the stock layout:

```
mtd0: bootloader    (0x000000 - 0x010000,  64 KB)
mtd1: tag           (0x010000 - 0x020000,  64 KB)  [preserve stock]
mtd2: kernel        (0x020000 - 0x120000,   1 MB)
mtd3: rootfs        (0x120000 - 0x820000,   7 MB)  [squashfs]
mtd4: app           (0x820000 - 0xC20000,   4 MB)  [squashfs]
mtd5: data          (0xC20000 - 0x1000000,  4 MB)  [JFFS2 or UBIFS]
```

> The exact partition boundaries must be confirmed from the bootloader or
> by reading `/proc/mtd` from a live device.

---

## 13. Tools

All tools developed during this analysis are included in the `tools/`
directory:

| File | Description |
|------|-------------|
| `tools/jzlzma_decompress.py` | Decompressor for jzlzma and auto-detection of standard LZMA |

Also available as a standalone repository:
- **`un-jzlzma`**: https://github.com/CapnRon/un-jzlzma

---

## 14. References

1. **Wladimir Palant** — *Unpacking VStarcam firmware for fun and profit*
   (December 2025) — Original documentation of the jzlzma algorithm:
   https://palant.info/2025/12/15/unpacking-vstarcam-firmware-for-fun-and-profit/

2. **Thingino** — Open-source firmware for Ingenic SoC IP cameras:
   https://thingino.com / https://github.com/themactep/thingino-firmware

3. **gtxaspec/thingino-linux** — Ingenic kernel trees with jzlzma support:
   https://github.com/gtxaspec/thingino-linux

4. **Ingenic Semiconductor T23 Datasheet** — Official product page:
   http://en.ingenic.com.cn/products-detail/id-22.html

5. **LZMA SDK 4.32** — Original SDK by Igor Pavlov:
   https://www.7-zip.org/sdk.html

6. **binwalk** — Firmware analysis tool:
   https://github.com/ReFirmLabs/binwalk

---

## License

The documentation and analysis in this repository are provided under
CC BY-SA 4.0. The included `jzlzma_decompress.py` tool is provided under
the MIT license.
