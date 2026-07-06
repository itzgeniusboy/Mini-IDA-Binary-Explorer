# Mini-IDA Binary Explorer 🚀

Mini-IDA is a lightweight, high-performance binary explorer for Android. Designed for reverse engineers, security researchers, and developer-enthusiasts, it allows you to analyze Executable and Linkable Format (ELF) files and shared libraries (`.so`) directly from your mobile device.

The app combines a powerful Kotlin/Jetpack Compose front-end with a high-performance native JNI layer built on top of standard compiler runtime utilities.

---

## Key Features 🌟

- **Efficient Large-Binary Parsing**: Utilizing a memory-mapped ByteBuffer layout (`RandomAccessFile` + `FileChannel.map`), the application loads and parses large binary files (50MB+) smoothly without causing Out-of-Memory (OOM) exceptions.
- **Robust ELF Header Inspection**: Detailed extraction and visualization of ELF header properties including Magic Bytes, Class Type (ELF32/ELF64), Endianness, Target Machine Architecture, and Entry Point.
- **High-Performance C++ Symbol Demangling**: Demangles complex C++ mangled symbols (templates, operator overloads, namespaces) using the standard compiler runtime's native Itanium ABI demangler (`abi::__cxa_demangle`) via JNI. Fallbacks are gracefully handled.
- **Cap-Limited String Extraction**: Safely extracts printable ASCII strings from files with a default truncation limit of 50,000 entries to maintain rapid rendering speed and prevent UI freezing.
- **Local SQLite Offsets Index**: Indexes extracted functions and symbols into a local database (`offsets.db`). Re-opening files cleanly clears and replaces rows mapped to that specific file identifier, ensuring zero state pollution.
- **Interactive Hex Viewer**: Generates clean, fast hex dumps displaying memory offsets, raw hexadecimal bytes, and matching ASCII equivalents side-by-side.
- **Zero-Trust Error Isolation**: Employs rigorous bounds checks at every single read offset, allowing corrupt, truncated, or obfuscated ELF binaries to be parsed safely without crashing the explorer.

---

## Tech Stack 🛠️

- **Android SDK**: Android API level 36 (Android 17 preview) support.
- **Language**: 100% Kotlin + modern Jetpack Compose for UI elements and layouts.
- **Native Layer**: C++20 standard, compiled with CMake and the Android NDK (v26.x).
- **Storage**: Highly optimized Android SQLite APIs supporting transactional bulk insertion and indexed paginated lookups.
- **Concurrency**: Kotlin Coroutines and asynchronous state flow streams.

---

## Project Structure 📁

```text
├── .github/workflows/       # GitHub Actions automated compile pipeline
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── cpp/         # C++ JNI demangling and utility library
│   │   │   │   ├── CMakeLists.txt
│   │   │   │   └── native-lib.cpp
│   │   │   ├── java/        # Kotlin core modules
│   │   │   │   └── com/example/
│   │   │   │       ├── MainActivity.kt
│   │   │   │       ├── ElfParser.kt
│   │   │   │       ├── OffsetsDatabaseHelper.kt
│   │   │   │       └── Adapters.kt
│   │   │   └── res/         # XML/UI assets and styling configs
│   │   └── build.gradle.kts # App configuration
│   └── build.gradle.kts     # Project level Gradle configuration
```

---

## Build & Run 🚀

### Build requirements:
- Android SDK with Platform 36 and Build-tools 36.0.0
- Android NDK 26.x or newer
- CMake 3.22.1 or newer
- Java JDK 17 (Temurin)

To compile the debug APK manually, execute:
```bash
chmod +x gradlew
./gradlew assembleDebug
```
The compiled APK will be located at `app/build/outputs/apk/debug/app-debug.apk`.
