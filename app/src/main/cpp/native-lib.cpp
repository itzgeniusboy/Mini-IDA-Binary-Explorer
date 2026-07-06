#include <jni.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>

// Helper to convert address to hex string
std::string to_hex_string(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::uppercase << std::hex << val;
    return ss.str();
}

// Structure to hold parsed function info
struct ParsedSymbol {
    std::string address;
    std::string name;
    std::string size;
    std::string bind;
    std::string type;
    int index;
};

// Demangles basic mangled names if starts with _Z
std::string simple_demangle(const std::string& mangled) {
    if (mangled.rfind("_Z", 0) != 0) {
        return mangled;
    }
    // Very simple demangle parsing for basic presentation fallback
    std::string working = mangled.substr(2);
    if (working.empty()) return mangled;
    
    if (working[0] == 'N') {
        working = working.substr(1);
        std::vector<std::string> parts;
        size_t idx = 0;
        while (idx < working.size() && isdigit(working[idx])) {
            size_t num_len = 0;
            while (idx + num_len < working.size() && isdigit(working[idx + num_len])) {
                num_len++;
            }
            int len = std::stoi(working.substr(idx, num_len));
            idx += num_len;
            if (idx + len <= working.size()) {
                parts.push_back(working.substr(idx, len));
                idx += len;
            } else {
                break;
            }
        }
        if (!parts.empty()) {
            std::string demangled;
            for (size_t i = 0; i < parts.size(); ++i) {
                if (i > 0) demangled += "::";
                demangled += parts[i];
            }
            return demangled + "()";
        }
    } else {
        size_t num_len = 0;
        while (num_len < working.size() && isdigit(working[num_len])) {
            num_len++;
        }
        if (num_len > 0) {
            int len = std::stoi(working.substr(0, num_len));
            if (num_len + len <= working.size()) {
                return working.substr(num_len, len) + "()";
            }
        }
    }
    return mangled;
}

extern "C"
JNIEXPORT jobject JNICALL
Java_com_example_ElfParser_parseElfNative(JNIEnv *env, jobject thiz, jstring file_path) {
    // Create ArrayList to return
    jclass list_class = env->FindClass("java/util/ArrayList");
    jmethodID list_init = env->GetMethodID(list_class, "<init>", "()V");
    jobject list_obj = env->NewObject(list_class, list_init);
    jmethodID list_add = env->GetMethodID(list_class, "add", "(Ljava/lang/Object;)Z");

    jclass func_class = env->FindClass("com/example/ElfParser$ElfFunction");
    jmethodID func_init = env->GetMethodID(func_class, "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V");

    const char *path = env->GetStringUTFChars(file_path, nullptr);
    if (!path) return list_obj;

    int fd = open(path, O_RDONLY);
    env->ReleaseStringUTFChars(file_path, path);
    if (fd < 0) return list_obj;

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        close(fd);
        return list_obj;
    }

    size_t length = sb.st_size;
    if (length < sizeof(Elf32_Ehdr)) {
        close(fd);
        return list_obj;
    }

    void *addr = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd); // descriptor can be closed after mmap according to POSIX
    if (addr == MAP_FAILED) {
        return list_obj;
    }

    unsigned char *elf_bytes = static_cast<unsigned char *>(addr);
    
    // Validate magic bytes
    if (elf_bytes[0] != 0x7F || elf_bytes[1] != 'E' || elf_bytes[2] != 'L' || elf_bytes[3] != 'F') {
        munmap(addr, length);
        return list_obj;
    }

    unsigned char elf_class = elf_bytes[4]; // ELFCLASS32 (1) or ELFCLASS64 (2)
    std::vector<ParsedSymbol> parsed_symbols;

    if (elf_class == 2) { // 64-bit ELF
        if (length >= sizeof(Elf64_Ehdr)) {
            Elf64_Ehdr *ehdr = reinterpret_cast<Elf64_Ehdr *>(elf_bytes);
            Elf64_Shdr *shdr = reinterpret_cast<Elf64_Shdr *>(elf_bytes + ehdr->e_shoff);

            uint64_t symtab_offset = 0;
            uint64_t symtab_size = 0;
            uint64_t symtab_entsize = 0;
            uint64_t strtab_offset = 0;
            uint64_t strtab_size = 0;

            uint64_t dynsym_offset = 0;
            uint64_t dynsym_size = 0;
            uint64_t dynsym_entsize = 0;
            uint64_t dynstr_offset = 0;
            uint64_t dynstr_size = 0;

            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint64_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf64_Shdr) > length) break;

                Elf64_Shdr *sec = reinterpret_cast<Elf64_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_SYMTAB) {
                    symtab_offset = sec->sh_offset;
                    symtab_size = sec->sh_size;
                    symtab_entsize = sec->sh_entsize;
                } else if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
                    strtab_offset = sec->sh_offset;
                    strtab_size = sec->sh_size;
                } else if (sec->sh_type == SHT_DYNSYM) {
                    dynsym_offset = sec->sh_offset;
                    dynsym_size = sec->sh_size;
                    dynsym_entsize = sec->sh_entsize;
                }
            }

            // Find matching dynstr
            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint64_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf64_Shdr) > length) break;
                Elf64_Shdr *sec = reinterpret_cast<Elf64_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx && sec->sh_offset != strtab_offset) {
                    dynstr_offset = sec->sh_offset;
                    dynstr_size = sec->sh_size;
                }
            }

            uint64_t target_sym_offset = (symtab_offset != 0) ? symtab_offset : dynsym_offset;
            uint64_t target_sym_size = (symtab_offset != 0) ? symtab_size : dynsym_size;
            uint64_t target_sym_entsize = (symtab_offset != 0) ? symtab_entsize : dynsym_entsize;
            uint64_t target_str_offset = (symtab_offset != 0) ? strtab_offset : dynstr_offset;
            uint64_t target_str_size = (symtab_offset != 0) ? strtab_size : dynstr_size;

            if (target_sym_offset != 0 && target_sym_size != 0 && target_sym_entsize != 0) {
                int num_syms = target_sym_size / target_sym_entsize;
                for (int i = 0; i < num_syms; i++) {
                    uint64_t sym_offset = target_sym_offset + i * target_sym_entsize;
                    if (sym_offset + sizeof(Elf64_Sym) > length) break;

                    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(elf_bytes + sym_offset);
                    unsigned char type = ELF64_ST_TYPE(sym->st_info);
                    unsigned char bind = ELF64_ST_BIND(sym->st_info);

                    if (type == STT_FUNC || type == STT_OBJECT) {
                        std::string name;
                        if (target_str_offset != 0 && sym->st_name < target_str_size) {
                            const char *sym_name = reinterpret_cast<const char *>(elf_bytes + target_str_offset + sym->st_name);
                            if (target_str_offset + sym->st_name < length) {
                                name = std::string(sym_name);
                            }
                        }
                        if (name.empty()) {
                            name = (type == STT_FUNC) ? "sub_" + to_hex_string(sym->st_value).substr(2) : "data_" + to_hex_string(sym->st_value).substr(2);
                        }

                        std::string bind_str = "GLOBAL";
                        if (bind == STB_LOCAL) bind_str = "LOCAL";
                        else if (bind == STB_WEAK) bind_str = "WEAK";

                        std::string type_str = (type == STT_FUNC) ? "FUNC" : "OBJECT";

                        parsed_symbols.push_back({
                            to_hex_string(sym->st_value),
                            simple_demangle(name),
                            std::to_string(sym->st_size) + " bytes",
                            bind_str,
                            type_str,
                            i
                        });
                    }
                }
            }
        }
    } else if (elf_class == 1) { // 32-bit ELF
        if (length >= sizeof(Elf32_Ehdr)) {
            Elf32_Ehdr *ehdr = reinterpret_cast<Elf32_Ehdr *>(elf_bytes);
            Elf32_Shdr *shdr = reinterpret_cast<Elf32_Shdr *>(elf_bytes + ehdr->e_shoff);

            uint32_t symtab_offset = 0;
            uint32_t symtab_size = 0;
            uint32_t symtab_entsize = 0;
            uint32_t strtab_offset = 0;
            uint32_t strtab_size = 0;

            uint32_t dynsym_offset = 0;
            uint32_t dynsym_size = 0;
            uint32_t dynsym_entsize = 0;
            uint32_t dynstr_offset = 0;
            uint32_t dynstr_size = 0;

            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint32_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf32_Shdr) > length) break;

                Elf32_Shdr *sec = reinterpret_cast<Elf32_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_SYMTAB) {
                    symtab_offset = sec->sh_offset;
                    symtab_size = sec->sh_size;
                    symtab_entsize = sec->sh_entsize;
                } else if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
                    strtab_offset = sec->sh_offset;
                    strtab_size = sec->sh_size;
                } else if (sec->sh_type == SHT_DYNSYM) {
                    dynsym_offset = sec->sh_offset;
                    dynsym_size = sec->sh_size;
                    dynsym_entsize = sec->sh_entsize;
                }
            }

            // Find matching dynstr
            for (int i = 0; i < ehdr->e_shnum; i++) {
                uint32_t sh_offset = ehdr->e_shoff + i * ehdr->e_shentsize;
                if (sh_offset + sizeof(Elf32_Shdr) > length) break;
                Elf32_Shdr *sec = reinterpret_cast<Elf32_Shdr *>(elf_bytes + sh_offset);
                if (sec->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx && sec->sh_offset != strtab_offset) {
                    dynstr_offset = sec->sh_offset;
                    dynstr_size = sec->sh_size;
                }
            }

            uint32_t target_sym_offset = (symtab_offset != 0) ? symtab_offset : dynsym_offset;
            uint32_t target_sym_size = (symtab_offset != 0) ? symtab_size : dynsym_size;
            uint32_t target_sym_entsize = (symtab_offset != 0) ? symtab_entsize : dynsym_entsize;
            uint32_t target_str_offset = (symtab_offset != 0) ? strtab_offset : dynstr_offset;
            uint32_t target_str_size = (symtab_offset != 0) ? strtab_size : dynstr_size;

            if (target_sym_offset != 0 && target_sym_size != 0 && target_sym_entsize != 0) {
                int num_syms = target_sym_size / target_sym_entsize;
                for (int i = 0; i < num_syms; i++) {
                    uint32_t sym_offset = target_sym_offset + i * target_sym_entsize;
                    if (sym_offset + sizeof(Elf32_Sym) > length) break;

                    Elf32_Sym *sym = reinterpret_cast<Elf32_Sym *>(elf_bytes + sym_offset);
                    unsigned char type = ELF32_ST_TYPE(sym->st_info);
                    unsigned char bind = ELF32_ST_BIND(sym->st_info);

                    if (type == STT_FUNC || type == STT_OBJECT) {
                        std::string name;
                        if (target_str_offset != 0 && sym->st_name < target_str_size) {
                            const char *sym_name = reinterpret_cast<const char *>(elf_bytes + target_str_offset + sym->st_name);
                            if (target_str_offset + sym->st_name < length) {
                                name = std::string(sym_name);
                            }
                        }
                        if (name.empty()) {
                            name = (type == STT_FUNC) ? "sub_" + to_hex_string(sym->st_value).substr(2) : "data_" + to_hex_string(sym->st_value).substr(2);
                        }

                        std::string bind_str = "GLOBAL";
                        if (bind == STB_LOCAL) bind_str = "LOCAL";
                        else if (bind == STB_WEAK) bind_str = "WEAK";

                        std::string type_str = (type == STT_FUNC) ? "FUNC" : "OBJECT";

                        parsed_symbols.push_back({
                            to_hex_string(sym->st_value),
                            simple_demangle(name),
                            std::to_string(sym->st_size) + " bytes",
                            bind_str,
                            type_str,
                            i
                        });
                    }
                }
            }
        }
    }

    munmap(addr, length);

    // Populate the jobject ArrayList with ElfFunction instances
    for (const auto& sym : parsed_symbols) {
        jstring address_jstr = env->NewStringUTF(sym.address.c_str());
        jstring name_jstr = env->NewStringUTF(sym.name.c_str());
        jstring size_jstr = env->NewStringUTF(sym.size.c_str());
        jstring bind_jstr = env->NewStringUTF(sym.bind.c_str());
        jstring type_jstr = env->NewStringUTF(sym.type.c_str());

        jobject func_obj = env->NewObject(
            func_class, 
            func_init, 
            address_jstr, 
            name_jstr, 
            size_jstr, 
            bind_jstr, 
            type_jstr, 
            sym.index
        );

        env->CallBooleanMethod(list_obj, list_add, func_obj);

        env->DeleteLocalRef(address_jstr);
        env->DeleteLocalRef(name_jstr);
        env->DeleteLocalRef(size_jstr);
        env->DeleteLocalRef(bind_jstr);
        env->DeleteLocalRef(type_jstr);
        env->DeleteLocalRef(func_obj);
    }

    return list_obj;
}
